using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Tests;

/// <summary>v1.4: versione pura, SAPI banner > sonda, TLD, pausa, pre-controllo porte, nomi con lo stesso contenuto, opzioni avanzate, nome del report.</summary>
public class V14Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v14_" + Guid.NewGuid().ToString("N"));
    public V14Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string targets = "127.0.0.1") => new()
    {
        TargetsText = targets, PortsText = srv.Port.ToString(), PathsText = "/ /index.php", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 4, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [srv.Port], UdpPorts = [], TimeoutMs = 1000, SkipIfNotAlive = true },
        Level1InfoPages = false, Level1EasterEgg = false, Level2 = true, WafDetect = false, WafBehaviour = false, SizeProbeKiB = 16,
        SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false,
        Advanced = new AdvancedOptions().Also(o => o.SetAll(false)),
    };

    // ---------- versione pura ----------

    [Fact]
    public void PureVersion_OnEolBranch_IsVulnerableByVersion_SuffixStaysLikely()
    {
        bool old = VerdictEngine.PureVersionIsVulnerable;
        try
        {
            VerdictEngine.PureVersionIsVulnerable = true;
            var pure = new ScanResult { Host = "192.0.2.1", Port = 443, HttpReachable = true, PhpDetected = true, PhpVersionRaw = "7.4.33", PhpVersionSource = "X-Powered-By", VersionStatus = VersionStatus.EndOfLife, PackageSuffix = false, Multipart = MultipartBarrier.Accepted };
            VerdictEngine.Apply(pure);
            Assert.Equal(Verdict.VulnerableByVersion, pure.Verdict);
            Assert.Contains("numero puro", pure.VerdictReason);
            Assert.Equal(Priority.High, pure.Priority);

            var deb = new ScanResult { Host = "192.0.2.1", Port = 443, HttpReachable = true, PhpDetected = true, PhpVersionRaw = "7.4.3-4ubuntu2.29", PhpVersionSource = "X-Powered-By", VersionStatus = VersionStatus.EndOfLife, PackageSuffix = true };
            VerdictEngine.Apply(deb);
            Assert.Equal(Verdict.LikelyVulnerable, deb.Verdict);

            VerdictEngine.PureVersionIsVulnerable = false;
            VerdictEngine.Apply(pure);
            Assert.Equal(Verdict.LikelyVulnerable, pure.Verdict);
        }
        finally { VerdictEngine.PureVersionIsVulnerable = old; }
    }

    // ---------- SAPI: il banner prevale sulla sonda ----------

    [Fact]
    public async Task SurfaceProbe_ModPhpSignal_IsOverriddenByFcgiBanner()
    {
        using var srv = new FakePhpServer { Server = "Apache/2.4.63 (Unix) mod_fcgid/2.3.9 PHP/7.3.33", PoweredBy = "PHP/7.3.33", MissingPhp = (404, "<h1>Not Found</h1>") };
        var cfg = Cfg(srv);
        cfg.SurfaceDiscovery = true; cfg.Level2 = false;
        var r = Assert.Single((await new ScanEngine().RunAsync(cfg, CancellationToken.None)).Results);
        Assert.Equal("cgi", r.Sapi);
        Assert.NotEqual(Priority.Critical, r.Priority);
        Assert.Contains("FastCGI", r.SapiEvidence);
    }

    // ---------- TLD ----------

    [Fact]
    public void NameDiscovery_RejectsUnknownThreeLetterTld()
    {
        Assert.False(NameDiscovery.IsValidHostName("cloudpanel.clp"));
        Assert.True(NameDiscovery.IsValidHostName("www.example.com"));
        Assert.True(NameDiscovery.IsValidHostName("app.example.dev"));
        Assert.True(NameDiscovery.IsValidHostName("intranet.example.it"));
        Assert.True(NameDiscovery.IsValidHostName("host.example.cloud"));
    }

    // ---------- pausa ----------

    [Fact]
    public async Task PauseToken_BlocksUntilResume_AndCountsTime()
    {
        var p = new PauseToken();
        await p.WaitAsync(CancellationToken.None);   // non in pausa: ritorna subito
        p.Pause();
        Assert.True(p.IsPaused);
        var waiter = p.WaitAsync(CancellationToken.None);
        await Task.Delay(120);
        Assert.False(waiter.IsCompleted);
        var d = p.Resume();
        await waiter.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.True(d.TotalMilliseconds >= 100);
        Assert.True(p.TotalPaused.TotalMilliseconds >= 100);
        // l'interruzione esce anche durante la pausa
        p.Pause();
        using var cts = new CancellationTokenSource(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => p.WaitAsync(cts.Token));
    }

    [Fact]
    public async Task Engine_PauseStopsNewHosts_ResumeCompletes()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = Cfg(srv, "127.0.0.1\n127.0.0.2\n127.0.0.3\n127.0.0.4");
        cfg.Threads = 1; cfg.Alive.Enabled = false; cfg.Level2 = false;
        var engine = new ScanEngine();
        int ready = 0;
        engine.ResultReady += _ => Interlocked.Increment(ref ready);
        engine.Pause.Pause();
        var task = engine.RunAsync(cfg, CancellationToken.None);
        await Task.Delay(700);
        Assert.Equal(0, ready);              // in pausa dall'inizio: nessun host parte
        Assert.False(task.IsCompleted);
        engine.Pause.Resume();
        var s = await task.WaitAsync(TimeSpan.FromSeconds(60));
        Assert.Equal(4, s.Results.Count);
        Assert.Equal(ScanStatus.Completed, s.Status);
    }

    // ---------- pre-controllo porte ----------

    [Fact]
    public async Task PortPrecheck_ClosedPorts_CostNoHandshake()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        int closed = FakePhpServer.FreePort();
        var cfg = Cfg(srv);
        cfg.PortsText = $"{srv.Port},{closed}";
        cfg.PortPrecheck = true; cfg.Level2 = false;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(2, s.Results.Count);
        var open = s.Results.Single(r => r.Port == srv.Port);
        var shut = s.Results.Single(r => r.Port == closed);
        Assert.True(open.HttpReachable);
        Assert.Contains(open.Tests, t => t.Id == "PORT" && t.Outcome == TestOutcome.Info);
        Assert.False(shut.HttpReachable);
        Assert.Equal(Verdict.NotReachable, shut.Verdict);
        Assert.Contains(shut.Tests, t => t.Id == "PORT" && t.Outcome == TestOutcome.Warn);
        Assert.DoesNotContain(shut.Tests, t => t.Id == "TLS");
        Assert.True(shut.PhaseMs.ContainsKey("precheck"));
        Assert.True(shut.DurationMs < 2500, $"{shut.DurationMs} ms");
    }

    // ---------- nomi con lo stesso contenuto ----------

    [Fact]
    public async Task DifferentContentName_KeepsItsRow()
    {
        using var srv = new FakePhpServer(anyHost: true) { Server = "nginx", RedirectRootTo = "https://site.example.org/", VhostName = "site.example.org", VhostPoweredBy = "PHP/7.4.33", VhostBody = "<html><body>real site</body></html>" };
        var cfg = Cfg(srv);
        cfg.DiscoverNames = true; cfg.RescanDiscoveredNames = true; cfg.FoldSameContentNames = true; cfg.Level2 = false;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(2, s.Results.Count);
        var byName = s.Results.Single(r => r.NameRescan);
        Assert.Equal("site.example.org", byName.DisplayName);
        Assert.Equal("127.0.0.1", byName.DisplayIp);
        Assert.Equal("", s.Results.Single(r => !r.NameRescan).DisplayName);
    }

    [Fact]
    public void SameContent_IgnoresHostNameAndNonces()
    {
        var a = new ScanResult { Host = "192.0.2.1", Port = 443, HttpReachable = true, ServerHeader = "Apache", Verdict = Verdict.NoPhpDetected };
        a.Requests.Add(new HttpSnapshot { Method = "GET", Url = "https://192.0.2.1/", Status = 200, Body = "<a href=\"https://192.0.2.1/x\">x</a> nonce=abcdefghijklmnopqrstuvwxyz0123 " });
        var b = new ScanResult { Host = "192.0.2.1", Port = 443, HttpReachable = true, ServerHeader = "Apache", Verdict = Verdict.NoPhpDetected, NameRescan = true, HostHeader = "www.example.org" };
        b.Requests.Add(new HttpSnapshot { Method = "GET", Url = "https://www.example.org/", Status = 200, Body = "<a href=\"https://www.example.org/x\">x</a>  nonce=ZYXWVUTSRQPONMLKJIHGFEDCBA9876 " });
        Assert.True(ScanEngine.SameContent(a, b, "www.example.org"));
        b.Requests[0] = new HttpSnapshot { Method = "GET", Url = "https://www.example.org/", Status = 200, Body = "<html>completely different site</html>" };
        Assert.False(ScanEngine.SameContent(a, b, "www.example.org"));
    }

    // ---------- opzioni avanzate ----------

    [Fact]
    public void AdvancedOptions_ParseAndKeyList()
    {
        var all = AdvancedOptions.Parse("all");
        Assert.True(all.CertificateTransparency);
        Assert.Equal("all", all.ToKeyList());
        var none = AdvancedOptions.Parse("none");
        Assert.False(none.Any);
        Assert.Equal("none", none.ToKeyList());
        var some = AdvancedOptions.Parse("composer, FastCGI,ptr");
        Assert.True(some.Composer); Assert.True(some.FastCgiProbe); Assert.True(some.ReverseDns); Assert.False(some.HeadVsGet);
        Assert.Equal("composer,fastcgi,ptr", some.ToKeyList());
        Assert.Throws<ArgumentException>(() => AdvancedOptions.Parse("composer,bogus"));
        var def = new AdvancedOptions();
        Assert.False(def.BrowserUserAgent); Assert.False(def.CertificateTransparency); Assert.True(def.Composer);
    }

    [Fact]
    public void Cli_ParsesV14Options()
    {
        var cfg = CliRunner.Parse(["--scan", "192.0.2.1", "--advanced", "composer,status", "--no-fold-names", "--no-precheck", "--no-pure-version"], _dir, out var err, out _, out _);
        Assert.Null(err);
        Assert.NotNull(cfg);
        Assert.True(cfg!.Advanced.Composer); Assert.True(cfg.Advanced.StatusPages); Assert.False(cfg.Advanced.HeadVsGet);
        Assert.False(cfg.FoldSameContentNames); Assert.False(cfg.PortPrecheck); Assert.False(cfg.PureVersionIsVulnerable);
        Assert.Contains("--advanced", CliRunner.Usage());
        var m = CliRunner.Parse(["--merge", "a", "b", "--out", _dir], _dir, out err, out _, out _);
        Assert.Null(err); Assert.NotNull(m);
        Assert.Equal(["a", "b"], CliRunner.MergeFolders);
    }

    [Fact]
    public void AdvancedOptions_RoundTripInSessionJson()
    {
        var cfg = new ScanConfig { Advanced = AdvancedOptions.Parse("composer,ct") };
        var clone = cfg.Clone();
        Assert.True(clone.Advanced.Composer); Assert.True(clone.Advanced.CertificateTransparency); Assert.False(clone.Advanced.HeadVsGet);
    }

    // ---------- file degli host ----------

    [Fact]
    public async Task HostListFiles_AreWrittenInSessionFolder()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = Cfg(srv, "127.0.0.1\n127.0.0.2");
        cfg.Alive.Enabled = false; cfg.Level2 = false;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var alive = File.ReadAllText(Path.Combine(s.Folder, $"host_attivi_v{s.AppVersion}.txt"));
        Assert.Equal("127.0.0.1\n", alive);   // il server finto ascolta solo su 127.0.0.1: il secondo indirizzo rifiuta la connessione
        Assert.True(File.Exists(Path.Combine(s.Folder, $"host_http_v{s.AppVersion}.txt")));
    }

    [Fact]
    public async Task RobotsWithDisallow_DoesNotAbortTheService_ApplicationAndSapiSurvive()
    {
        // Sessione notturna v1.3.1: 18 servizi (WordPress, Drupal, Matomo) finiti "PHP non rilevato" con "errore Collection was modified":
        // robots.txt con Disallow aggiungeva candidati durante il foreach della superficie e l'eccezione saltava SAPI, applicazione e livello 2.
        using var srv = new FakePhpServer { Server = "Apache/2.4.52 (Ubuntu)", PoweredBy = "", HomeBody = "<html><head><link rel=\"stylesheet\" href=\"/wp-content/themes/x/style.css\"></head><body>wp</body></html>" };
        srv.PathBodies["/robots.txt"] = (200, "User-agent: *\nDisallow: /wp-admin/\nDisallow: /privato/\nAllow: /wp-admin/admin-ajax.php\n", "text/plain");
        var cfg = Cfg(srv); cfg.SurfaceDiscovery = true; cfg.Level2 = false;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.Equal("", r.Error);
        Assert.DoesNotContain(r.Tests, t => t.Outcome == TestOutcome.Error);
        Assert.Equal("WordPress", r.Application);
        Assert.True(r.PhpDetected);
        Assert.Contains(r.Tests, t => t.Id == "L1-SURFACE");
    }

    [Fact]
    public void Samples_ScrubOrganisationLabelsAndEmails()
    {
        // v1.3 sostituiva solo i nomi interi: "Regione Acme" in prosa e info@... passavano. Ora cadono anche le etichette dei domini.
        var ip = new ScanResult { Host = "192.0.2.10", Port = 443, IsIpLiteral = true, HttpReachable = true, ServerHeader = "Apache", DiscoveredNames = ["portale.ente-acme.example"] };
        ip.Requests.Add(new HttpSnapshot { Method = "GET", Url = "https://192.0.2.10/", Status = 200,
            Body = "<title>Portale Ente-Acme</title> Benvenuti nell'Ente Acme, scrivi a info@ente-acme.example o visita https://portale.ente-acme.example/x" });
        var other = new ScanResult { Host = "192.0.2.11", Port = 443, IsIpLiteral = true, HttpReachable = true, ServerHeader = "nginx" };
        other.Requests.Add(new HttpSnapshot { Method = "GET", Url = "https://192.0.2.11/", Status = 200, Body = "Sede ACME via Roma 1, 192.0.2.11" });
        var s = new ScanSession { Results = [ip, other], StartLocal = DateTime.Now };

        string json = Samples.Build(s);
        Assert.DoesNotContain("acme", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("192.0.2.", json);
        Assert.DoesNotContain("info@", json);
        Assert.Contains("utente1@example.org", json);
        Assert.Contains("host1.example.org", json);
        Assert.Contains("Portale", json);   // le etichette generiche restano: servono alle firme
        Assert.Equal(["ente-acme", "acme", "ente"], Samples.OrganisationLabels(["portale.ente-acme.example"]).ToList());
    }
}

internal static class V14Ext
{
    public static T Also<T>(this T o, Action<T> f) { f(o); return o; }
}
