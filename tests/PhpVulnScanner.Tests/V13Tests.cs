using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Tests;

/// <summary>v1.3: pianificazione per host, cicli e consolidamento, ordine casuale e ritmo, stima, superficie PHP, nomi scoperti, correzioni dall'analisi della /20.</summary>
// Collection "AppDbDefault": TechnologyDatabase.Default è uno stato statico del processo; i test che lo impostano (qui, AppDbTests,
// AppDbFixtureTests) devono girare in sequenza, altrimenti il "ripristino" di uno cancella il database dell'altro mentre gira (v1.6: test intermittente).
[Collection("AppDbDefault")]
public class V13Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v13_" + Guid.NewGuid().ToString("N"));
    public V13Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string targets = "127.0.0.1") => new()
    {
        TargetsText = targets, PortsText = srv.Port.ToString(), PathsText = "/ /index.php", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 4, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [srv.Port], UdpPorts = [], TimeoutMs = 1000, SkipIfNotAlive = true },
        Level1InfoPages = false, Level1EasterEgg = false, Level2 = true, WafDetect = false, WafBehaviour = false, SizeProbeKiB = 16,
        SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false, Advanced = AdvancedOptions.Parse("none"),
    };

    // ---------- stima ----------

    [Fact]
    public void Estimator_UsesRecentWindow_AndProjectsLoop()
    {
        var e = new ScanEstimator { Cycles = 3, CyclePauseSec = 60 };
        e.Reset(1);
        Assert.False(e.Rate().Reliable);
        // 10 minuti: primi 5 a 1 coppia/s, poi 5 a 4 coppie/s → il ritmo recente deve riflettere i 4/s, non la media 2,5/s
        for (int t = 0; t <= 300; t += 10) e.Add(t, t);
        for (int t = 310; t <= 600; t += 10) e.Add(t, 300 + (t - 300) * 4);
        var (rate, reliable) = e.Rate();
        Assert.True(reliable);
        Assert.InRange(rate, 3.9, 4.1);
        var p = e.Snapshot(done: 1500, total: 2700, elapsedSec: 600, hostsAlive: 10, hostsDone: 100, hostsTotal: 200);
        Assert.NotNull(p.CycleRemainingSec);
        Assert.InRange(p.CycleRemainingSec!.Value, 290, 310);   // 1200 coppie a 4/s
        // loop: ciclo corrente proiettato (600+300) × 2 cicli restanti + 2 pause
        Assert.InRange(p.LoopRemainingSec!.Value, 300 + 2 * 900 + 120 - 40, 300 + 2 * 900 + 120 + 40);
        e.LastCycleSec = 500;
        p = e.Snapshot(1500, 2700, 600, 10, 100, 200);
        Assert.InRange(p.LoopRemainingSec!.Value, 300 + 2 * 560 - 40, 300 + 2 * 560 + 40);
    }

    [Fact]
    public void Estimator_NotReliable_UnderOneMinute()
    {
        var e = new ScanEstimator();
        for (int t = 0; t <= 50; t += 10) e.Add(t, t * 3);
        Assert.False(e.Rate().Reliable);
        Assert.Null(e.Snapshot(150, 1000, 50, 0, 0, 10).CycleRemainingSec);
        Assert.Equal("45 s", ScanEstimator.Duration(45));
        Assert.Equal("12 min", ScanEstimator.Duration(12 * 60 + 20));
        Assert.Equal("2 h 05 min", ScanEstimator.Duration(2 * 3600 + 5 * 60));
    }

    // ---------- consolidamento ----------

    [Fact]
    public void Merger_MostInformativeWins_TiesToMostRecent()
    {
        var dead = new ScanResult { Host = "192.0.2.1", Port = 443, Alive = AliveState.NoResponse, Cycle = 1 };
        VerdictEngine.Apply(dead);
        var alive = new ScanResult { Host = "192.0.2.1", Port = 443, Alive = AliveState.Alive, HttpReachable = true, PhpDetected = true, PhpEvidence = "x", Cycle = 2 };
        VerdictEngine.Apply(alive);
        var versioned = new ScanResult { Host = "192.0.2.1", Port = 443, Alive = AliveState.Alive, HttpReachable = true, PhpDetected = true, PhpVersionRaw = "7.4.33", VersionStatus = VersionStatus.EndOfLife, Cycle = 3 };
        VerdictEngine.Apply(versioned);
        var dead4 = new ScanResult { Host = "192.0.2.1", Port = 443, Alive = AliveState.NoResponse, Cycle = 4 };
        VerdictEngine.Apply(dead4);

        var m = ResultMerger.Merge(null, dead);
        Assert.Same(dead, m);
        m = ResultMerger.Merge(m, alive);
        Assert.Same(alive, m);                      // raggiungibile batte non raggiungibile
        m = ResultMerger.Merge(m, versioned);
        Assert.Same(versioned, m);                  // versione dichiarata batte non determinabile
        m = ResultMerger.Merge(m, dead4);
        Assert.Same(versioned, m);                  // il ciclo 4 non raggiungibile non cancella l'informazione
        Assert.Equal(4, m.History.Count);
        Assert.True(ResultMerger.VerdictChanged(m));
        Assert.Contains("ciclo 1:", m.History[0]);

        // parità: vince il più recente
        var a = new ScanResult { Host = "h", Port = 80, HttpReachable = true, Cycle = 1 }; VerdictEngine.Apply(a);
        var b = new ScanResult { Host = "h", Port = 80, HttpReachable = true, Cycle = 2 }; VerdictEngine.Apply(b);
        Assert.Same(b, ResultMerger.Merge(a, b));
        Assert.False(ResultMerger.VerdictChanged(b));
    }

    // ---------- ritmo ----------

    [Fact]
    public async Task Pacer_RespectsDelayAndRate()
    {
        var p = new Pacer(20, 40, 0, seed: 1);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        for (int i = 0; i < 5; i++) await p.WaitAsync(CancellationToken.None);
        Assert.True(sw.ElapsedMilliseconds >= 90, $"{sw.ElapsedMilliseconds} ms");
        Assert.Equal(5, p.Requests);

        var r = new Pacer(0, 0, 10);   // 10/s: 15 richieste ≈ almeno 400 ms (i primi 10 token sono già disponibili)
        sw.Restart();
        for (int i = 0; i < 15; i++) await r.WaitAsync(CancellationToken.None);
        Assert.True(sw.ElapsedMilliseconds >= 350, $"{sw.ElapsedMilliseconds} ms");
        Assert.False(new Pacer(0, 0, 0).Active);
    }

    // ---------- nomi ----------

    [Fact]
    public void NameDiscovery_ValidatesAndCollects()
    {
        Assert.True(NameDiscovery.IsValidHostName("www.example.org"));
        Assert.True(NameDiscovery.IsValidHostName("www.example.org"));
        Assert.False(NameDiscovery.IsValidHostName("www.example.orgindex.php"));   // redirect incollato
        Assert.False(NameDiscovery.IsValidHostName("192.0.2.1"));
        Assert.False(NameDiscovery.IsValidHostName("localhost"));
        Assert.False(NameDiscovery.IsValidHostName("host.local"));
        Assert.False(NameDiscovery.IsValidHostName("bad_name.example.org"));

        var r = new ScanResult { Host = "192.0.2.1", Port = 443, IsIpLiteral = true };
        r.Tls = new TlsInfo { Handshake = true, Subject = "CN=*.example.org, O=Example", SubjectAltNames = ["*.example.org", "example.org", "www.example.org"] };
        r.Requests.Add(new HttpSnapshot { Status = 302, Headers = [new("Location", "https://portal.example.org/login")] });
        r.Requests.Add(new HttpSnapshot { Status = 302, Headers = [new("Location", "https://www.example.orgindex.php")] });
        r.Requests.Add(new HttpSnapshot { Status = 301, Headers = [new("Location", "/index.php")] });
        var names = NameDiscovery.Collect(r);
        Assert.Equal(["*.example.org", "example.org", "www.example.org", "portal.example.org"], names);
        var rescan = NameDiscovery.Rescannable(names, "192.0.2.1", null, 2);
        Assert.Equal(["example.org", "www.example.org"], rescan);
        Assert.Equal(["www.example.org", "portal.example.org"], NameDiscovery.Rescannable(names, "192.0.2.1", "example.org", 10));
    }

    // ---------- superficie ----------

    [Fact]
    public void SurfaceDiscovery_ClassifiesMissingPhp()
    {
        Assert.Equal(SurfaceDiscovery.MissingFileKind.Fpm, SurfaceDiscovery.ClassifyMissingPhp(new HttpSnapshot { Status = 404, Body = "File not found.\n" }));
        Assert.Equal(SurfaceDiscovery.MissingFileKind.Cgi, SurfaceDiscovery.ClassifyMissingPhp(new HttpSnapshot { Status = 404, Body = "No input file specified." }));
        Assert.Equal(SurfaceDiscovery.MissingFileKind.ModPhp, SurfaceDiscovery.ClassifyMissingPhp(new HttpSnapshot { Status = 404, Body = "<h1>Not Found</h1>", Headers = [new("X-Powered-By", "PHP/8.1.2")] }));
        Assert.Equal(SurfaceDiscovery.MissingFileKind.CatchAll, SurfaceDiscovery.ClassifyMissingPhp(new HttpSnapshot { Status = 200, Body = "home" }));
        Assert.Equal(SurfaceDiscovery.MissingFileKind.RedirectAll, SurfaceDiscovery.ClassifyMissingPhp(new HttpSnapshot { Status = 301, Headers = [new("Location", "https://x/")] }));
        Assert.Equal(SurfaceDiscovery.MissingFileKind.Unknown, SurfaceDiscovery.ClassifyMissingPhp(new HttpSnapshot { Status = 404, Body = "<html>Not Found</html>" }));
        Assert.True(SurfaceDiscovery.IsGlobalRedirect(new HttpSnapshot { Status = 301, Headers = [new("Location", "https://example.org/admin/")] }, "/admin/"));
        Assert.False(SurfaceDiscovery.IsGlobalRedirect(new HttpSnapshot { Status = 302, Headers = [new("Location", "/wp-login.php")] }, "/wp-admin/"));
    }

    [Fact]
    public async Task FpmSignature_MakesPhpDetected_AndEntryPointsFound()
    {
        // 4 host della /20: Apache senza banner PHP, /index.php → 404 "File not found." (PHP-FPM); la v1.2 diceva "PHP non rilevato"
        using var srv = new FakePhpServer { Server = "Apache/2.4.62 (Rocky Linux)", MissingPhp = (404, "File not found.\n") };
        srv.ExistingPaths["/wp-login.php"] = 200;
        srv.ExistingPaths["/admin/"] = 401;
        var cfg = Cfg(srv);
        cfg.SurfaceDiscovery = true; cfg.Level2 = false;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.Equal("Fpm", r.PhpSurfaceProbe);
        Assert.Equal("fpm", r.Sapi);
        Assert.True(r.PhpDetected);
        Assert.Equal(Verdict.Undetermined, r.Verdict);
        Assert.Contains("/wp-login.php (200)", r.PhpSurface);
        Assert.Contains("/admin/ (401)", r.PhpSurface);
        Assert.DoesNotContain(r.PhpSurface, p => p.StartsWith("/login.php"));
        Assert.Contains(r.Tests, t => t.Id == "L1-SURFACE-PROBE" && t.Outcome == TestOutcome.Warn);
        // la sonda usa un nome casuale .php, i punti di ingresso solo HEAD
        Assert.Contains(srv.Requests, q => q.StartsWith("GET /pvs") && q.Contains(".php"));
        Assert.Contains(srv.Requests, q => q.StartsWith("HEAD /wp-login.php"));
    }

    [Fact]
    public async Task Level2_UsesDiscoveredPhp_WhenConfiguredPathsHaveNone()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        srv.ExistingPaths["/login.php"] = 200;
        var cfg = Cfg(srv);
        cfg.PathsText = "/";                      // nessun .php configurato
        cfg.SurfaceDiscovery = true;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.Contains(r.Tests, t => t.Id == "L2-PATH" && t.Detail.Contains("/login.php"));
        Assert.EndsWith("/login.php", r.Requests.First(q => q.Method == "POST").Url);
    }

    // ---------- pianificazione per host ----------

    [Fact]
    public async Task AliveCheck_RunsOncePerHost_AcrossPorts()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        int closed1 = FakePhpServer.FreePort(), closed2 = FakePhpServer.FreePort();
        var cfg = Cfg(srv);
        cfg.PortsText = $"{srv.Port},{closed1},{closed2}";
        cfg.Threads = 3;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(3, s.Results.Count);
        Assert.All(s.Results, r => Assert.Equal(AliveState.Alive, r.Alive));
        // il tempo dell'alive check è attribuito a una sola riga; le altre lo dichiarano "eseguito una volta per host"
        Assert.Equal(1, s.Results.Count(r => r.PhaseMs.ContainsKey("alive")));
        Assert.Equal(2, s.Results.Count(r => r.Tests.Any(t => t.Id == "ALIVE" && t.Detail.Contains("una volta per host"))));
        Assert.Equal(1, s.HostsAlive);
        Assert.Equal(1, s.HostsHttp);
        Assert.Equal(1, s.HostsTotal);
    }

    [Fact]
    public async Task DeadHosts_CostOneAliveCheck_NotOnePerPort()
    {
        // alive check TCP su una porta chiusa con RST immediato: 20 host × 4 porte devono costare ~20 alive check, non 80
        int closed = FakePhpServer.FreePort();
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.1-20", PortsText = $"{closed},{closed + 1},{closed + 2},{closed + 3}", ConnectTimeoutMs = 1000, ReadTimeoutMs = 2000, Threads = 4, OutputFolder = _dir,
            Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [closed], UdpPorts = [], TimeoutMs = 500, SkipIfNotAlive = true },
            SurfaceDiscovery = false, DiscoverNames = false, Advanced = AdvancedOptions.Parse("none"),
        };
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(80, s.Results.Count);
        Assert.Equal(20, s.Results.Count(r => r.PhaseMs.ContainsKey("alive")));
        Assert.Equal(20, s.HostsTotal);
    }

    // ---------- cicli ----------

    [Fact]
    public async Task Cycles_Consolidated_OneSession_WithHistory()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = Cfg(srv);
        cfg.Cycles = 3; cfg.CyclePauseSec = 0; cfg.Consolidate = true; cfg.RandomOrder = true;
        int started = 0, completed = 0; var ready = new List<ScanResult>();
        var engine = new ScanEngine();
        engine.CycleStarted += (c, n, _) => started++;
        engine.CycleCompleted += _ => completed++;
        engine.ResultReady += r => { lock (ready) ready.Add(r); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(ScanStatus.Completed, s.Status);
        Assert.Equal(3, started); Assert.Equal(3, completed);
        Assert.Equal(3, s.Cycle); Assert.Equal(3, s.Cycles); Assert.True(s.Consolidated);
        var r = Assert.Single(s.Results);
        Assert.True(r.History.Count == 3, string.Join(" || ", r.History) + $" ready={ready.Count}");
        Assert.Equal(3, r.Cycle);
        Assert.False(ResultMerger.VerdictChanged(r));
        Assert.Equal(3, ready.Count);
        Assert.Single(Directory.GetDirectories(_dir));
        // results.jsonl ha le tre osservazioni; results.json solo il consolidato
        var folder = Directory.GetDirectories(_dir)[0];
        Assert.Equal(3, SessionFiles.ReadJsonl(Path.Combine(folder, SessionFiles.ResultsJsonl)).Count);
        var read = SessionFiles.ReadSession(folder)!;
        Assert.Single(read.Results);
        Assert.Equal(3, read.Results[0].History.Count);
        Assert.Contains("ciclo", File.ReadAllText(Path.Combine(folder, SessionFiles.ScanLog)));
        var csv = File.ReadAllText(Path.Combine(folder, SessionFiles.ResultsCsv));
        Assert.Contains("history", csv);
        var html = ReportGenerator.Build(s);
        Assert.Contains("Storia dei cicli", html);
        Assert.Contains("Host attivi", html);
    }

    [Fact]
    public async Task Cycles_SeparateSessions_OneFolderPerCycle()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = Cfg(srv);
        cfg.Cycles = 2; cfg.CyclePauseSec = 0; cfg.Consolidate = false;
        var sessions = new List<ScanSession>();
        var engine = new ScanEngine();
        engine.CycleCompleted += s => sessions.Add(s);
        var last = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(2, sessions.Count);
        Assert.Equal(2, last.Cycle);
        var dirs = Directory.GetDirectories(_dir).OrderBy(d => d).ToList();
        Assert.Equal(2, dirs.Count);
        Assert.EndsWith("_c1of2", dirs[0]);
        Assert.EndsWith("_c2of2", dirs[1]);
        Assert.All(dirs, d => Assert.True(File.Exists(Path.Combine(d, SessionFiles.ResultsCsv))));
        Assert.Single(sessions[0].Results);
        Assert.Single(sessions[0].Results[0].History);
    }

    [Fact]
    public async Task Stop_DuringCycles_KeepsCompletedResults()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = Cfg(srv);
        cfg.Cycles = 5; cfg.CyclePauseSec = 30; cfg.Consolidate = true;
        var cts = new CancellationTokenSource();
        var engine = new ScanEngine();
        engine.CycleCompleted += _ => cts.CancelAfter(200);   // interruzione durante la pausa
        var s = await engine.RunAsync(cfg, cts.Token);
        Assert.Equal(ScanStatus.Stopped, s.Status);
        Assert.Single(s.Results);
        Assert.Equal(1, s.Cycle);
    }

    // ---------- nomi scoperti: seconda passata ----------

    [Fact]
    public async Task DiscoveredNames_AreRescanned_WithHostHeader()
    {
        using var srv = new FakePhpServer(anyHost: true) { Server = "nginx", RedirectRootTo = "https://site.example.org/", VhostName = "site.example.org", VhostPoweredBy = "PHP/7.4.33", VhostBody = "<html><body>real site</body></html>" };
        var cfg = Cfg(srv);
        cfg.DiscoverNames = true; cfg.RescanDiscoveredNames = true; cfg.Level2 = false;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(2, s.Results.Count);
        var byIp = s.Results.Single(r => !r.NameRescan);
        var byName = s.Results.Single(r => r.NameRescan);
        Assert.Contains("site.example.org", byIp.DiscoveredNames);
        Assert.Equal(Verdict.NoPhpDetected, byIp.Verdict);
        Assert.Equal("site.example.org", byName.HostHeader);
        Assert.Equal("site.example.org @ 127.0.0.1", byName.Display);
        Assert.Equal(Verdict.VulnerableByVersion, byName.Verdict);   // v1.4: numero puro su ramo fuori supporto
        Assert.Equal("7.4.33", byName.PhpVersionRaw);
        Assert.StartsWith("http://site.example.org:", byName.Requests[0].Url);
        Assert.True(srv.VhostRequests > 0);
        Assert.Equal("127.0.0.1|" + srv.Port + "|site.example.org", byName.Key);
        Assert.True(string.CompareOrdinal(byIp.SortKey, byName.SortKey) < 0);
        var html = ReportGenerator.Build(s);
        Assert.Contains("Nomi scoperti", html);
        Assert.Contains("site.example.org @ 127.0.0.1", html);
    }

    // ---------- correzioni dall'analisi della /20 ----------

    [Fact]
    public async Task ModFcgid_IsNotModPhp_AndEvidenceIsDeduplicated()
    {
        using var srv = new FakePhpServer { Server = "Apache/2.4.63 (Unix) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/7.3.33", PoweredBy = "PHP/7.3.33" };
        var cfg = Cfg(srv);
        var r = Assert.Single((await new ScanEngine().RunAsync(cfg, CancellationToken.None)).Results);
        Assert.Equal("cgi", r.Sapi);
        Assert.Equal(Priority.High, r.Priority);          // non Critical: non è mod_php
        Assert.Equal(1, r.PhpEvidence.Split("; ").Count(e => e == "X-Powered-By: PHP/7.3.33"));
        Assert.Equal("Unix", r.OsHint.Length == 0 ? "Unix" : r.OsHint);   // "(Unix)" non è un sistema operativo
        Assert.Equal("", r.OsHint);
    }

    [Fact]
    public void OsHint_IsNormalised()
    {
        Assert.Equal("CentOS", StackFingerprint.NormalizeOs("centos"));
        Assert.Equal("Windows", StackFingerprint.NormalizeOs("Win64"));
        Assert.Equal("Oracle Linux", StackFingerprint.NormalizeOs("Oracle Linux Server"));
        var r = new ScanResult { Host = "h", ServerHeader = "Apache/2.4.62 (Oracle Linux Server) OpenSSL/3.2.2", PoweredBy = "PHP/8.0.30" };
        StackFingerprint.Apply(r, [new HttpSnapshot { Status = 200, Body = "<html></html>" }]);
        Assert.Equal("Oracle Linux", r.OsHint);
        var w = new ScanResult { Host = "h", ServerHeader = "Microsoft-HTTPAPI/2.0" };
        StackFingerprint.Apply(w, [new HttpSnapshot { Status = 404, Body = "" }]);
        Assert.Equal("Windows", w.OsHint);
    }

    [Fact]
    public async Task AliveMethods_CancelledOnesSayCancelled()
    {
        using var srv = new FakePhpServer();
        int closed = FakePhpServer.FreePort();
        var cfg = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [srv.Port], UdpPorts = [40000 + Random.Shared.Next(20000)], TimeoutMs = 3000 };
        var a = await AliveChecker.CheckAsync("127.0.0.1", cfg, CancellationToken.None);
        Assert.Equal(AliveState.Alive, a.State);
        var udp = a.Methods.Single(m => m.Method.StartsWith("UDP"));
        if (!udp.Confirmed) Assert.Contains("annullato", udp.Detail);
        Assert.DoesNotContain("canceled", a.MethodsSummary, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- file di sessione ----------

    [Fact]
    public async Task ResultsJson_IsRewrittenAtMostEveryInterval_AndJsonlAlways()
    {
        int old = SessionWriter.RewriteIntervalMs;
        SessionWriter.RewriteIntervalMs = 60000;
        try
        {
            using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
            var cfg = Cfg(srv, "127.0.0.1\n127.0.0.2\n127.0.0.3");
            cfg.Alive.Enabled = false;
            var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
            Assert.Equal(3, s.Results.Count);
            Assert.Equal(3, SessionFiles.ReadJsonl(Path.Combine(s.Folder, SessionFiles.ResultsJsonl)).Count);
            Assert.Equal(3, SessionFiles.ReadSession(s.Folder)!.Results.Count);
        }
        finally { SessionWriter.RewriteIntervalMs = old; }
    }

    [Fact]
    public void TargetsSummary_ListsInputsAsEntered()
    {
        var parsed = TargetParser.Parse("192.0.2.0/29\n198.51.100.5-7 www.example.org");
        Assert.Equal("192.0.2.0/29, 198.51.100.5-7, www.example.org", ScanEngine.SummarizeTargets(parsed.Targets));
        var many = TargetParser.Parse(string.Join("\n", Enumerable.Range(1, 9).Select(i => $"203.0.113.{i}")));
        Assert.EndsWith("e altre 3", ScanEngine.SummarizeTargets(many.Targets));
    }

    // ---------- database applicazioni nel motore ----------

    [Fact]
    public async Task TechnologyDatabase_RecognisesApp_AndImpliesPhp_InsideTheEngine()
    {
        // CodeIgniter non è tra le 50 firme a mano: lo riconosce solo il database (cookie ci_session), che implica PHP
        var old = PhpVulnScanner.Core.Apps.TechnologyDatabase.Default;
        PhpVulnScanner.Core.Apps.TechnologyDatabase.Default = PhpVulnScanner.Core.Apps.TechnologyDatabase.Load(Path.Combine(LocalizationTests.RepoRoot(), "data"));
        try
        {
            using var srv = new FakePhpServer { Server = "nginx" };
            srv.ExtraHeaders.Add(new("Set-Cookie", "ci_session=abc123; path=/; HttpOnly"));
            var cfg = Cfg(srv);
            cfg.Level2 = false;
            var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
            var r = Assert.Single(s.Results);
            Assert.Equal("CodeIgniter", r.Application);
            Assert.True(r.PhpDetected);
            Assert.Contains("CodeIgniter", r.PhpEvidence);
            Assert.Equal(Verdict.Undetermined, r.Verdict);
            Assert.Contains(r.Technologies, t => t.StartsWith("CodeIgniter"));
            Assert.NotEmpty(s.DataVersion);
            var html = ReportGenerator.Build(s);
            Assert.Contains("webappanalyzer", html);
            Assert.Contains("CodeIgniter", html);
            var csv = SessionFiles.ResultsToCsv(s.Results, new CsvFormat(CsvDialect.Standard));
            Assert.Contains("technologies", csv);
            Assert.Contains("CodeIgniter", csv);
        }
        finally { PhpVulnScanner.Core.Apps.TechnologyDatabase.Default = old; }
    }

    // ---------- debug e campioni ----------

    [Fact]
    public async Task DebugMode_WritesSamples_Anonymised()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", HomeBody = "<html><a href=\"http://127.0.0.1/x.php\">x</a></html>" };
        var cfg = Cfg(srv);
        cfg.DebugMode = true;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.NotNull(r.Requests[0].RequestHeaders);
        Assert.Contains(r.Requests[0].RequestHeaders!, h => h.Key == "User-Agent");
        string samples = File.ReadAllText(Path.Combine(s.Folder, SessionFiles.SamplesJson));
        Assert.DoesNotContain("127.0.0.1", samples);
        Assert.Contains("198.51.100.", samples);
        Assert.Contains("PHP/8.3.20", samples);
    }

    // ---------- riga di comando ----------

    [Fact]
    public void Cli_ParsesNewOptions()
    {
        var cfg = CliRunner.Parse(["--scan", "192.0.2.1", "--cycles", "4", "--cycle-pause", "5", "--separate-sessions", "--random", "--delay", "100-300", "--rate", "20", "--no-surface", "--no-rescan-names", "--max-names", "3", "--debug", "--report-unreachable"], _dir, out var err, out _, out _);
        Assert.Null(err);
        Assert.NotNull(cfg);
        Assert.Equal(4, cfg!.Cycles); Assert.Equal(5, cfg.CyclePauseSec); Assert.False(cfg.Consolidate); Assert.True(cfg.RandomOrder);
        Assert.Equal(100, cfg.DelayMinMs); Assert.Equal(300, cfg.DelayMaxMs); Assert.Equal(20, cfg.MaxRequestsPerSecond);
        Assert.False(cfg.SurfaceDiscovery); Assert.True(cfg.DiscoverNames); Assert.False(cfg.RescanDiscoveredNames); Assert.Equal(3, cfg.MaxNamesPerHost);
        Assert.True(cfg.DebugMode); Assert.True(cfg.ReportUnreachableDetails);
        Assert.Contains("--cycles", CliRunner.Usage());
        Assert.Null(CliRunner.Parse(["--scan", "192.0.2.1", "--delay", "abc"], _dir, out err, out _, out _));
        Assert.NotNull(err);
    }

    [Fact]
    public async Task Cli_Cycles_SeparateSessions_ReportPerCycle()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var sw = new StringWriter();
        int code = await CliRunner.RunAsync(["--scan", "127.0.0.1", "--ports", srv.Port.ToString(), "--no-alive", "--no-surface", "--no-names", "--out", _dir, "--quiet", "--cycles", "2", "--cycle-pause", "0", "--separate-sessions"], _dir, sw, CancellationToken.None);
        Assert.Equal(CliRunner.ExitVulnerable, code);
        Assert.Contains("cicli eseguiti: 2 di 2", sw.ToString());
        Assert.Equal(2, Directory.GetDirectories(_dir).Count(d => Directory.GetFiles(d, "report_v*.html").Length == 1));
    }
}
