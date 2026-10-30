using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Tests;

/// <summary>Scansioni complete contro il server PHP finto su loopback.</summary>
public class EngineTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_engine_" + Guid.NewGuid().ToString("N"));

    public EngineTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Config(FakePhpServer srv, bool level2 = true, bool waf = true) => new()
    {
        TargetsText = "127.0.0.1",
        PortsText = srv.Port.ToString(),
        PathsText = "/ /index.php",
        ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 2,
        Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [srv.Port], UdpPorts = [], TimeoutMs = 1000, SkipIfNotAlive = true },
        Level1InfoPages = true, Level1EasterEgg = true, Level2 = level2, SizeProbeKiB = 64,
        WafDetect = waf, WafBehaviour = waf,
        OutputFolder = _dir,
    };

    private static async Task<ScanResult> One(ScanConfig cfg)
    {
        var engine = new ScanEngine();
        var session = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(ScanStatus.Completed, session.Status);
        return Assert.Single(session.Results);
    }

    [Fact]
    public async Task VulnerableVersion_MultipartAccepted()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var r = await One(Config(srv));
        Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        Assert.Equal("8.3.20", r.PhpVersionRaw);
        Assert.Equal("X-Powered-By", r.PhpVersionSource);
        Assert.Equal(MultipartBarrier.Accepted, r.Multipart);
        Assert.Equal(AliveState.Alive, r.Alive);
        Assert.StartsWith("TCP/", r.AliveMethod);
        Assert.False(r.UploadProgressFieldBlocked);
        Assert.Contains("accettato", r.SizeLimit);
        Assert.Equal("/index.php", r.Requests.First(q => q.Method == "POST").Url[^10..]);
        Assert.Contains(r.Tests, t => t.Id == "L1-EGG" && t.Outcome == TestOutcome.Info);
        // nessuna richiesta porta corpi oltre la dimensione di prova
        Assert.All(srv.Requests, q => Assert.True(int.Parse(q.Split(' ')[^1]) <= 64 * 1024 + 512));
    }

    [Fact]
    public async Task FixedVersion()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.4.27" };
        var r = await One(Config(srv));
        Assert.Equal(Verdict.FixedByVersion, r.Verdict);
        Assert.Contains(r.Tests, t => t.Id == "L1-VERSION" && t.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public async Task EolVersionWithPackageSuffix_IsLikelyVulnerable()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/7.4.33-1+deb11u5" };
        var r = await One(Config(srv));
        Assert.Equal(Verdict.LikelyVulnerable, r.Verdict);
        Assert.True(r.PackageSuffix);
    }

    [Fact]
    public async Task MultipartBlockedCompletely_IsMitigatedAtEdge()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.2.10", Multipart = FakePhpServer.MultipartPolicy.BlockAll };
        var r = await One(Config(srv));
        Assert.Equal(Verdict.MitigatedAtEdge, r.Verdict);
        Assert.Equal(MultipartBarrier.Blocked, r.Multipart);
        Assert.Equal(8, r.VariantsTotal);
        Assert.Equal(8, r.VariantsBlocked);
        Assert.Contains("8.2.10", r.VerdictReason);
        Assert.Null(r.UploadProgressFieldBlocked);
    }

    [Fact]
    public async Task MultipartBlockedOnlyExactString_IsPartial()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.2.10", Multipart = FakePhpServer.MultipartPolicy.BlockExactOnly };
        var r = await One(Config(srv));
        Assert.Equal(MultipartBarrier.PartiallyBlocked, r.Multipart);
        Assert.True(r.VariantsBlocked < r.VariantsTotal);
        Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        Assert.Contains("aggirabile", r.VerdictReason);
    }

    [Fact]
    public async Task UploadProgressFieldFiltered_AndSizeLimit()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.1", Multipart = FakePhpServer.MultipartPolicy.BlockUploadProgressField, SizeLimitBytes = 16 * 1024 };
        var r = await One(Config(srv));
        Assert.Equal(MultipartBarrier.Accepted, r.Multipart);
        Assert.True(r.UploadProgressFieldBlocked);
        Assert.Contains("respinto", r.SizeLimit);
        Assert.Contains(r.Tests, t => t.Id == "L2-SIZE" && t.Outcome == TestOutcome.Pass);
    }

    [Fact]
    public async Task NoPhp_AndPhpWithoutVersion()
    {
        using var a = new FakePhpServer { Server = "nginx/1.26.0" };
        var ra = await One(Config(a));
        Assert.Equal(Verdict.NoPhpDetected, ra.Verdict);
        Assert.False(ra.PhpDetected);

        using var b = new FakePhpServer { Server = "nginx", SessionCookie = true };
        var rb = await One(Config(b));
        Assert.Equal(Verdict.Undetermined, rb.Verdict);
        Assert.True(rb.PhpDetected);
        Assert.Contains("PHPSESSID", rb.PhpEvidence);
        Assert.Contains(rb.Tests, t => t.Id == "L1-SESSID" && t.Outcome == TestOutcome.Info);
    }

    [Fact]
    public async Task PhpinfoExposed_GivesVersionAndFinding()
    {
        using var srv = new FakePhpServer { Server = "nginx", ExposePhpinfo = true };
        var r = await One(Config(srv));
        Assert.Equal("/phpinfo.php", r.PhpVersionSource);
        Assert.Equal("8.1.2-1ubuntu2.14", r.PhpVersionRaw);
        Assert.Equal(Verdict.LikelyVulnerable, r.Verdict);
        Assert.Contains(r.Tests, t => t.Id == "L1-PHPINFO" && t.Outcome == TestOutcome.Fail);
    }

    [Fact]
    public async Task PostNotAllowed()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.36", PostNotAllowed = true };
        var r = await One(Config(srv));
        Assert.Equal(MultipartBarrier.PostNotAllowed, r.Multipart);
        Assert.Equal(Verdict.FixedByVersion, r.Verdict);
    }

    [Fact]
    public async Task WafDetected_BySignatureAndBehaviour()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", Waf = true, Server = "cloudflare" };
        var r = await One(Config(srv));
        Assert.Contains(r.Waf, f => f.Name == "Cloudflare" && f.Category == WafCategory.Cdn);
        Assert.Contains(r.Waf, f => f.Category == WafCategory.Waf);
        Assert.Contains("Cloudflare", r.WafSummary);
        Assert.Contains(r.Tests, t => t.Id == "WAF-BEHAVIOUR" && t.Outcome == TestOutcome.Warn);
    }

    [Fact]
    public async Task ClosedPort_IsNotReachable_ButAliveByRst()
    {
        int port = FakePhpServer.FreePort();
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.1", PortsText = port.ToString(), ConnectTimeoutMs = 1500, ReadTimeoutMs = 2000, OutputFolder = _dir,
            Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [port], TimeoutMs = 1000, SkipIfNotAlive = true },
        };
        var r = await One(cfg);
        Assert.Equal(AliveState.Alive, r.Alive);           // RST = host attivo
        Assert.Equal(Verdict.NotReachable, r.Verdict);
        Assert.False(r.HttpReachable);
        Assert.True(r.Tls!.ConnectFailed);
        Assert.Contains(r.Tests, t => t.Id == "HTTP" && t.Outcome == TestOutcome.Skipped);   // nessuna seconda connessione sulla porta chiusa
        Assert.DoesNotContain(r.Tests, t => t.Id == "L1-GET");
        Assert.True(r.PhaseMs.ContainsKey("tls") && r.PhaseMs.ContainsKey("alive"));
    }

    [Fact]
    public async Task SilentPort_IsSkippedAfterTlsTimeout()
    {
        // porta che accetta la connessione ma non risponde mai: l'handshake va in timeout e l'HTTP non viene tentato
        using var silent = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        silent.Start();
        int port = ((System.Net.IPEndPoint)silent.LocalEndpoint).Port;
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.1", PortsText = port.ToString(), ConnectTimeoutMs = 500, ReadTimeoutMs = 8000, OutputFolder = _dir,
            Alive = new AliveConfig { Enabled = false },
        };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = await One(cfg);
        Assert.True(r.Tls!.Silent);
        Assert.Equal(Verdict.NotReachable, r.Verdict);
        Assert.Contains(r.Tests, t => t.Id == "HTTP" && t.Outcome == TestOutcome.Skipped);
        Assert.True(sw.ElapsedMilliseconds < 6000, $"durata {sw.ElapsedMilliseconds} ms: l'HTTP non doveva essere tentato");
    }

    [Fact]
    public async Task AliveCheck_MethodsRunInParallel()
    {
        // una porta aperta e una chiusa su loopback: la conferma arriva dal primo metodo che risponde, senza attendere gli altri
        using var srv = new FakePhpServer();
        int closed = FakePhpServer.FreePort();
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var res = await AliveChecker.CheckAsync("127.0.0.1", new AliveConfig { Icmp = false, TcpPorts = [closed, srv.Port], UdpPorts = [FakePhpServer.FreePort()], TimeoutMs = 3000 }, CancellationToken.None);
        Assert.Equal(AliveState.Alive, res.State);
        Assert.True(sw.ElapsedMilliseconds < 2500, $"durata {sw.ElapsedMilliseconds} ms");
    }

    [Fact]
    public async Task NotAlive_IsSkipped()
    {
        // nessun metodo attivo = nessuna conferma: il bersaglio viene saltato (la rete della sandbox non è affidabile per host muti)
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = Config(srv);
        cfg.Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 500, SkipIfNotAlive = true, Retry = false };   // v1.8: senza seconda chance (che proverebbe TCP sulla porta della scansione)
        var r = await One(cfg);
        Assert.Equal(AliveState.NoResponse, r.Alive);
        Assert.Equal(Verdict.NotReachable, r.Verdict);
        Assert.DoesNotContain(r.Tests, t => t.Id == "L1-GET");

        // con "salta" disattivato la scansione HTTP procede comunque
        cfg.Alive.SkipIfNotAlive = false;
        r = await One(cfg);
        Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
    }

    [Fact]
    public async Task UdpAliveCheck_ClosedLoopbackPort_IsAliveByPortUnreachable()
    {
        int port = FakePhpServer.FreePort();
        var res = await AliveChecker.CheckAsync("127.0.0.1", new AliveConfig { Icmp = false, TcpPorts = [], UdpPorts = [port], TimeoutMs = 1500 }, CancellationToken.None);
        Assert.Equal(AliveState.Alive, res.State);
        Assert.Equal($"UDP/{port}", res.Method);
    }

    [Fact]
    public async Task SessionFiles_Report_AndReload()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var engine = new ScanEngine();
        var logs = new List<string>();
        engine.Log += logs.Add;
        var cfg = Config(srv);
        cfg.SessionLabel = "test lab";
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.True(Directory.Exists(s.Folder));
        Assert.EndsWith("_phpscan_test_lab", s.Folder);
        foreach (var f in new[] { SessionFiles.SessionJson, SessionFiles.ResultsJson, SessionFiles.ResultsCsv, SessionFiles.TestsCsv, SessionFiles.ScanLog })
            Assert.True(File.Exists(Path.Combine(s.Folder, f)), f);
        var csv = File.ReadAllLines(Path.Combine(s.Folder, SessionFiles.ResultsCsv));
        Assert.StartsWith("input;host;port", csv[0]);
        Assert.Contains("VulnerableByVersion", csv[1]);
        Assert.Contains(logs, l => l.Contains("Vulnerabile per versione"));

        var path = ReportGenerator.Generate(s);
        Assert.EndsWith($"report_v{s.AppVersion}.html", path);
        Assert.True(File.Exists(Path.Combine(s.Folder, $"report_completo_v{s.AppVersion}.html")));
        var html = File.ReadAllText(Path.Combine(s.Folder, $"report_completo_v{s.AppVersion}.html"));
        Assert.Contains("Vulnerabile per versione", html);
        Assert.Contains("8.3.20", html);
        Assert.Contains("L2-MULTIPART", html);
        Assert.DoesNotContain("<script src", html);
        Assert.EndsWith($"report_v{s.AppVersion}_2.html", ReportGenerator.Generate(s));   // mai sovrascritto

        var reloaded = SessionFiles.ReadSession(s.Folder)!;
        Assert.Single(reloaded.Results);
        Assert.Equal(Verdict.VulnerableByVersion, reloaded.Results[0].Verdict);
        Assert.Equal(ScanStatus.Completed, reloaded.Status);
    }

    [Fact]
    public async Task Stop_KeepsCompletedResults()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = Config(srv);
        cfg.TargetsText = "127.0.0.1\n192.0.2.1\n192.0.2.2\n192.0.2.3";
        cfg.Alive.Enabled = false;
        cfg.Threads = 1;
        cfg.ConnectTimeoutMs = 5000;
        var engine = new ScanEngine();
        var cts = new CancellationTokenSource();
        engine.ResultReady += _ => cts.Cancel();     // dopo il primo risultato
        var s = await engine.RunAsync(cfg, cts.Token);
        Assert.Equal(ScanStatus.Stopped, s.Status);
        Assert.True(s.Results.Count >= 1);
        Assert.Contains(s.Results, r => r.Host == "127.0.0.1" && r.Verdict == Verdict.VulnerableByVersion);
    }

    [Fact]
    public void InvalidTargets_Throw()
    {
        var cfg = new ScanConfig { TargetsText = "nonsense!!", OutputFolder = _dir };
        Assert.ThrowsAsync<ArgumentException>(() => new ScanEngine().RunAsync(cfg, CancellationToken.None)).Wait();
    }
}
