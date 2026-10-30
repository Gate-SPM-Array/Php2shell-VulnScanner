using System.Diagnostics;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Tests;

/// <summary>
/// v1.7: seconda passata sui nomi in parallelo (la coda del ciclo era un thread solo), anteprima delle righe per IP prima dei nomi,
/// catch-all 5xx anche con la radice in redirect, "PHP forse" in evidenza nei report.
/// </summary>
public class V17Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v17_" + Guid.NewGuid().ToString("N"));
    public V17Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string paths = "/ /index.php") => new()
    {
        TargetsText = "127.0.0.1", PortsText = srv.Port.ToString(), PathsText = paths, ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 4, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = false }, Level1InfoPages = false, Level1EasterEgg = false, Level2 = false, WafDetect = false, WafBehaviour = false, SizeProbeKiB = 4,
        SurfaceDiscovery = false, DiscoverNames = true, RescanDiscoveredNames = true, FoldSameContentNames = true, FoldSameOutcomeNames = true, PortPrecheck = false,
        Advanced = new AdvancedOptions().Also(o => o.SetAll(false)), ServiceBudgetMs = 0,
    };

    /// <summary>Server che annuncia quattro nomi (un redirect per percorso) e risponde a ogni nome come vhost con lo stesso esito; ogni risposta tarda 400 ms.</summary>
    private static FakePhpServer FourNamesServer()
    {
        var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/7.4.33", VhostName = "*", VhostPoweredBy = "PHP/7.4.33", VhostBody = "<html><body>vhost body, different from the IP</body></html>", DelayMs = 400 };
        foreach (var n in new[] { "a", "b", "c", "d" }) srv.Redirects["/r" + n] = $"https://{n}.example.org/";
        return srv;
    }

    // ---------- nomi in parallelo ----------

    [Fact]
    public async Task DiscoveredNames_AreScannedInParallel_WithTheSameFolding()
    {
        using var srv = FourNamesServer();
        var cfg = Cfg(srv, "/ /index.php /ra /rb /rc /rd");
        var sw = Stopwatch.StartNew();
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        sw.Stop();
        var ip = Assert.Single(s.Results);
        Assert.Equal(["a.example.org", "b.example.org", "c.example.org", "d.example.org"], ip.DiscoveredNames.OrderBy(n => n, StringComparer.Ordinal));
        Assert.Equal(["a.example.org", "b.example.org", "c.example.org", "d.example.org"], ip.SameOutcomeNames);   // ordine dei nomi, come prima
        Assert.Equal(4, ip.Tests.Count(t => t.Id == "NAME-OUTCOME"));
        // riga per IP: 6 percorsi × 400 ms = 2,4 s; ogni nome 6 percorsi × 400 ms = 2,4 s. In sequenza: ≥ 12 s. In parallelo su 4 thread: ≈ 5 s.
        Assert.True(sw.Elapsed.TotalSeconds < 9, $"nomi in sequenza? {sw.Elapsed.TotalSeconds:F1} s");
        var obs = SessionFiles.ReadJsonl(Path.Combine(s.Folder, SessionFiles.ResultsJsonl));
        Assert.Equal(5, obs.Count);
        Assert.Equal(4, obs.Count(o => o.NameRescan));
    }

    [Fact]
    public async Task IpRow_IsPreviewedBeforeTheNamePass_AndReemittedComplete()
    {
        using var srv = FourNamesServer();
        srv.DelayMs = 50;
        var engine = new ScanEngine();
        var seen = new List<(int Names, int Tests)>();
        engine.ResultReady += r => { lock (seen) seen.Add((r.SameOutcomeNames.Count, r.Tests.Count(t => t.Id == "NAME-OUTCOME"))); };
        var s = await engine.RunAsync(Cfg(srv, "/ /index.php /ra /rb /rc /rd"), CancellationToken.None);
        Assert.Single(s.Results);
        Assert.Equal(2, seen.Count);                 // anteprima + riga definitiva, stessa chiave
        Assert.Equal((0, 0), seen[0]);               // prima dei nomi: nessun nome ripiegato
        Assert.Equal((4, 4), seen[1]);               // dopo: i quattro nomi con lo stesso esito
        // nel file di sessione la riga è una sola
        Assert.Single(SessionFiles.ReadSession(s.Folder)!.Results);
    }

    [Fact]
    public async Task NoDiscoveredNames_NoPreview()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.36" };
        var engine = new ScanEngine();
        int ready = 0;
        engine.ResultReady += _ => Interlocked.Increment(ref ready);
        var s = await engine.RunAsync(Cfg(srv), CancellationToken.None);
        Assert.Single(s.Results);
        Assert.Equal(1, ready);
    }

    [Fact]
    public async Task Stop_DuringNamePass_EndsCleanly()
    {
        using var srv = FourNamesServer();
        using var cts = new CancellationTokenSource();
        var engine = new ScanEngine();
        engine.ResultReady += _ => cts.CancelAfter(300);   // l'anteprima arriva quando la passata sui nomi sta partendo
        var s = await engine.RunAsync(Cfg(srv, "/ /index.php /ra /rb /rc /rd"), cts.Token);
        Assert.Equal(ScanStatus.Stopped, s.Status);
    }

    // ---------- catch-all 5xx con la radice in redirect ----------

    private static HttpSnapshot Snap(int status, int len) => new() { Method = "GET", Url = "https://192.0.2.1/x", Status = status, Body = new string('x', len), BodyLength = len };

    [Fact]
    public void IsServerErrorEverywhere_IgnoresRedirectPages()
    {
        Assert.True(SurfaceDiscovery.IsServerErrorEverywhere(Snap(503, 299), [Snap(302, 0), Snap(503, 299)]));    // "/" 302, /index.php 503: backend morto
        Assert.False(SurfaceDiscovery.IsServerErrorEverywhere(Snap(503, 299), [Snap(302, 0)]));                   // solo il redirect: nessun confronto
        Assert.False(SurfaceDiscovery.IsServerErrorEverywhere(Snap(503, 299), [Snap(302, 0), Snap(200, 5000)]));  // una pagina viva
        Assert.True(SurfaceDiscovery.IsServerErrorEverywhere(Snap(502, 150), [Snap(502, 150), Snap(502, 3000)]));  // regola v1.6 invariata
    }

    [Fact]
    public async Task RootRedirect_RestServerError_SkipsEntryPointsAndPathProbes()
    {
        using var srv = new FakePhpServer { Server = "Apache", AllStatus = 503, AllStatusRootRedirect = "https://www.example.org/" };
        var cfg = Cfg(srv);
        cfg.DiscoverNames = false; cfg.RescanDiscoveredNames = false; cfg.SurfaceDiscovery = true;
        cfg.Advanced = AdvancedOptions.Parse("composer,status,appversion,behaviours,exposures");
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.Contains(r.Tests, t => t.Id == "L1-SURFACE-PROBE" && t.Detail.Contains("503"));
        Assert.Contains(r.Tests, t => t.Id == "ADV-SKIP" && t.Detail.Contains("503"));
        Assert.DoesNotContain(r.Tests, t => t.Id == "ADV-COMPOSER");
        // niente punti di ingresso: le richieste sono "/", "/index.php", il .php casuale e poco altro
        Assert.True(srv.Requests.Count <= 6, string.Join("\n", srv.Requests));
        Assert.Equal(Verdict.NoPhpDetected, r.Verdict);
    }

    // ---------- "PHP forse" nei report ----------

    private static ScanResult Row(string host, int port, Verdict v, string presence = "no")
    {
        var r = new ScanResult { Input = host, Host = host, IsIpLiteral = true, Port = port, Scheme = "https", HttpReachable = true, Alive = AliveState.Alive, StartedLocal = DateTime.Now, Verdict = v, PhpPresence = presence };
        if (presence == "maybe") { r.PhpHintScore = 2; r.PhpHints = ["2: cookie wordpress_test_cookie"]; }
        r.Priority = VerdictEngine.Prioritize(r);
        return r;
    }

    private static ScanSession Session(params ScanResult[] rows) => new()
    {
        AppVersion = "1.7", StartLocal = DateTime.Now, EndLocal = DateTime.Now, Status = ScanStatus.Completed, Folder = "", TargetCount = rows.Length, PortCount = 1, Ports = ["443"], Paths = ["/"],
        HostsTotal = rows.Length, HostsAlive = rows.Length, HostsHttp = rows.Length, Results = rows.ToList(), Config = new ScanConfig(),
    };

    [Fact]
    public void Reports_HighlightPhpMaybe()
    {
        var s = Session(Row("192.0.2.10", 443, Verdict.NoPhpDetected, "maybe"), Row("192.0.2.11", 443, Verdict.NoPhpDetected));
        string compact = CompactReportGenerator.Build(s, "report_completo_v1.7.html");
        Assert.Contains("<div class=\"kpi maybe\">", compact);
        Assert.Contains("note maybe", compact);
        Assert.Contains("1 servizi su 1 host rispondono senza prova di PHP", compact);
        int sus = compact.IndexOf("<h2>PHP sospetto</h2>", StringComparison.Ordinal), hosts = compact.IndexOf("<h2>Host attivi</h2>", StringComparison.Ordinal), att = compact.IndexOf("Da tenere in considerazione", StringComparison.Ordinal);
        Assert.True(att < sus && sus < hosts);   // subito dopo "da tenere in considerazione"
        string full = ReportGenerator.Build(s);
        Assert.Equal(1, full.Split("<tr class=\"row maybe\"").Length - 1);
        Assert.Contains("tr.row.maybe td{background:#f3eeff}", full);
        // senza "forse" niente richiamo
        string none = CompactReportGenerator.Build(Session(Row("192.0.2.11", 443, Verdict.NoPhpDetected)), "x.html");
        Assert.DoesNotContain("note maybe", none);
    }
}
