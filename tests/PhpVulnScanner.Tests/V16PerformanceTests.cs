using System.Diagnostics;
using System.Text;
using System.Text.Json;
using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;

namespace PhpVulnScanner.Tests;

/// <summary>
/// v1.6, prestazioni sulla /20: SessionWriter che non blocca i thread durante la riscrittura di results.json, host "502 su tutto"
/// che non ricevono le sonde su percorso, budget di tempo per servizio, opzione --budget.
/// </summary>
public class V16PerformanceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v16perf_" + Guid.NewGuid().ToString("N"));
    public V16PerformanceTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string targets = "127.0.0.1") => new()
    {
        TargetsText = targets, PortsText = srv.Port.ToString(), PathsText = "/ /index.php", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 4, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = false }, Level1InfoPages = false, Level1EasterEgg = false, Level2 = true, WafDetect = true, WafBehaviour = false, SizeProbeKiB = 4,
        SurfaceDiscovery = true, DiscoverNames = false, RescanDiscoveredNames = false, PortPrecheck = false,
        Advanced = AdvancedOptions.Parse("headvsget,composer,status,appversion,behaviours,level2all,browserua,components,exposures"),
        ServiceBudgetMs = 0,
    };

    private static ScanResult Synthetic(int i, int bodyBytes)
    {
        var r = new ScanResult { Input = "198.51.100.0/24", Host = $"198.51.100.{i % 250}", IsIpLiteral = true, Port = 1000 + i, Scheme = "https", HttpReachable = true, StartedLocal = DateTime.Now, PhpVersionRaw = "8.1.2" };
        var snap = new HttpSnapshot { Method = "GET", Url = $"https://{r.Host}:{r.Port}/", Status = 200, Reason = "OK", Body = new string('x', bodyBytes), BodyLength = bodyBytes, Headers = [new("Server", "nginx")] };
        r.Add("L1-GET", "GET /", TestOutcome.Info, "200 OK", snap);
        return r;
    }

    private ScanSession NewSession(string? name = null)
    {
        var folder = Path.Combine(_dir, name ?? Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        return new ScanSession { Folder = folder, StartLocal = DateTime.Now, Config = new ScanConfig { OutputFolder = _dir }, TargetCount = 1, PortCount = 1 };
    }

    // ---------- SessionWriter non bloccante ----------

    [Fact]
    public void Writer_UpsertNeverBlocks_WhileRewriteRunsInBackground_AndFinalFileIsComplete()
    {
        const int n = 2000, body = 10 * 1024;
        var session = NewSession();
        var results = Enumerable.Range(0, n).Select(i => Synthetic(i, body)).ToList();
        double maxMs = 0; int slow = 0;
        using (var w = new SessionWriter(session) { RewriteInterval = 1 })
        {
            foreach (var r in results)
            {
                var sw = Stopwatch.StartNew();
                w.Upsert(r);
                double ms = sw.Elapsed.TotalMilliseconds;
                if (ms > maxMs) maxMs = ms;
                if (ms > 50) slow++;
            }
            // con 20 MB di risultati la riscrittura di sfondo dura ben più di 1 ms: ne devono essere partite diverse, mai una per Upsert (single-flight)
            Assert.InRange(w.BackgroundRewrites, 1, n - 1);
            session.Results = results;
            session.Status = ScanStatus.Completed;
            w.Finish(session);
        }
        // Upsert fa solo l'append in results.jsonl e la copia dell'elenco: nella versione precedente ogni riscrittura (serializzazione dell'intera
        // sessione sotto il lock) teneva ferma Upsert per secondi; qui si tollera solo qualche pausa di GC
        Assert.True(maxMs < 250, $"Upsert più lenta: {maxMs:F0} ms");
        Assert.True(slow <= 3, $"{slow} Upsert oltre 50 ms (max {maxMs:F0} ms)");

        var read = SessionFiles.ReadSession(session.Folder);
        Assert.NotNull(read);
        Assert.Equal(ScanStatus.Completed, read!.Status);
        Assert.Equal(n, read.Results.Count);
        Assert.All(read.Results, r => Assert.Equal(body, r.Requests[0].Body.Length));
        Assert.Equal(n, SessionFiles.ReadJsonl(Path.Combine(session.Folder, SessionFiles.ResultsJsonl)).Count);
        Assert.False(File.Exists(Path.Combine(session.Folder, SessionFiles.ResultsJson + ".tmp")));
    }

    [Fact]
    public void Writer_DisposeWithoutFinish_WaitsForBackgroundRewrite_AndWritesPendingResults()
    {
        var session = NewSession();
        using (var w = new SessionWriter(session) { RewriteInterval = 1 })
        {
            for (int i = 0; i < 50; i++) w.Upsert(Synthetic(i, 2048));
        }
        var read = SessionFiles.ReadSession(session.Folder);
        Assert.NotNull(read);
        Assert.Equal(50, read!.Results.Count);
    }

    [Fact]
    public void WriteJsonAtomic_ProducesTheSameBytesAsTheStringSerializer()
    {
        var session = NewSession();
        session.Results = Enumerable.Range(0, 5).Select(i => Synthetic(i, 300)).ToList();
        session.Results[1].Error = "àèì \"quoted\" <tag> —";
        session.ParseErrors.Add("porta non valida: x");
        string viaStream = Path.Combine(_dir, "stream.json");
        SessionFiles.WriteResultsJson(viaStream, session);
        var streamBytes = File.ReadAllBytes(viaStream);
        var stringBytes = new UTF8Encoding(false).GetBytes(SessionFiles.ResultsToJson(session));
        Assert.Equal(stringBytes, streamBytes);
        Assert.False(File.Exists(viaStream + ".tmp"));

        var a = JsonSerializer.Deserialize<ScanSession>(streamBytes, ScanConfig.JsonOptions)!;
        var b = JsonSerializer.Deserialize<ScanSession>(stringBytes, ScanConfig.JsonOptions)!;
        Assert.Equal(b.Results.Count, a.Results.Count);
        Assert.Equal(b.Results[1].Error, a.Results[1].Error);
        Assert.Equal(b.Results.Select(r => r.Port), a.Results.Select(r => r.Port));
    }

    // ---------- catch-all 5xx ----------

    private static HttpSnapshot Snap(int status, int bodyLength) => new() { Method = "GET", Url = "https://192.0.2.1/", Status = status, Body = new string('e', bodyLength), BodyLength = bodyLength };

    [Fact]
    public void IsServerErrorEverywhere_GatewayStatuses_AndSimilarBodies()
    {
        Assert.True(SurfaceDiscovery.IsServerErrorEverywhere(Snap(502, 150), [Snap(502, 150), Snap(502, 3000)]));   // 502: basta lo stato
        Assert.True(SurfaceDiscovery.IsServerErrorEverywhere(Snap(500, 1000), [Snap(500, 950), Snap(500, 1090)]));  // 500 con corpi entro il 10%
        Assert.False(SurfaceDiscovery.IsServerErrorEverywhere(Snap(500, 1000), [Snap(500, 950), Snap(500, 5000)])); // 500 ma una pagina diversa: l'applicazione risponde
        Assert.False(SurfaceDiscovery.IsServerErrorEverywhere(Snap(502, 150), [Snap(200, 150), Snap(502, 150)]));   // una pagina 200: non è tutto morto
        Assert.False(SurfaceDiscovery.IsServerErrorEverywhere(Snap(200, 150), [Snap(200, 150)]));
        Assert.False(SurfaceDiscovery.IsServerErrorEverywhere(Snap(404, 150), [Snap(404, 150)]));
        Assert.False(SurfaceDiscovery.IsServerErrorEverywhere(Snap(502, 150), []));                                 // nessuna pagina: nessun confronto
        Assert.Equal(SurfaceDiscovery.MissingFileKind.ServerError, SurfaceDiscovery.ClassifyMissingPhp(Snap(503, 10), [Snap(503, 10)]));
        Assert.Equal(SurfaceDiscovery.MissingFileKind.Unknown, SurfaceDiscovery.ClassifyMissingPhp(Snap(503, 10)));
    }

    [Fact]
    public async Task CatchAll502Host_SkipsEntryPointsAndPathProbes_WithOneSkipLine()
    {
        using var srv = new FakePhpServer { Server = "nginx", AllStatus = 502 };
        var s = await new ScanEngine().RunAsync(Cfg(srv), CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.True(r.HttpReachable);
        Assert.Equal(Verdict.NoPhpDetected, r.Verdict);

        var probe = Assert.Single(r.Tests, t => t.Id == "L1-SURFACE-PROBE");
        Assert.Contains("errore del server su qualunque percorso", probe.Detail);
        Assert.Empty(r.PhpSurface);
        Assert.DoesNotContain(r.Tests, t => t.Id == "L1-SURFACE");
        var skip = Assert.Single(r.Tests, t => t.Id == "ADV-SKIP");
        Assert.Contains("502", skip.Detail);
        // nessun punto di ingresso, nessun file di Composer/versione, nessuna esposizione: solo /, /index.php, il .php casuale, HEAD/OPTIONS e il livello 2
        Assert.DoesNotContain(srv.Requests, q => q.Contains("/wp-login.php") || q.Contains("/phpmyadmin/") || q.Contains("/robots.txt"));
        Assert.DoesNotContain(srv.Requests, q => q.Contains("/composer.json") || q.Contains("/readme.html") || q.Contains("/.git/") || q.Contains("/.env"));
        Assert.DoesNotContain(r.Tests, t => t.Id is "ADV-COMPOSER" or "ADV-APPVERSION" or "ADV-EXPOSURES" or "ADV-STATUS");
        Assert.True(srv.Requests.Count < SurfaceDiscovery.EntryPoints.Length, $"{srv.Requests.Count} richieste");
        // le sonde economiche restano
        Assert.Contains(r.Tests, t => t.Id == "ADV-HEAD");
        Assert.Contains(r.Tests, t => t.Id.StartsWith("L2-"));
    }

    [Fact]
    public async Task Normal200Host_IsUnaffected_EntryPointsRequested_NoSkipLine()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.40" };
        var s = await new ScanEngine().RunAsync(Cfg(srv), CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.DoesNotContain(r.Tests, t => t.Id == "ADV-SKIP");
        Assert.DoesNotContain(r.Tests, t => t.Id == "BUDGET");
        Assert.Empty(r.SkippedForBudget);
        Assert.Contains(srv.Requests, q => q.Contains("/wp-login.php"));
        Assert.Contains(srv.Requests, q => q.Contains("/composer.json"));
        Assert.Contains(r.Tests, t => t.Id == "L1-SURFACE");
        Assert.Equal(Verdict.FixedByVersion, r.Verdict);
    }

    // ---------- budget di tempo per servizio ----------

    [Fact]
    public async Task Budget_WhenExhausted_SkipsOptionalProbes_KeepsLevel1Level2Waf_AndAddsBudgetLine()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.40" };
        var cfg = Cfg(srv);
        cfg.ServiceBudgetMs = 1;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.NotEmpty(r.SkippedForBudget);
        var line = Assert.Single(r.Tests, t => t.Id == "BUDGET");
        Assert.Equal(TestOutcome.Warn, line.Outcome);
        Assert.Contains("esaurito", line.Detail);
        Assert.Contains(r.SkippedForBudget[0], line.Detail);
        // livello 1, livello 2 e WAF non guardano il budget
        Assert.Contains(r.Tests, t => t.Id == "L1-GET");
        Assert.Contains(r.Tests, t => t.Id == "L1-SURFACE-PROBE");
        Assert.Contains(r.Tests, t => t.Id.StartsWith("L2-"));
        Assert.Contains(r.Tests, t => t.Id.StartsWith("WAF-"));
        Assert.Equal(Verdict.FixedByVersion, r.Verdict);
        // superficie: i punti di ingresso non sono stati provati; test avanzati: i gruppi su percorso saltati
        Assert.DoesNotContain(srv.Requests, q => q.Contains("/wp-login.php"));
        Assert.DoesNotContain(srv.Requests, q => q.Contains("/composer.json"));
        Assert.Contains(r.SkippedForBudget, x => x.Contains("Composer"));
        Assert.Contains(r.SkippedForBudget, x => x.Contains("superficie PHP"));
        Assert.Contains("budget di", File.ReadAllText(Path.Combine(s.Folder, SessionFiles.ScanLog)));
    }

    [Fact]
    public void Budget_CliOption_ParsesSeconds_RejectsNegative_AndIsInUsage()
    {
        var cfg = CliRunner.Parse(["--scan", "192.0.2.1", "--budget", "30"], _dir, out var err, out _, out _);
        Assert.Null(err);
        Assert.Equal(30000, cfg!.ServiceBudgetMs);
        cfg = CliRunner.Parse(["--scan", "192.0.2.1", "--budget", "0"], _dir, out err, out _, out _);
        Assert.Null(err);
        Assert.Equal(0, cfg!.ServiceBudgetMs);
        Assert.Null(CliRunner.Parse(["--scan", "192.0.2.1", "--budget", "-5"], _dir, out err, out _, out _));
        Assert.NotNull(err);
        Assert.Null(CliRunner.Parse(["--scan", "192.0.2.1", "--budget", "abc"], _dir, out err, out _, out _));
        Assert.Contains("--budget", err);
        Assert.Equal(120000, CliRunner.Parse(["--scan", "192.0.2.1"], _dir, out _, out _, out _)!.ServiceBudgetMs);
        Assert.Contains("--budget 120", CliRunner.Usage());
    }

    [Fact]
    public void ScanContext_OverBudget_FollowsConfigAndStopwatch()
    {
        var cfg = new ScanConfig { ServiceBudgetMs = 0 };
        var r = new ScanResult { Host = "192.0.2.1", Port = 443 };
        using var http = new HttpProbe(1000, 1000);
        var ctx = new ScanContext { Config = cfg, Http = http, Endpoint = new HttpEndpoint("https", "192.0.2.1", 443), Result = r, Paths = ["/"], Log = _ => { }, Ct = CancellationToken.None };
        Assert.False(ctx.OverBudget);                    // 0 = nessun budget, anche dopo tempo
        cfg.ServiceBudgetMs = 60000;
        Assert.False(ctx.OverBudget);
        var done = Stopwatch.StartNew(); Thread.Sleep(5); done.Stop();
        var ctx2 = new ScanContext { Config = new ScanConfig { ServiceBudgetMs = 1 }, Http = http, Endpoint = ctx.Endpoint, Result = r, Paths = ["/"], Log = _ => { }, Ct = CancellationToken.None, Budget = done };
        Assert.True(ctx2.OverBudget);
    }
}
