using System.IO.Compression;
using System.Text.Json;
using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Report;

namespace PhpVulnScanner.Tests;

/// <summary>v1.10: verifica DNS dei nomi da CT, seconda chance (corsie fisse, dal ciclo 2 solo host visti attivi), reset dal perimetro, colonna Nomi, suffisso sui CSV rigenerati, configurazione su file, pacchetto per analisi.</summary>
public class V110Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v110_" + Guid.NewGuid().ToString("N"));
    public V110Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    // ---------- nomi da CT: sorte in base alla risoluzione ----------

    [Fact]
    public void CtNameFate_HereRouteDoneElsewhere()
    {
        var here = new HashSet<string>(["192.0.2.10"]); var targets = new HashSet<string>(["192.0.2.10", "192.0.2.11", "192.0.2.12"]);
        Assert.Equal((ScanEngine.CtFate.Here, (string?)null), ScanEngine.CtNameFate(["198.51.100.1", "192.0.2.10"], here, targets, []));
        Assert.Equal((ScanEngine.CtFate.Route, "192.0.2.11"), ScanEngine.CtNameFate(["192.0.2.11"], here, targets, []));
        Assert.Equal((ScanEngine.CtFate.Done, "192.0.2.12"), ScanEngine.CtNameFate(["192.0.2.12"], here, targets, ["192.0.2.12"]));
        Assert.Equal((ScanEngine.CtFate.Elsewhere, (string?)null), ScanEngine.CtNameFate(["198.51.100.7"], here, targets, []));
        Assert.Equal((ScanEngine.CtFate.Elsewhere, (string?)null), ScanEngine.CtNameFate([], here, targets, []));
        Assert.True(new ScanConfig().CtDnsCheck);
        Assert.False(CliRunner.Parse(["--scan", "192.0.2.1", "--no-ct-dns"], _dir, out _, out _, out _)!.CtDnsCheck);
    }

    // ---------- seconda chance: dal ciclo 2 solo host visti attivi ----------

    [Fact]
    public async Task Sweeper_RetriesUnconfirmedHost_EachCycle_WithoutRecovering()
    {
        var cfg = new ScanConfig
        {
            TargetsText = "203.0.113.250", PortsText = "9", PathsText = "/", ConnectTimeoutMs = 300, ReadTimeoutMs = 300, Threads = 2, OutputFolder = _dir,
            Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 300, SkipIfNotAlive = true, Retry = true },
            Level2 = false, WafDetect = false, SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false, PortPrecheck = false,
            Advanced = new AdvancedOptions().Also(o => o.SetAll(false)), Cycles = 2, CyclePauseSec = 0, Consolidate = true,
        };
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(Verdict.NotReachable, Assert.Single(s.Results).Verdict);
        // v1.11: lo sweeper riprova l'host (primo giro di ogni ciclo) senza recuperarlo
        Assert.Equal(2, log.Count(l => l.Contains("Sweeper dell'alive check: 0 host recuperati")));
        Assert.Contains(log, l => l.Contains("Sweeper dell'alive check attivo"));
    }

    // ---------- reset dal perimetro ----------

    [Fact]
    public void PerimeterReset_HasItsOwnReason()
    {
        var r = new ScanResult { Host = "192.0.2.9", IsIpLiteral = true, Port = 443, Scheme = "https", Alive = AliveState.Alive, Error = "Connessione in corso interrotta forzatamente dall'host remoto." };
        Assert.True(VerdictEngine.IsPerimeterReset(r));
        VerdictEngine.Apply(r);
        Assert.Equal(Verdict.NotReachable, r.Verdict);
        Assert.Contains("chiusa dal perimetro", r.VerdictReason);
        var t = new ScanResult { Host = "192.0.2.9", IsIpLiteral = true, Port = 443, Alive = AliveState.Alive, Error = "timeout di connessione" };
        Assert.False(VerdictEngine.IsPerimeterReset(t));
        VerdictEngine.Apply(t);
        Assert.Contains("nessuna risposta HTTP", t.VerdictReason);
    }

    // ---------- report: colonna Nomi, suffissi ----------

    private static ScanResult Row(string host, Verdict v, params string[] names)
    {
        var r = new ScanResult { Input = host, Host = host, IsIpLiteral = true, Port = 443, Scheme = "https", HttpReachable = true, Alive = AliveState.Alive, StartedLocal = DateTime.Now, Verdict = v, PhpDetected = true, PhpVersionRaw = "7.4.33", PhpPresence = "yes" };
        r.DiscoveredNames = [.. names];
        r.Priority = VerdictEngine.Prioritize(r);
        return r;
    }

    private static ScanSession Session(params ScanResult[] rows) => new()
    {
        AppVersion = "1.10", StartLocal = DateTime.Now, EndLocal = DateTime.Now, Status = ScanStatus.Completed, Folder = "", TargetCount = rows.Length, PortCount = 1, Ports = ["443"], Paths = ["/"],
        HostsTotal = rows.Length, HostsAlive = rows.Length, HostsHttp = rows.Length, Results = rows.ToList(), Config = new ScanConfig(),
    };

    [Fact]
    public void NamesColumn_OnePerLine_NoBreakInsideNames()
    {
        var s = Session(Row("192.0.2.10", Verdict.VulnerableByVersion, "alpha.example.org", "beta.example.org", "gamma-very-long-name.example.org"));
        string html = CompactReportGenerator.Build(s, "x.html");
        Assert.Contains("alpha.example.org<br>beta.example.org<br>gamma-very-long-name.example.org", html);
        Assert.DoesNotContain("word-break:break-all", html);
        Assert.Contains("table.att td:nth-child(2),table.hosts td:nth-child(2)", html);
        Assert.Equal("–", CompactReportGenerator.NamesHtml([]));
    }

    [Fact]
    public void Regenerate_SuffixesCsvFilesLikeTheReports()
    {
        Assert.Equal("", ReportGenerator.Suffix(Path.Combine("x", "report_v1.10.html")));
        Assert.Equal("_2", ReportGenerator.Suffix(Path.Combine("x", "report_v1.10_2.html")));
        Assert.Equal("_12", ReportGenerator.Suffix("report_completo_v1.10_12.html"));
        var s = Session(Row("192.0.2.10", Verdict.VulnerableByVersion));
        s.Folder = _dir;
        ReportGenerator.Generate(s);
        string second = ReportGenerator.Generate(s);
        Assert.EndsWith("report_v1.10_2.html", second);
        Assert.True(File.Exists(Path.Combine(_dir, "elenco_v1.10.csv")));
        Assert.True(File.Exists(Path.Combine(_dir, "elenco_v1.10_2.csv")));
    }

    // ---------- configurazione su file ----------

    [Fact]
    public async Task Config_LoadFromFileOrSessionJson_ExplicitOptionsWin_SaveConfigExits()
    {
        var cfg = new ScanConfig { TargetsText = "192.0.2.0/29", PortsText = "8443", Threads = 3, Alive = new AliveConfig { Parallel = 5 }, CtDnsCheck = false };
        string file = Path.Combine(_dir, "cfg.json");
        File.WriteAllText(file, JsonSerializer.Serialize(cfg, ScanConfig.JsonOptions));
        var loaded = CliRunner.Parse(["--config", file], _dir, out var err, out _, out _);
        Assert.Null(err); Assert.NotNull(loaded);
        Assert.Equal("192.0.2.0/29", loaded!.TargetsText); Assert.Equal("8443", loaded.PortsText); Assert.Equal(3, loaded.Threads); Assert.Equal(5, loaded.Alive.Parallel); Assert.False(loaded.CtDnsCheck);
        var over = CliRunner.Parse(["--config", file, "--threads", "9", "--ports", "80"], _dir, out _, out _, out _)!;
        Assert.Equal(9, over.Threads); Assert.Equal("80", over.PortsText); Assert.Equal("192.0.2.0/29", over.TargetsText);
        // session.json: blocco Config
        string sess = Path.Combine(_dir, "session.json");
        File.WriteAllText(sess, JsonSerializer.Serialize(new ScanSession { Folder = _dir, Config = cfg, StartLocal = DateTime.Now }, ScanConfig.JsonOptions));
        Assert.Equal("8443", CliRunner.LoadConfigFile(sess).PortsText);
        // --save-config: scrive e termina senza scansione
        string outFile = Path.Combine(_dir, "saved.json");
        var sw = new StringWriter();
        int code = await CliRunner.RunAsync(["--scan", "192.0.2.1", "--threads", "7", "--save-config", outFile], _dir, sw, CancellationToken.None);
        Assert.Equal(0, code);
        Assert.Equal(7, JsonSerializer.Deserialize<ScanConfig>(File.ReadAllText(outFile), ScanConfig.JsonOptions)!.Threads);
        Assert.Contains("Configurazione salvata", sw.ToString());
        Assert.Empty(Directory.GetDirectories(_dir));   // nessuna sessione creata
        Assert.Null(CliRunner.Parse(["--config", Path.Combine(_dir, "manca.json")], _dir, out var e2, out _, out _));
        Assert.Contains("configurazione non leggibile", e2);
    }

    // ---------- pacchetto per analisi ----------

    [Fact]
    public void AnalysisBundle_StripsBodies_KeepsEverythingElse()
    {
        string json = "{\"Requests\":[{\"Method\":\"GET\",\"Body\":\"<html>ciao</html>\",\"BodyLength\":17,\"Status\":200,\"Ok\":true,\"Nothing\":null,\"Ratio\":1.5}],\"Body\":\"\",\"Name\":\"Body\"}";
        string stripped = AnalysisBundle.StripBodies(json);
        Assert.DoesNotContain("<html>ciao</html>", stripped);
        Assert.Contains("\"Body\":\"<rimosso: 17 byte, sha256 ", stripped);
        Assert.Contains("\"BodyLength\":17", stripped); Assert.Contains("\"Status\":200", stripped); Assert.Contains("\"Ok\":true", stripped); Assert.Contains("\"Nothing\":null", stripped); Assert.Contains("\"Ratio\":1.5", stripped);
        Assert.Contains("\"Name\":\"Body\"", stripped);   // un valore "Body" non è una proprietà Body
        Assert.Contains("\"Body\":\"\"", stripped);
        using var doc = JsonDocument.Parse(stripped);   // JSON ancora valido
    }

    [Fact]
    public void AnalysisBundle_Build_ZipWithoutSamples_JsonlLineCountKept()
    {
        var folder = Path.Combine(_dir, "sess"); Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "session.json"), "{\"AppVersion\":\"1.10\"}");
        File.WriteAllText(Path.Combine(folder, "scan.log"), "riga\n");
        File.WriteAllText(Path.Combine(folder, "results.json"), "{\"Results\":[{\"Requests\":[{\"Body\":\"abc\"}]}]}");
        File.WriteAllText(Path.Combine(folder, "results.jsonl"), "{\"Requests\":[{\"Body\":\"abc\"}]}\n{\"Requests\":[{\"Body\":\"def\"}]}\n");
        File.WriteAllText(Path.Combine(folder, "samples.json"), "{\"segreto\":1}");
        string zip = AnalysisBundle.Build(folder, Path.Combine(_dir, AnalysisBundle.DefaultName(folder, "1.10")));
        Assert.EndsWith("sess_analisi_v1.10.zip", zip);
        using var z = ZipFile.OpenRead(zip);
        var names = z.Entries.Select(e => e.Name).ToList();
        Assert.Contains("results.jsonl", names); Assert.Contains("scan.log", names); Assert.DoesNotContain("samples.json", names);
        using var rd = new StreamReader(z.GetEntry("results.jsonl")!.Open());
        var lines = rd.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        Assert.All(lines, l => Assert.Contains("<rimosso: 3 byte", l));
        using var rj = new StreamReader(z.GetEntry("results.json")!.Open());
        Assert.DoesNotContain("\"abc\"", rj.ReadToEnd());
    }
}
