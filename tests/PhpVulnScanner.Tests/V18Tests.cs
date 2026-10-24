using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Targets;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Tests;

/// <summary>
/// v1.8: coda a priorità per i nomi scoperti, tetto separato e seconda chance dell'alive check, sonde annullate non attese,
/// fusione per campo tra i cicli, Certificate Transparency sul sottodominio, "PHP forse" nel gruppo dei verdetti, elenco per Excel.
/// </summary>
public class V18Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v18_" + Guid.NewGuid().ToString("N"));
    public V18Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string targets = "127.0.0.1", string paths = "/ /index.php") => new()
    {
        TargetsText = targets, PortsText = srv.Port.ToString(), PathsText = paths, ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 4, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = false }, Level1InfoPages = false, Level1EasterEgg = false, Level2 = false, WafDetect = false, WafBehaviour = false, SizeProbeKiB = 4,
        SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false, FoldSameContentNames = true, FoldSameOutcomeNames = true, PortPrecheck = false,
        Advanced = new AdvancedOptions().Also(o => o.SetAll(false)), ServiceBudgetMs = 0,
    };

    // ---------- seconda chance dell'alive check ----------

    [Fact]
    public async Task SecondChance_RecoversHost_AndReplacesTheRow()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/7.4.33" };
        var cfg = Cfg(srv);
        // primo giro: nessun metodo → non confermato; seconda chance: TCP sulla porta della scansione → attivo
        cfg.Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 500, SkipIfNotAlive = true, Retry = true };
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var ready = new List<Verdict>();
        engine.ResultReady += r => { lock (ready) ready.Add(r.Verdict); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(ScanStatus.Completed, s.Status);
        Assert.True(s.Results.Count == 1, string.Join("\n", log) + "\nREADY: " + string.Join(",", ready));
        var r = Assert.Single(s.Results);
        Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        Assert.Equal(AliveState.Alive, r.Alive);
        Assert.Equal(1, s.HostsAlive);
        Assert.Equal([Verdict.NotReachable, Verdict.VulnerableByVersion], ready);   // prima la riga "non raggiungibile", poi la sostituzione
        Assert.Contains(log, l => l.Contains("Seconda chance dell'alive check: 1 host"));
        Assert.Contains(log, l => l.Contains("Seconda chance: 1 host recuperati su 1"));
        // file di sessione: una riga sola; results.jsonl: entrambe le osservazioni
        Assert.Single(SessionFiles.ReadSession(s.Folder)!.Results);
        var obs = SessionFiles.ReadJsonl(Path.Combine(s.Folder, SessionFiles.ResultsJsonl));
        Assert.Equal(2, obs.Count);
        Assert.Equal(Verdict.NotReachable, obs[0].Verdict);
        Assert.True(s.Results.Single().History.Count <= 1);   // ciclo singolo: nessuna riga di storia doppia
    }

    [Fact]
    public async Task SecondChance_Consolidated_KeepsOneHistoryLinePerCycle()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/7.4.33" };
        var cfg = Cfg(srv);
        cfg.Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 300, SkipIfNotAlive = true, Retry = true };
        cfg.Cycles = 2; cfg.CyclePauseSec = 0; cfg.Consolidate = true;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        Assert.Equal(2, r.History.Count);
        Assert.All(r.History, h => Assert.Contains("Vulnerabile per versione", h));
    }

    [Fact]
    public async Task NoRetry_LeavesHostUnreachable()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/7.4.33" };
        var cfg = Cfg(srv);
        cfg.Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 300, SkipIfNotAlive = true, Retry = false };
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(Verdict.NotReachable, Assert.Single(s.Results).Verdict);
    }

    [Fact]
    public void Cli_AliveParallelAndRetry()
    {
        var cfg = CliRunner.Parse(["--scan", "192.0.2.1", "--alive-parallel", "3", "--no-alive-retry"], _dir, out _, out _, out _)!;
        Assert.Equal(3, cfg.Alive.Parallel);
        Assert.False(cfg.Alive.Retry);
        Assert.Equal(8, new AliveConfig().Parallel);
        Assert.True(new AliveConfig().Retry);
    }

    [Fact]
    public async Task AliveChecker_DoesNotWaitForCancelledProbes()
    {
        using var srv = new FakePhpServer();
        var cfg = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [srv.Port], UdpPorts = [9], TimeoutMs = 5000 };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var res = await AliveChecker.CheckAsync("127.0.0.1", cfg, CancellationToken.None);
        Assert.Equal(AliveState.Alive, res.State);
        Assert.True(sw.ElapsedMilliseconds < 3000, $"{sw.ElapsedMilliseconds} ms");   // prima: l'intero timeout UDP
        Assert.Equal(2, res.Methods.Count);   // il metodo rimasto in sospeso è registrato come annullato (su loopback può confermare anche UDP/9 con port unreachable)
        Assert.Contains(res.Methods, m => m.Confirmed || m.Detail.Contains("annullato"));
    }

    // ---------- coda a priorità: i nomi passano davanti agli host nuovi ----------

    [Fact]
    public async Task NameJobs_RunBeforeTheNextHost()
    {
        using var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/7.4.33", VhostName = "*", VhostPoweredBy = "PHP/7.4.33", VhostBody = "<html>vhost</html>" };
        srv.Redirects["/ra"] = "https://a.example.org/"; srv.Redirects["/rb"] = "https://b.example.org/";
        var cfg = Cfg(srv, "127.0.0.1 127.0.0.2", "/ /index.php /ra /rb");
        cfg.Threads = 1; cfg.RandomOrder = false; cfg.DiscoverNames = true; cfg.RescanDiscoveredNames = true;
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(2, s.Results.Count);
        int nameA = log.FindIndex(l => l.StartsWith("a.example.org @ 127.0.0.1")), nameB = log.FindIndex(l => l.StartsWith("b.example.org @ 127.0.0.1")), host2 = log.FindIndex(l => l.StartsWith("127.0.0.2:"));
        Assert.True(nameA > 0 && nameB > 0 && host2 > 0, string.Join("\n", log));
        Assert.True(nameA < host2 && nameB < host2, "i nomi del primo host devono finire prima del secondo host");
        var ip = s.Results.Single(r => r.Host == "127.0.0.1");
        Assert.Equal(["a.example.org", "b.example.org"], ip.SameOutcomeNames);
    }

    // ---------- fusione per campo ----------

    private static ScanResult R(string host, int cycle, DateTime t) => new() { Host = host, IsIpLiteral = true, Port = 443, Scheme = "https", HttpReachable = true, Alive = AliveState.Alive, Cycle = cycle, StartedLocal = t };

    [Fact]
    public void Merge_UnitesFieldsAcrossCycles_AndRecomputesVerdict()
    {
        var t0 = new DateTime(2026, 10, 24, 10, 0, 0);
        var c1 = R("192.0.2.5", 1, t0); c1.PhpDetected = true; c1.PhpEvidence = "X-Powered-By"; c1.PhpVersionRaw = "7.4.33"; c1.VersionStatus = VersionStatus.EndOfLife; c1.Sapi = "fpm"; c1.PhpSurface = ["/index.php (200)"]; c1.Technologies = ["Nginx"];
        VerdictEngine.Apply(c1);
        var c2 = R("192.0.2.5", 2, t0.AddHours(1)); c2.PhpDetected = true; c2.PhpEvidence = "cookie"; c2.Application = "WordPress"; c2.ApplicationVersion = "6.8"; c2.Multipart = MultipartBarrier.Accepted; c2.VariantsBlocked = 0; c2.VariantsTotal = 8;
        c2.Technologies = ["Nginx", "jQuery"]; c2.Exposures = ["/.git/HEAD (200)"]; c2.Waf = [new WafFinding(WafCategory.Waf, "Cloudflare", Confidence.High, "cf-ray")]; c2.WafSummary = "WAF: Cloudflare";
        VerdictEngine.Apply(c2);
        Assert.Equal(Verdict.VulnerableByVersion, c1.Verdict);
        Assert.Equal(Verdict.Undetermined, c2.Verdict);

        var m = ResultMerger.Merge(ResultMerger.Merge(null, c1), c2);
        Assert.Same(c1, m);                                     // base: il più informativo (versione dichiarata)
        Assert.Equal("7.4.33", m.PhpVersionRaw);
        Assert.Equal("WordPress", m.Application); Assert.Equal("6.8", m.ApplicationVersion);   // preso dal ciclo 2
        Assert.Equal(MultipartBarrier.Accepted, m.Multipart); Assert.Equal(8, m.VariantsTotal);
        Assert.Equal(["Nginx", "jQuery"], m.Technologies);
        Assert.Equal(["/.git/HEAD (200)"], m.Exposures);
        Assert.Single(m.Waf); Assert.Equal("WAF: Cloudflare", m.WafSummary);
        Assert.Equal(Verdict.VulnerableByVersion, m.Verdict);   // ricalcolato sui campi fusi: la versione resta
        Assert.Contains("multipart accettato", m.VerdictReason);   // ... e la barriera del ciclo 2 entra nella motivazione
        Assert.Equal(2, m.Cycle); Assert.Equal(t0.AddHours(1), m.StartedLocal);   // orario e ciclo dell'ultima osservazione
        Assert.Equal(2, m.History.Count);
        var merge = Assert.Single(m.Tests, t => t.Id == "MERGE");
        Assert.Contains("dal ciclo 2", merge.Detail); Assert.Contains("Application", merge.Detail); Assert.Contains("Multipart", merge.Detail);
    }

    [Fact]
    public void Merge_WithNothingToTake_AddsNoMergeLine()
    {
        var t0 = new DateTime(2026, 10, 24, 10, 0, 0);
        var c1 = R("192.0.2.6", 1, t0); c1.PhpVersionRaw = "8.3.20"; c1.PhpDetected = true; VerdictEngine.Apply(c1);
        var c2 = R("192.0.2.6", 2, t0.AddHours(1)); c2.HttpReachable = false; c2.Alive = AliveState.NoResponse; VerdictEngine.Apply(c2);
        var m = ResultMerger.Merge(ResultMerger.Merge(null, c1), c2);
        Assert.Same(c1, m);
        Assert.DoesNotContain(m.Tests, t => t.Id == "MERGE");
        Assert.Equal(2, m.Cycle);   // orario dell'ultima osservazione anche quando non porta nulla
        Assert.Equal(2, m.History.Count);
        // stesso ciclo (riemissione): la riga di storia viene sostituita
        var c1b = R("192.0.2.6", 2, t0.AddHours(2)); c1b.PhpVersionRaw = "8.3.20"; c1b.PhpDetected = true; VerdictEngine.Apply(c1b);
        m = ResultMerger.Merge(m, c1b, sameCycle: true);
        Assert.Equal(2, m.History.Count);
    }

    // ---------- Certificate Transparency: sottodominio più frequente ----------

    [Fact]
    public void Ct_MostCommonSubdomain()
    {
        Assert.Equal("regione.example.it", CertificateTransparency.MostCommonSubdomain(["www.regione.example.it", "*.regione.example.it", "altro.example.it", "x.altro.example.it", "regione.example.it"], "example.it"));
        Assert.Null(CertificateTransparency.MostCommonSubdomain(["example.it", "www.example.org"], "example.it"));
        Assert.Equal("a.example.org", CertificateTransparency.MostCommonSubdomain(["b.a.example.org"], "example.org"));
    }

    // ---------- report: NCSC breve, elenco per Excel ----------

    private static ScanResult Row(string host, int port, Verdict v, string presence = "no", string? name = null)
    {
        var r = new ScanResult { Input = host, Host = host, IsIpLiteral = true, Port = port, Scheme = "https", HttpReachable = true, Alive = AliveState.Alive, StartedLocal = DateTime.Now, Verdict = v, PhpPresence = presence };
        if (presence == "maybe") { r.PhpHintScore = 2; r.PhpHints = ["2: cookie"]; }
        if (presence == "yes") { r.PhpDetected = true; r.PhpVersionRaw = "7.4.33"; }
        if (name != null) { r.NameRescan = true; r.HostHeader = name; }
        r.Priority = VerdictEngine.Prioritize(r);
        return r;
    }

    private static ScanSession Session(params ScanResult[] rows) => new()
    {
        AppVersion = "1.8", StartLocal = DateTime.Now, EndLocal = DateTime.Now, Status = ScanStatus.Completed, Folder = "", TargetCount = rows.Length, PortCount = 1, Ports = ["443"], Paths = ["/"],
        HostsTotal = rows.Length, HostsAlive = rows.Length, HostsHttp = rows.Length, Results = rows.ToList(), Config = new ScanConfig(),
    };

    [Fact]
    public void NcscShort_AbbreviatesTheLongSentence()
    {
        Assert.Equal("affetto: dipende dalla versione di PHP", CompactReportGenerator.NcscShort("NCSC-NL: prodotto affetto in quanto dipende dalla versione di PHP (nessuna versione del prodotto corregge da sola)"));
        Assert.Equal("–", CompactReportGenerator.NcscShort(""));
        Assert.Equal("corretto in 8.3.36", CompactReportGenerator.NcscShort("NCSC-NL: corretto in 8.3.36"));
    }

    [Fact]
    public void ExcelRows_OneNamePerRow_AndCsv()
    {
        var a = Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "yes");
        a.DiscoveredNames = ["n1.example.org", "n2.example.org", "n3.example.org"]; a.SameOutcomeNames = ["n2.example.org"]; a.Waf = [new WafFinding(WafCategory.Waf, "Cloudflare", Confidence.High, "cf-ray")]; a.InventoryOwner = "Rossi";
        var b = Row("192.0.2.11", 443, Verdict.NoPhpDetected, "maybe");
        var c = Row("192.0.2.12", 443, Verdict.NoPhpDetected);
        var d = Row("192.0.2.13", 443, Verdict.FixedByVersion, "yes");
        var e = Row("192.0.2.10", 443, Verdict.Undetermined, "yes", "shop.example.org");
        var s = Session(a, b, c, d, e);
        var (header, rows) = CompactReportGenerator.ExcelRows(s);
        Assert.Equal(14, header.Count);
        Assert.Equal(3, rows.Count);                                  // a, e (nome), b (forse); c e d esclusi
        var ra = rows.Single(r => r[0] == "192.0.2.10" && r[1] == "n1.example.org");
        Assert.Equal("2", ra[2]);                                     // altri nomi
        Assert.Equal("Vulnerabile per versione", ra[4]); Assert.Equal("sì", ra[6]); Assert.Equal("7.4.33", ra[7]); Assert.Equal("Cloudflare", ra[11]); Assert.Equal("Rossi", ra[12]);
        var re = rows.Single(r => r[1] == "shop.example.org"); Assert.Equal("", re[2]);
        var rb = rows.Single(r => r[0] == "192.0.2.11"); Assert.Equal("forse", rb[6]); Assert.Equal("PHP non rilevato", rb[4]);
        Assert.Equal(0, rows[0].Concat(rows[1]).Concat(rows[2]).Count(cell => cell.Contains('\n')));
        string csv = CompactReportGenerator.ExcelCsv(s, new CsvFormat(CsvDialect.ExcelItalian));
        Assert.StartsWith("IP;Nome;Altri nomi;Porta", csv);
        Assert.Equal(4, csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
        string html = CompactReportGenerator.Build(s, "x.html");
        Assert.Contains("<h2>Elenco per Excel</h2>", html);
        Assert.Equal(3, html.Split("<tr class=\"x\">").Length - 1);
        Assert.Contains("elenco_v1.8.csv", html);
    }

    [Fact]
    public void ExcelRows_CappedInHtml_FullInCsv()
    {
        var rows = Enumerable.Range(0, CompactReportGenerator.MaxExcelRowsInHtml + 20).Select(i => Row($"192.0.{i / 250}.{i % 250}", 443, Verdict.Undetermined, "yes")).ToArray();
        var s = Session(rows);
        string html = CompactReportGenerator.Build(s, "x.html");
        Assert.Equal(CompactReportGenerator.MaxExcelRowsInHtml, html.Split("<tr class=\"x\">").Length - 1);
        Assert.Contains("elenco completo", html);
        Assert.Equal(rows.Length + 1, CompactReportGenerator.ExcelCsv(s, new CsvFormat(CsvDialect.Standard)).Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
    }

    [Fact]
    public void Generate_WritesTheExcelCsvNextToTheReports()
    {
        var s = Session(Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "yes"));
        s.Folder = _dir;
        ReportGenerator.Generate(s);
        string csv = File.ReadAllText(Path.Combine(_dir, "elenco_v1.8.csv"));
        Assert.Contains("192.0.2.10", csv);
    }
}
