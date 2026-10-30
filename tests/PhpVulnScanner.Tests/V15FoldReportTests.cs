using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Tests;

/// <summary>v1.5: nomi con lo stesso esito (seconda riga di ripiegamento), results.jsonl completo, CSV, report compatto con tutti i nomi, PHP sospetto, loquacità, 115560.</summary>
public class V15FoldReportTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v15_" + Guid.NewGuid().ToString("N"));
    public V15FoldReportTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string targets = "127.0.0.1") => new()
    {
        TargetsText = targets, PortsText = srv.Port.ToString(), PathsText = "/ /index.php", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 4, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [srv.Port], UdpPorts = [], TimeoutMs = 1000, SkipIfNotAlive = true },
        Level1InfoPages = false, Level1EasterEgg = false, Level2 = false, WafDetect = false, WafBehaviour = false, SizeProbeKiB = 16,
        SurfaceDiscovery = false, DiscoverNames = true, RescanDiscoveredNames = true, FoldSameContentNames = true, FoldSameOutcomeNames = true,
        Advanced = new AdvancedOptions().Also(o => o.SetAll(false)),
    };

    /// <summary>Server con vhost per nome: la riga per IP risponde 302 verso il nome (contenuto diverso), il nome risponde 200 con lo stesso banner PHP.</summary>
    private static FakePhpServer SameOutcomeServer(string? vhostPhp = null) => new(anyHost: true)
    {
        PoweredBy = "PHP/7.4.33", RedirectRootTo = "https://site.example.org/", VhostName = "site.example.org", VhostPoweredBy = vhostPhp ?? "PHP/7.4.33",
        VhostBody = "<html><body>a completely different site body</body></html>",
    };

    // ---------- ripiegamento per esito ----------

    [Fact]
    public async Task SameOutcomeName_IsFoldedOnIpRow_AndObservationStaysInJsonl()
    {
        using var srv = SameOutcomeServer();
        var s = await new ScanEngine().RunAsync(Cfg(srv), CancellationToken.None);
        var ip = Assert.Single(s.Results);
        Assert.False(ip.NameRescan);
        Assert.Equal(["site.example.org"], ip.SameOutcomeNames);
        Assert.Empty(ip.SameContentNames);
        Assert.Contains(ip.Tests, t => t.Id == "NAME-OUTCOME" && t.Detail.Contains("site.example.org"));
        // l'osservazione completa resta in results.jsonl, anche se non è una riga
        var obs = SessionFiles.ReadJsonl(Path.Combine(s.Folder, SessionFiles.ResultsJsonl));
        var folded = Assert.Single(obs, o => o.NameRescan);
        Assert.Equal("site.example.org", folded.HostHeader);
        Assert.True(folded.HttpReachable);
        Assert.Equal(ip.Verdict, folded.Verdict);
        Assert.Equal(2, obs.Count);
        // results.json e CSV hanno una sola riga, con il nome nella colonna same_outcome_names
        var saved = SessionFiles.ReadSession(s.Folder)!;
        Assert.Single(saved.Results);
        string csv = File.ReadAllText(Path.Combine(s.Folder, SessionFiles.ResultsCsv));
        Assert.Contains("site.example.org", csv);
        Assert.Contains("same_outcome_names", csv);
        // il nome arriva nel file dei nomi scoperti
        Assert.Contains("site.example.org", File.ReadAllText(Path.Combine(s.Folder, HostLists.NamesFileName(s.AppVersion))));
    }

    [Fact]
    public async Task DifferentPhpVersionName_KeepsItsRow()
    {
        using var srv = SameOutcomeServer("PHP/8.3.36");
        var s = await new ScanEngine().RunAsync(Cfg(srv), CancellationToken.None);
        Assert.Equal(2, s.Results.Count);
        var named = s.Results.Single(r => r.NameRescan);
        Assert.Equal("8.3.36", named.PhpVersionRaw);
        Assert.Empty(s.Results.Single(r => !r.NameRescan).SameOutcomeNames);
    }

    [Fact]
    public async Task FoldSameOutcomeOff_KeepsSeparateRows()
    {
        using var srv = SameOutcomeServer();
        var cfg = Cfg(srv); cfg.FoldSameOutcomeNames = false;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(2, s.Results.Count);
        Assert.Contains(s.Results, r => r.NameRescan && r.HostHeader == "site.example.org");
        Assert.All(s.Results, r => Assert.Empty(r.SameOutcomeNames));
    }

    [Fact]
    public async Task SameContentName_ObservationAlsoStaysInJsonl()
    {
        // il nome risponde identico al vhost predefinito: ripiegato come in v1.4, ma ora l'osservazione è in results.jsonl
        using var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/8.3.20", HomeBody = "<html><body>same</body></html>", VhostName = "www.example.org", VhostBody = "<html><body>same</body></html>" };
        srv.ExtraHeaders.Add(new("Location", "https://www.example.org/"));   // Location su una 200: il nome viene raccolto, il contenuto resta identico
        var cfg = Cfg(srv);
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var ip = Assert.Single(s.Results);
        Assert.Contains("www.example.org", ip.DiscoveredNames);
        Assert.Contains("www.example.org", ip.SameContentNames);
        Assert.Empty(ip.SameOutcomeNames);
        var obs = SessionFiles.ReadJsonl(Path.Combine(s.Folder, SessionFiles.ResultsJsonl));
        Assert.Contains(obs, o => o.NameRescan && o.HostHeader == "www.example.org");
    }

    [Fact]
    public void OutcomeKey_AndSameOutcome_CompareOnlyOutcomeFields()
    {
        var a = new ScanResult { Host = "192.0.2.1", Port = 443, HttpReachable = true, Verdict = Verdict.Undetermined, Sapi = "fpm", WafSummary = "WAF: Cloudflare", Priority = Priority.Medium, PhpPresence = "yes" };
        var b = new ScanResult { Host = "192.0.2.1", Port = 443, HttpReachable = true, Verdict = Verdict.Undetermined, Sapi = "fpm", WafSummary = "WAF: Cloudflare", Priority = Priority.Medium, PhpPresence = "yes", NameRescan = true, HostHeader = "www.example.org", ServerHeader = "nginx" };
        b.Requests.Add(new HttpSnapshot { Method = "GET", Url = "https://www.example.org/", Status = 200, Body = "different" });
        Assert.Equal(ScanEngine.OutcomeKey(a), ScanEngine.OutcomeKey(b));
        Assert.True(ScanEngine.SameOutcome(a, b));
        b.Application = "WordPress";
        Assert.False(ScanEngine.SameOutcome(a, b));
        b.Application = ""; b.FastCgiExposed = true;
        Assert.False(ScanEngine.SameOutcome(a, b));
        b.FastCgiExposed = null; b.PhpPresence = "maybe";
        Assert.False(ScanEngine.SameOutcome(a, b));
        b.PhpPresence = "yes"; b.HttpReachable = false;
        Assert.False(ScanEngine.SameOutcome(a, b));
    }

    [Fact]
    public void ReadSession_RunningSession_DoesNotPromoteFoldedObservationsToRows()
    {
        var folder = Path.Combine(_dir, "running"); Directory.CreateDirectory(folder);
        var ip = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, HttpReachable = true, Verdict = Verdict.Undetermined, SameOutcomeNames = ["www.example.org"], SameContentNames = ["example.org"] };
        var n1 = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, HttpReachable = true, Verdict = Verdict.Undetermined, NameRescan = true, HostHeader = "www.example.org" };
        var n2 = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, HttpReachable = true, Verdict = Verdict.Undetermined, NameRescan = true, HostHeader = "example.org" };
        var kept = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, HttpReachable = true, Verdict = Verdict.FixedByVersion, NameRescan = true, HostHeader = "shop.example.org" };
        var session = new ScanSession { Folder = folder, Status = ScanStatus.Running, StartLocal = DateTime.Now };
        using (var w = new SessionWriter(session))
        {
            w.Upsert(ip); w.Observe(n1); w.Observe(n2); w.Upsert(kept);
        }
        var read = SessionFiles.ReadSession(folder)!;
        Assert.Equal(2, read.Results.Count);
        Assert.Contains(read.Results, r => !r.NameRescan);
        Assert.Contains(read.Results, r => r.NameRescan && r.HostHeader == "shop.example.org");
        Assert.Equal(4, SessionFiles.ReadJsonl(Path.Combine(folder, SessionFiles.ResultsJsonl)).Count);
    }

    // ---------- CLI, CSV, file degli host ----------

    [Fact]
    public void Cli_ParsesNoFoldOutcome_AndKeepsNoFoldNames()
    {
        var cfg = CliRunner.Parse(["--scan", "192.0.2.1", "--no-fold-outcome"], _dir, out var err, out _, out _);
        Assert.Null(err); Assert.NotNull(cfg);
        Assert.False(cfg!.FoldSameOutcomeNames); Assert.True(cfg.FoldSameContentNames);
        cfg = CliRunner.Parse(["--scan", "192.0.2.1", "--no-fold-names"], _dir, out err, out _, out _);
        Assert.Null(err); Assert.True(cfg!.FoldSameOutcomeNames); Assert.False(cfg.FoldSameContentNames);
        Assert.Contains("--no-fold-outcome", CliRunner.Usage());
    }

    [Fact]
    public void Csv_HasV15Columns_AndRowsMatchHeader()
    {
        var r = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, HttpReachable = true, Verdict = Verdict.NoPhpDetected, PhpPresence = "maybe", PhpHintScore = 3, PhpHints = ["2: cookie wordpress_test_cookie", "1: percorso /wp-login.php"], IniHints = ["session.upload_progress.enabled=On", "session.serialize_handler=php"], VerbosityScore = 2, VerbosityItems = ["1: versione nel banner Server", "1: directory listing"], SameOutcomeNames = ["www.example.org", "shop.example.org"] };
        var csv = new CsvFormat(CsvDialect.Standard);
        string text = SessionFiles.ResultsToCsv([r], csv);
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(2, lines.Length);
        foreach (var col in new[] { "same_outcome_names", "php_presence", "php_hints", "php_hint_score", "ini_hints", "verbosity_score", "verbosity_items" }) Assert.Contains(col, SessionFiles.ResultColumns);
        Assert.Equal(SessionFiles.ResultColumns.Length, CountFields(lines[0]));
        Assert.Equal(SessionFiles.ResultColumns.Length, CountFields(lines[1]));
        Assert.Contains("www.example.org; shop.example.org", lines[1]);
        Assert.Contains("session.upload_progress.enabled=On; session.serialize_handler=php", lines[1]);
        Assert.Contains("maybe", lines[1]);
        Assert.Contains("\"0001-01-01 00:00:00,000\"", lines[1]);   // la virgola dei millisecondi non deve spezzare la colonna started nel dialetto standard
    }

    /// <summary>Campi di una riga CSV standard (virgola, campi tra virgolette con virgole interne).</summary>
    private static int CountFields(string line)
    {
        int n = 1; bool q = false;
        foreach (char c in line.TrimEnd('\r')) { if (c == '"') q = !q; else if (c == ',' && !q) n++; }
        return n;
    }

    [Fact]
    public void HostLists_NamesIncludeSameOutcomeNames()
    {
        var r = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, HttpReachable = true, DiscoveredNames = ["www.example.org"], SameContentNames = ["example.org"], SameOutcomeNames = ["shop.example.org", "*.example.org"] };
        var names = HostLists.Names([r]);
        Assert.Equal(["example.org", "shop.example.org", "www.example.org"], names);
        Assert.Contains("shop.example.org\n", HostLists.DiscoveredNamesText([r]));
    }

    // ---------- report ----------

    private static ScanResult Row(string host, int port, Verdict v, string php = "", string name = "")
    {
        var r = new ScanResult
        {
            Input = host, Host = host, IsIpLiteral = true, Port = port, Scheme = "https", HostHeader = name.Length > 0 ? name : host, NameRescan = name.Length > 0,
            Alive = AliveState.Alive, AliveMethod = "TCP 443", HttpReachable = true, StartedLocal = new DateTime(2026, 10, 24, 9, 0, 0), DurationMs = 100,
            PhpVersionRaw = php, PhpDetected = v is not (Verdict.NoPhpDetected or Verdict.NotReachable), Verdict = v, ServerHeader = "nginx", VerdictReason = "motivo sintetico",
        };
        if (php.Length > 0) { r.VersionStatus = VersionStatus.VulnerableSupported; r.PhpVersionSource = "X-Powered-By"; r.PhpPresence = "yes"; }
        r.Priority = VerdictEngine.Prioritize(r);
        return r;
    }

    private static ScanSession Session(List<ScanResult> rows) => new()
    {
        AppVersion = "1.5", StartLocal = new DateTime(2026, 10, 24, 9, 0, 0), EndLocal = new DateTime(2026, 10, 24, 9, 10, 0), Status = ScanStatus.Completed, Folder = "",
        TargetCount = rows.Select(r => r.Host).Distinct().Count(), PortCount = 1, Ports = ["443"], Paths = ["/"], TargetsSummary = "192.0.2.0/24", DataVersion = "test",
        HostsTotal = rows.Select(r => r.Host).Distinct().Count(), HostsAlive = rows.Select(r => r.Host).Distinct().Count(), HostsHttp = rows.Select(r => r.Host).Distinct().Count(),
        Results = rows.OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList(),
    };

    private static List<ScanResult> V15Rows()
    {
        var a = Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "8.3.20");
        a.DiscoveredNames = ["n01.example.org", "n02.example.org", "n03.example.org", "n04.example.org", "n05.example.org", "n06.example.org", "n07.example.org", "n08.example.org"];
        a.SameContentNames = ["example.org"]; a.SameOutcomeNames = ["shop.example.org", "n09.example.org"];
        a.Exposures = ["/.git/HEAD (200): repository esposto"];
        a.VerbosityScore = 4; a.VerbosityItems = ["2: phpinfo esposto", "1: versione nel banner Server", "1: nomi interni nel certificato"];
        var b = Row("192.0.2.11", 443, Verdict.NoPhpDetected);
        b.PhpPresence = "maybe"; b.PhpHintScore = 3; b.PhpHints = ["2: cookie wordpress_test_cookie", "1: percorso /wp-login.php"]; b.WafSummary = "WAF: Cloudflare";
        b.Waf = [new WafFinding(WafCategory.Waf, "Cloudflare", Confidence.High, "cf-ray")];
        b.VerbosityScore = 1; b.VerbosityItems = ["1: versione nel banner Server"];
        var c = Row("192.0.2.12", 443, Verdict.NoPhpDetected);   // niente indizi, muto
        return [a, b, c];
    }

    [Fact]
    public void CompactReport_ListsEveryName_AndHasSuspectAndVerbositySections()
    {
        var s = Session(V15Rows());
        string html = CompactReportGenerator.Build(s, "report_completo_v1.5.html");
        // tutti i nomi, mai "+N": nella tabella "Da tenere in considerazione" e in "Host attivi"
        int att = html.IndexOf("Da tenere in considerazione", StringComparison.Ordinal), exp = html.IndexOf("Esposizioni</h3>", StringComparison.Ordinal);
        string attention = html[att..exp];
        foreach (var n in new[] { "n01.example.org", "n08.example.org", "n09.example.org", "shop.example.org", "example.org" }) Assert.Contains(n, attention);
        int hosts = html.IndexOf("<h2>Host attivi</h2>", StringComparison.Ordinal), sus = html.IndexOf("<h2>PHP sospetto</h2>", StringComparison.Ordinal);
        Assert.True(sus > 0 && hosts > sus);   // v1.7: "PHP sospetto" sta prima degli host attivi
        int loq = html.IndexOf("<h2>Loquacit", StringComparison.Ordinal);
        string hostTable = html[hosts..loq];
        Assert.Contains("n08.example.org", hostTable); Assert.Contains("n09.example.org", hostTable); Assert.Contains("shop.example.org", hostTable);
        Assert.DoesNotContain("+5", hostTable); Assert.DoesNotContain("+6", hostTable);
        // PHP sospetto: solo b, con punteggio e indizi
        Assert.True(loq > hosts);
        string suspect = html[sus..hosts];
        Assert.Contains("192.0.2.11", suspect); Assert.DoesNotContain("192.0.2.12", suspect); Assert.DoesNotContain("192.0.2.10", suspect);
        Assert.Contains("wordpress_test_cookie", suspect); Assert.Contains("WAF: Cloudflare", suspect);
        Assert.Contains("prima di escluderli", suspect);
        // loquacità: a (4/5) prima di b (1/5), c assente
        string talk = html[loq..];
        Assert.Contains("4/5", talk); Assert.Contains("1/5", talk); Assert.Contains("phpinfo esposto", talk);
        Assert.True(talk.IndexOf("192.0.2.10", StringComparison.Ordinal) < talk.IndexOf("192.0.2.11", StringComparison.Ordinal));
        Assert.DoesNotContain("192.0.2.12", talk[..talk.IndexOf("<footer>", StringComparison.Ordinal)]);
        // riepilogo
        Assert.Contains("PHP sospetto", html[..att]);
        Assert.Contains("1 servizi su 1 host", html[..att]);
        Assert.Contains("(di cui 1 con indizi)", html[..att]);
    }

    [Fact]
    public void CompactReport_WithoutSuspectsOrVerbosity_SectionsStayEmptyAndSmall()
    {
        var rows = new List<ScanResult> { Row("192.0.2.10", 443, Verdict.FixedByVersion, "8.3.36"), Row("192.0.2.11", 443, Verdict.NoPhpDetected) };
        string html = CompactReportGenerator.Build(Session(rows), "");
        Assert.Contains("<h2>PHP sospetto</h2>", html);
        Assert.Contains("<h2>Loquacit", html);
        Assert.DoesNotContain("<table class=\"sus\">", html);
        Assert.DoesNotContain("<table class=\"loq\">", html);
        Assert.DoesNotContain("di cui", html);
    }

    [Fact]
    public void FullReport_Has115560Paragraph_SheetFields_AndHintedCounter()
    {
        var s = Session(V15Rows());
        s.Results[0].IniHints = ["session.upload_progress.enabled=On", "session.serialize_handler=php_serialize"];
        string html = ReportGenerator.Build(s);
        Assert.Contains("CVE-2026-115560", html);
        Assert.Contains("session.upload_progress.enabled e session.serialize_handler", html);
        Assert.Contains("php-fpm -i", html);
        Assert.Contains("Indice di loquacit", html);
        Assert.Contains("session.serialize_handler=php_serialize", html);
        Assert.Contains("wordpress_test_cookie", html);
        Assert.Contains("4/5", html);
        Assert.Contains("Nomi con lo stesso esito", html);
        Assert.Contains("shop.example.org", html);
        Assert.Contains("(= stesso esito)", html);
        Assert.Contains("(di cui 1 con indizi)", html);
        Assert.Contains(">forse<", html);
    }
}
