using System.Text.Json;
using PhpVulnScanner.Core;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Tests;

/// <summary>v1.4: report compatto, vista per ciclo, elenchi degli host, fusione di sessioni. Sessioni sintetiche (RFC 5737, example.org).</summary>
public class ReportsAndMergeTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v14_" + Guid.NewGuid().ToString("N"));
    public ReportsAndMergeTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private static readonly DateTime T0 = new(2026, 10, 23, 22, 47, 0);

    // ---------- fabbrica di risultati sintetici ----------

    private static ScanResult Row(string host, int port, Verdict v, string php = "", bool http = true, AliveState alive = AliveState.Alive, int cycle = 1, string app = "", string appVer = "", DateTime? started = null, string name = "")
    {
        var r = new ScanResult
        {
            Input = host, Host = host, IsIpLiteral = true, Port = port, Scheme = port == 80 ? "http" : "https", HostHeader = name.Length > 0 ? name : host, NameRescan = name.Length > 0,
            Alive = alive, AliveMethod = alive == AliveState.Alive ? "TCP 443" : "", HttpReachable = http, Cycle = cycle, StartedLocal = started ?? T0.AddSeconds(port), DurationMs = 120,
            PhpVersionRaw = php, PhpDetected = http && v is not (Verdict.NoPhpDetected or Verdict.NotReachable), Application = app, ApplicationVersion = appVer,
            Verdict = v, ServerHeader = http ? "nginx" : "",
        };
        if (php.Length > 0) { r.VersionStatus = v == Verdict.FixedByVersion ? VersionStatus.Fixed : v == Verdict.LikelyVulnerable ? VersionStatus.EndOfLife : VersionStatus.VulnerableSupported; r.PhpVersionSource = "X-Powered-By"; }
        r.Priority = VerdictEngine.Prioritize(r);
        r.VerdictReason = v == Verdict.NotReachable ? "nessuna risposta HTTP" : "motivo sintetico; dettaglio barriera";
        return r;
    }

    private static ScanSession Session(List<ScanResult> rows, int cycles = 1, bool consolidated = false)
    {
        var s = new ScanSession
        {
            AppVersion = "1.4", StartLocal = T0, EndLocal = T0.AddMinutes(10), Status = ScanStatus.Completed, Folder = "", TargetCount = rows.Select(r => r.Host).Distinct().Count(), PortCount = 2,
            Ports = ["80", "443"], Paths = ["/"], TargetsSummary = "192.0.2.0/24, 198.51.100.0/24", Cycle = cycles, Cycles = cycles, Consolidated = consolidated, DataVersion = "test",
            HostsTotal = rows.Select(r => r.Host).Distinct().Count(),
            HostsAlive = rows.Where(HostLists.IsAlive).Select(r => r.Host).Distinct().Count(),
            HostsHttp = rows.Where(r => r.HttpReachable).Select(r => r.Host).Distinct().Count(),
            Results = rows.OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList(),
        };
        return s;
    }

    private static List<ScanResult> SmallRows()
    {
        var a443 = Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "8.3.20", app: "WordPress", appVer: "6.5");
        a443.Sapi = "mod_php"; a443.Multipart = MultipartBarrier.Accepted; a443.VariantsBlocked = 0; a443.VariantsTotal = 8;
        a443.DiscoveredNames = ["www.example.org", "shop.example.org"]; a443.SameContentNames = ["example.org"];
        a443.Exposures = ["/.git/HEAD (200): repository esposto"];
        var a80 = Row("192.0.2.10", 80, Verdict.FixedByVersion, "8.3.36");
        var b = Row("192.0.2.11", 443, Verdict.Undetermined); b.PhpVersionSource = "phpinfo /info.php"; b.PhpVersionRaw = ""; b.PhpDetected = true;
        b.Waf = [new WafFinding(WafCategory.Waf, "Cloudflare", Confidence.High, "cf-ray")]; b.WafSummary = "WAF: Cloudflare";
        var c = Row("192.0.2.12", 443, Verdict.NoPhpDetected);
        c.Requests.Add(new HttpSnapshot { Method = "GET", Url = "https://192.0.2.12/", Status = 200, Body = "<html><head><title>Index of /</title></head>" });
        var d = Row("198.51.100.7", 443, Verdict.NotReachable, http: false, alive: AliveState.NoResponse);
        var e = Row("198.51.100.8", 443, Verdict.NotReachable, http: false, alive: AliveState.Alive);   // attivo ma senza HTTP
        var n = Row("192.0.2.10", 443, Verdict.LikelyVulnerable, "7.4.33", name: "www.example.org");  // seconda passata sul nome
        return [a443, a80, b, c, d, e, n];
    }

    // ---------- report compatto ----------

    [Fact]
    public void CompactReport_DoubleCounts_ExcludesUnreachable_HasExposuresAndHosts()
    {
        var s = Session(SmallRows());
        string html = CompactReportGenerator.Build(s, "report_completo_v1.4.html");

        Assert.Contains("1 servizi su 1 host", html);                 // vulnerabile per versione: a443
        Assert.Contains("2 servizi su 2 host", html);                 // non raggiungibili: d, e
        Assert.Contains("Host attivi 4 su 5, 3 con HTTP", html);
        Assert.DoesNotContain("198.51.100.7", html);                  // riga non raggiungibile e non attiva: assente
        Assert.Contains("198.51.100.8", html);                        // attivo senza HTTP: solo nella tabella host
        Assert.Contains("Da tenere in considerazione", html);
        Assert.Contains("Esposizioni", html);
        Assert.Contains(".git/HEAD", html);
        Assert.Contains("phpinfo", html);
        Assert.Contains("directory listing", html);
        Assert.Contains("Applicazioni riconosciute", html);
        Assert.Contains("WordPress", html);
        Assert.Contains("shop.example.org", html);                    // nomi dell'host
        Assert.Contains("report_completo_v1.4.html", html);
        Assert.DoesNotContain("cf-ray", html);                        // nessuna evidenza grezza
        Assert.DoesNotContain("<pre>", html);
        // "Da tenere in considerazione" non contiene i corretti né i PHP non rilevati
        int from = html.IndexOf("Da tenere in considerazione", StringComparison.Ordinal), to = html.IndexOf("Esposizioni</h3>", StringComparison.Ordinal);
        string attention = html[from..to];
        Assert.DoesNotContain("8.3.36", attention);
        Assert.Contains("8.3.20", attention);
        Assert.Contains("7.4.33", attention);
        // ordinamento per priorità: la critica (mod_php, multipart accettato) viene prima
        Assert.True(attention.IndexOf("192.0.2.10", StringComparison.Ordinal) < attention.IndexOf("192.0.2.11", StringComparison.Ordinal));
    }

    [Fact]
    public void CompactReport_WorstVerdictPerHost_AndCorrelation()
    {
        var rows = new List<ScanResult>();
        for (int i = 1; i <= 10; i++)
        {
            var r = Row($"203.0.113.{i}", 443, i == 1 ? Verdict.VulnerableByVersion : Verdict.Undetermined, i == 1 ? "8.2.30" : "");
            r.ServerHeader = i % 3 == 0 ? "Apache" : i % 3 == 1 ? "nginx" : "IIS";
            r.Waf = [new WafFinding(WafCategory.Waf, "FortiWeb", Confidence.Medium, "block page")];
            rows.Add(r);
            rows.Add(Row($"203.0.113.{i}", 80, Verdict.NoPhpDetected));
        }
        string html = CompactReportGenerator.Build(Session(rows), "");
        Assert.Contains("FortiWeb", html);
        Assert.Contains("Correlazione", html);
        Assert.Equal(Verdict.VulnerableByVersion, CompactReportGenerator.Worst([Verdict.NoPhpDetected, Verdict.VulnerableByVersion, Verdict.Undetermined]));
        Assert.Equal(Verdict.Undetermined, CompactReportGenerator.Worst([Verdict.FixedByVersion, Verdict.Undetermined, Verdict.NotReachable]));
        // tabella host: 10 righe, una per IP
        int hostsSection = html.IndexOf("<h2>Host attivi</h2>", StringComparison.Ordinal);
        Assert.True(hostsSection > 0);
        Assert.Equal(10, html[hostsSection..].Split("<tr><td>203.0.113.").Length - 1);
    }

    [Fact]
    public void CompactReport_StaysSmall_On20kRows()
    {
        var rows = new List<ScanResult>(20_000);
        var nets = new[] { "192.0.2.", "198.51.100.", "203.0.113." };
        int reachable = 0;
        for (int n = 0; n < 3; n++)
            for (int h = 0; h < 256; h++)
            {
                string ip = nets[n] + h;
                bool live = (h % 2 == 0) && reachable < 700;   // 350 host × 2 porte = 700 righe raggiungibili
                for (int p = 0; p < 26; p++)
                {
                    int port = p == 0 ? 80 : p == 1 ? 443 : 8000 + p;
                    if (live && p < 2)
                    {
                        var v = reachable % 4 == 0 ? Verdict.VulnerableByVersion : reachable % 4 == 1 ? Verdict.Undetermined : reachable % 4 == 2 ? Verdict.FixedByVersion : Verdict.MitigatedAtEdge;
                        var r = Row(ip, port, v, v == Verdict.Undetermined ? "" : v == Verdict.FixedByVersion ? "8.3.36" : "8.3.20", app: reachable % 5 == 0 ? "WordPress" : "", appVer: reachable % 5 == 0 ? "6.5" : "");
                        r.VerdictReason = "versione dichiarata 8.3.20 precedente alla correzione 8.3.36 (fonte: X-Powered-By); multipart accettato: il vettore raggiunge PHP";
                        r.WafSummary = "WAF: Cloudflare"; r.Sapi = "fpm"; r.Multipart = MultipartBarrier.Accepted; r.VariantsBlocked = 0; r.VariantsTotal = 8;
                        r.DiscoveredNames = [$"h{h}.example.org", $"www{h}.example.org"];
                        r.PhpSurface = ["/index.php (200)", "/wp-login.php (200)"];
                        rows.Add(r); reachable++;
                    }
                    else rows.Add(Row(ip, port, Verdict.NotReachable, http: false, alive: live ? AliveState.Alive : AliveState.NoResponse));
                }
            }
        Assert.Equal(19_968, rows.Count);
        Assert.Equal(700, rows.Count(r => r.HttpReachable));
        var s = Session(rows);
        string html = CompactReportGenerator.Build(s, "report_completo_v1.4.html");
        Assert.True(html.Length < 300 * 1024, $"report compatto di {html.Length / 1024} KB");
        Assert.Contains("19968 servizi (righe bersaglio/porta/nome) su 768 host distinti", html);
        Assert.Contains("Host attivi 350 su 768, 350 con HTTP", html);
    }

    // ---------- vista per ciclo ----------

    [Fact]
    public void SplitByCycle_CountsAndPerCycleSection()
    {
        var c1 = new List<ScanResult>
        {
            Row("192.0.2.10", 443, Verdict.NotReachable, http: false, alive: AliveState.NoResponse, cycle: 1, started: T0),
            Row("192.0.2.11", 443, Verdict.Undetermined, cycle: 1, started: T0.AddSeconds(5)),
        };
        var c2 = new List<ScanResult>
        {
            Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "8.3.20", cycle: 2, started: T0.AddMinutes(30)),
            Row("192.0.2.11", 443, Verdict.Undetermined, cycle: 2, started: T0.AddMinutes(30).AddSeconds(5)),
        };
        var consolidated = Session([.. c2], cycles: 2, consolidated: true);
        var cycles = CycleReports.SplitByCycle(consolidated, c1.Concat(c2));
        Assert.Equal(2, cycles.Count);
        Assert.Equal(1, cycles[0].Cycle);
        Assert.Equal(2, cycles[0].Session.Results.Count);
        Assert.Equal(1, cycles[0].Session.HostsAlive);
        Assert.Equal(1, cycles[0].Session.HostsHttp);
        Assert.Equal(2, cycles[1].Session.HostsHttp);
        Assert.False(cycles[0].Session.Consolidated);
        Assert.Equal(T0, cycles[0].Session.StartLocal);
        Assert.Equal(T0.AddMinutes(30), cycles[1].Session.StartLocal);
        Assert.True(cycles[1].Session.EndLocal > cycles[1].Session.StartLocal);

        string html = CycleReports.BuildPerCycleSection(consolidated, cycles);
        Assert.Contains("Per ciclo", html);
        Assert.Contains("Servizi con HTTP in almeno un ciclo: 2", html);
        Assert.Equal(2, html.Split("<details class=\"card\">").Length - 1);
        Assert.Contains("Δ", html);                                   // 192.0.2.10 cambia verdetto
        Assert.Contains("8.3.20", html);
        Assert.DoesNotContain("<html", html);
    }

    // ---------- elenchi host ----------

    [Fact]
    public void HostLists_OrderDedupeAndFiles()
    {
        var rows = new List<ScanResult>
        {
            Row("198.51.100.20", 443, Verdict.Undetermined),
            Row("192.0.2.9", 443, Verdict.NotReachable, http: false, alive: AliveState.Alive),
            Row("192.0.2.9", 80, Verdict.NotReachable, http: false, alive: AliveState.Alive, cycle: 2),     // seconda osservazione: deduplicata
            Row("192.0.2.100", 443, Verdict.NotReachable, http: false, alive: AliveState.NoResponse),
            Row("192.0.2.10", 443, Verdict.NoPhpDetected, alive: AliveState.NotTested),                    // alive non verificato ma HTTP: attivo
        };
        rows[0].DiscoveredNames = ["*.example.org", "www.example.org", "Mail.Example.org", "bad host", "www.example.org"];
        rows[4].SameContentNames = ["api.example.org"];
        rows[4].Tls = new TlsInfo { Handshake = true };

        Assert.Equal("192.0.2.9\n192.0.2.10\n198.51.100.20\n", HostLists.AliveHostsText(rows));
        Assert.Equal("192.0.2.10\n198.51.100.20\n", HostLists.HttpHostsText(rows));
        Assert.Equal("api.example.org\nmail.example.org\nwww.example.org\n", HostLists.DiscoveredNamesText(rows));

        HostLists.Write(_dir, "1.4", rows);
        Assert.Equal("192.0.2.9\n192.0.2.10\n198.51.100.20\n", File.ReadAllText(Path.Combine(_dir, "host_attivi_v1.4.txt")));
        Assert.True(File.Exists(Path.Combine(_dir, "host_http_v1.4.txt")));
        Assert.True(File.Exists(Path.Combine(_dir, "nomi_scoperti_v1.4.txt")));
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
        // riscrittura con più righe: il file viene sostituito, non accodato
        rows.Add(Row("192.0.2.1", 443, Verdict.Undetermined));
        HostLists.Write(_dir, "1.4", rows);
        Assert.Equal("192.0.2.1\n192.0.2.9\n192.0.2.10\n198.51.100.20\n", File.ReadAllText(Path.Combine(_dir, "host_attivi_v1.4.txt")));
    }

    // ---------- fusione di sessioni ----------

    private string WriteSessionFolder(string name, ScanSession s, List<ScanResult> observations, bool jsonl = true)
    {
        string folder = Path.Combine(_dir, name);
        Directory.CreateDirectory(folder);
        s.Folder = folder;
        if (jsonl)
        {
            var header = JsonSerializer.Deserialize<ScanSession>(JsonSerializer.Serialize(s, ScanConfig.JsonOptions), ScanConfig.JsonOptions)!;
            header.Results = [];
            File.WriteAllText(Path.Combine(folder, SessionFiles.SessionJson), JsonSerializer.Serialize(header, ScanConfig.JsonOptions));
            File.WriteAllLines(Path.Combine(folder, SessionFiles.ResultsJsonl), observations.Select(r => JsonSerializer.Serialize(r, SessionFiles.JsonlOptions)));
        }
        else
        {
            File.WriteAllText(Path.Combine(folder, SessionFiles.ResultsJson), SessionFiles.ResultsToJson(s));
        }
        return folder;
    }

    [Fact]
    public void SessionMerger_Load_Analyse_Merge_Differences()
    {
        // sessione A (v1.2, 23/10 22:47): .10 non raggiungibile, .11 non determinabile, .12 PHP non rilevato
        var aRows = new List<ScanResult>
        {
            Row("192.0.2.10", 443, Verdict.NotReachable, http: false, alive: AliveState.NoResponse, started: T0),
            Row("192.0.2.11", 443, Verdict.Undetermined, started: T0.AddSeconds(1)),
            Row("192.0.2.12", 443, Verdict.NoPhpDetected, started: T0.AddSeconds(2)),
        };
        aRows[1].DiscoveredNames = ["old.example.org"];
        var a = Session(aRows); a.AppVersion = "1.2"; a.TargetsSummary = "192.0.2.10-12";
        string fa = WriteSessionFolder("A", a, aRows, jsonl: false);

        // sessione B (v1.4, un giorno dopo): .10 vulnerabile con versione, .11 corretto, .13 nuovo host attivo
        var t1 = T0.AddDays(1);
        var bRows = new List<ScanResult>
        {
            Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "8.3.20", started: t1, app: "WordPress", appVer: "6.5"),
            Row("192.0.2.11", 443, Verdict.FixedByVersion, "8.3.36", started: t1.AddSeconds(1), app: "WordPress", appVer: "6.5"),
            Row("192.0.2.13", 443, Verdict.Undetermined, started: t1.AddSeconds(2)),
        };
        bRows[0].DiscoveredNames = ["www.example.org"];
        var b = Session(bRows); b.AppVersion = "1.4"; b.StartLocal = t1; b.EndLocal = t1.AddMinutes(5); b.TargetsSummary = "192.0.2.10-13";
        string fb = WriteSessionFolder("B", b, bRows, jsonl: true);

        var inA = SessionMerger.Load(fa);
        var inB = SessionMerger.Load(fb);
        Assert.Equal("1.2", inA.Session.AppVersion);
        Assert.Equal(3, inA.Observations.Count);
        Assert.Equal(3, inB.Observations.Count);
        Assert.Equal("2026-10-23 22:47 v1.2", inA.Label);
        Assert.Equal("2026-10-24 22:47 v1.4", inB.Label);

        var report = SessionMerger.Analyse([inB, inA]);
        Assert.Equal(4, report.Union.Count);
        Assert.Equal(2, report.Intersection.Count);
        Assert.Equal(["192.0.2.12"], report.OnlyIn[inA.Label]);
        Assert.Equal(["192.0.2.13"], report.OnlyIn[inB.Label]);
        Assert.Equal(inA.Label, report.Labels[0]);   // ordine cronologico anche se passate al contrario

        string outFolder = Path.Combine(_dir, "merged");
        var merged = SessionMerger.Merge([inB, inA], outFolder);
        Assert.Equal(outFolder, merged.Folder);
        Assert.True(merged.Consolidated);
        Assert.Equal(2, merged.Cycles);
        Assert.Equal(ScanStatus.Completed, merged.Status);
        Assert.Equal(4, merged.Results.Count);
        Assert.Equal(4, merged.HostsTotal);
        Assert.Equal(4, merged.HostsAlive);
        Assert.Equal(4, merged.HostsHttp);
        Assert.Equal("192.0.2.10-12, 192.0.2.10-13", merged.TargetsSummary);
        Assert.Equal(T0, merged.StartLocal);
        var r10 = merged.Results.Single(r => r.Host == "192.0.2.10");
        Assert.Equal(Verdict.VulnerableByVersion, r10.Verdict);           // il più informativo vince
        Assert.Equal(2, r10.History.Count);
        Assert.Equal("23/10 22.47 v1.2: Non raggiungibile (Nessuna risposta)", r10.History[0]);
        Assert.StartsWith("24/10 22.47 v1.4: Vulnerabile per versione (8.3.20)", r10.History[1]);
        Assert.True(ResultMerger.VerdictChanged(r10));
        var r11 = merged.Results.Single(r => r.Host == "192.0.2.11");
        Assert.Equal(Verdict.FixedByVersion, r11.Verdict);
        Assert.False(ResultMerger.VerdictChanged(merged.Results.Single(r => r.Host == "192.0.2.12")));

        string html = report.DifferencesHtml([inA, inB], merged);
        Assert.Contains("Host attivi solo in alcune sessioni: 3", html);   // .10 (attivo solo in B), .12 (solo A), .13 (solo B)
        Assert.Contains("192.0.2.13", html);
        Assert.Contains("non scansionato", html);
        Assert.Contains("Servizi con verdetto diverso tra le sessioni: 2", html);
        // .11: versione PHP e applicazione solo in B, nomi solo in A; .10 non conta (in A non aveva HTTP)
        Assert.Contains("Informazioni presenti in una sessione e assenti in un&#39;altra: 3", html);
        Assert.Contains("old.example.org", html);
        Assert.Contains("WordPress 6.5", html);
        Assert.Contains("Unione 4 host, intersezione 2 host", report.Summary());

        // la sessione fusa si serializza come le altre e il report compatto la legge
        Assert.Contains("1 servizi su 1 host", CompactReportGenerator.Build(merged, "report_completo_v1.4.html"));
    }

    [Fact]
    public void SessionMerger_Load_OldResultsJson_WithDefaults_AndMissingFolderThrows()
    {
        string folder = Path.Combine(_dir, "old");
        Directory.CreateDirectory(folder);
        // results.json della v1.2: solo i campi di allora, niente Cycle/History/Exposures/…
        File.WriteAllText(Path.Combine(folder, SessionFiles.ResultsJson), """
        {
          "AppVersion": "1.2", "StartLocal": "2026-10-22T16:07:12", "EndLocal": "2026-10-22T16:09:00", "Status": "Completed", "Folder": "C:\\Sessioni\\x",
          "TargetCount": 2, "PortCount": 1, "Ports": ["443"], "Paths": ["/"],
          "Results": [
            { "Input": "192.0.2.50", "Host": "192.0.2.50", "IsIpLiteral": true, "Port": 443, "Scheme": "https", "Alive": "Alive", "HttpReachable": true, "PhpDetected": true, "PhpVersionRaw": "8.1.2", "VersionStatus": "EndOfLife", "Verdict": "LikelyVulnerable", "VerdictReason": "r", "StartedLocal": "2026-10-22T16:07:13" },
            { "Input": "192.0.2.51", "Host": "192.0.2.51", "IsIpLiteral": true, "Port": 443, "Alive": "NoResponse", "HttpReachable": false, "Verdict": "NotReachable" }
          ]
        }
        """);
        var inp = SessionMerger.Load(folder);
        Assert.Equal("1.2", inp.Session.AppVersion);
        Assert.Equal(2, inp.Observations.Count);
        var r = inp.Observations[0];
        Assert.Equal(1, r.Cycle);
        Assert.Empty(r.History);
        Assert.Empty(r.Exposures);
        Assert.Empty(r.DiscoveredNames);
        Assert.Equal("", r.DisplayName);
        Assert.Equal("192.0.2.50", r.DisplayIp);
        Assert.Equal(Verdict.LikelyVulnerable, r.Verdict);
        Assert.Equal("2026-10-22 16:07 v1.2", inp.Label);

        // fusione con sé stessa più una sessione recente: nessuna eccezione, storia etichettata
        var merged = SessionMerger.Merge([inp], Path.Combine(_dir, "m2"));
        Assert.Equal(2, merged.Results.Count);
        Assert.Single(merged.Results[0].History);
        Assert.StartsWith("22/10 16.07 v1.2: Probabilmente vulnerabile (8.1.2)", merged.Results[0].History[0]);

        string empty = Path.Combine(_dir, "empty");
        Directory.CreateDirectory(empty);
        var ex = Assert.Throws<ArgumentException>(() => SessionMerger.Load(empty));
        Assert.Contains("session.json", ex.Message);
        Assert.Throws<ArgumentException>(() => SessionMerger.Load(Path.Combine(_dir, "missing")));
    }

    [Fact]
    public void SessionMerger_Load_FromSessionWriterFolder()
    {
        var rows = new List<ScanResult> { Row("192.0.2.70", 443, Verdict.Undetermined, cycle: 1), Row("192.0.2.70", 443, Verdict.VulnerableByVersion, "8.2.30", cycle: 2, started: T0.AddMinutes(1)) };
        var s = Session([rows[1]], cycles: 2, consolidated: true);
        s.Folder = Path.Combine(_dir, "writer"); Directory.CreateDirectory(s.Folder);
        s.Config = new ScanConfig { OutputFolder = _dir };
        using (var w = new SessionWriter(s, consolidate: true))
        {
            w.Upsert(rows[0]);
            w.Upsert(ResultMerger.Merge(rows[0], rows[1]));
            w.Finish(s);
        }
        var inp = SessionMerger.Load(s.Folder);
        Assert.Equal(2, inp.Observations.Count);                      // results.jsonl: ogni osservazione
        Assert.Equal("1.4", inp.Session.AppVersion);
        Assert.Empty(inp.Session.Results);
        var merged = SessionMerger.Merge([inp], Path.Combine(_dir, "m3"));
        var r = Assert.Single(merged.Results);
        Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        Assert.Equal(2, r.History.Count);
        Assert.All(r.History, h => Assert.Contains("v1.4:", h));
    }
}
