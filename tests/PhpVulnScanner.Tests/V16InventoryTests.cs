using System.Text;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Inventory;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Report;

namespace PhpVulnScanner.Tests;

/// <summary>v1.6: inventario (CSV/JSON, riconciliazione, sezione del report, file inventario_vX.Y.json) e sonda di adozione dell'ID di sessione.</summary>
public class V16InventoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v16_" + Guid.NewGuid().ToString("N"));
    private readonly HttpProbe _http = new(2000, 5000);
    public V16InventoryTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { _http.Dispose(); try { Directory.Delete(_dir, true); } catch { } }

    private static ScanResult Row(string host, int port, Verdict v, string php = "", bool http = true, bool phpDetected = true)
    {
        var r = new ScanResult
        {
            Input = host, Host = host, IsIpLiteral = true, Port = port, Scheme = "https", HostHeader = host, Alive = http ? AliveState.Alive : AliveState.NoResponse,
            HttpReachable = http, PhpVersionRaw = php, PhpDetected = http && phpDetected, Verdict = v, ServerHeader = http ? "nginx" : "",
        };
        return r;
    }

    // ---------- CSV ----------

    [Fact]
    public void Csv_Aliases_Semicolon_Quotes_Bom_Comments()
    {
        string csv = "﻿Host;Versione PHP;Ambiente;Referente;Note;App\n" +
                     "# commento\n" +
                     "\n" +
                     "192.0.2.10;8.3.20;produzione;\"Rossi, Mario\";\"nota con ; dentro\";WordPress\n" +
                     "https://www.example.org/path?x=1;;test;Team Web;;\n" +
                     ";8.1;;;;\n";            // bersaglio mancante: scartata
        var list = InventoryFile.ParseCsv(csv, out int skipped);
        Assert.Equal(2, list.Count);
        Assert.Equal(1, skipped);
        Assert.Equal("192.0.2.10", list[0].Target);
        Assert.Equal("8.3.20", list[0].PhpVersion);
        Assert.Equal("Rossi, Mario", list[0].Owner);
        Assert.Equal("nota con ; dentro", list[0].Note);
        Assert.Equal("WordPress", list[0].Application);
        Assert.Equal("produzione", list[0].Environment);
        Assert.Equal("www.example.org", list[1].Target);   // URL ridotta all'host
        Assert.Equal("Team Web", list[1].Owner);
    }

    [Fact]
    public void Csv_CommaAndTab_Separators_InvalidTargetSkipped()
    {
        var comma = InventoryFile.ParseCsv("target,php,owner\n198.51.100.5,8.2.30,Bianchi\nnon valido!!,8.2,Verdi\n", out int skipped);
        Assert.Single(comma);
        Assert.Equal(1, skipped);
        Assert.Equal("Bianchi", comma[0].Owner);
        var tab = InventoryFile.ParseCsv("ip\tphp_version\tteam\n198.51.100.0/28\t8.1.2-1ubuntu2.14\tInfra\n");
        Assert.Single(tab);
        Assert.True(tab[0].IsNetwork);
        Assert.Equal("Infra", tab[0].Owner);
    }

    [Fact]
    public void Csv_WithoutTargetColumn_Throws_AndEmptyIsEmpty()
    {
        Assert.Throws<InvalidDataException>(() => InventoryFile.ParseCsv("php,owner\n8.3,x\n"));
        Assert.Empty(InventoryFile.ParseCsv("# solo commenti\n\n"));
    }

    // ---------- JSON ----------

    [Fact]
    public void Json_AssetsObject_AndBareArray()
    {
        var a = InventoryFile.ParseJson("{\"assets\":[{\"host\":\"192.0.2.20\",\"php\":\"7.4.33\",\"owner\":\"Neri\",\"env\":\"prod\",\"note\":\"legacy\",\"app\":\"Joomla\"},{\"nome\":\"intranet.example.org\"}]}");
        Assert.Equal(2, a.Count);
        Assert.Equal("Neri", a[0].Owner); Assert.Equal("7.4.33", a[0].PhpVersion); Assert.Equal("Joomla", a[0].Application); Assert.Equal("prod", a[0].Environment);
        Assert.Equal("intranet.example.org", a[1].Target);
        var b = InventoryFile.ParseJson("﻿[{\"target\":\"192.0.2.0/24\",\"versione\":\"8.3\"},{\"php\":\"8.3\"},5]", out int skipped);
        Assert.Single(b);
        Assert.Equal(2, skipped);
        Assert.Throws<InvalidDataException>(() => InventoryFile.ParseJson("{\"x\":1}"));
    }

    [Fact]
    public void Load_DetectsFormat_AndRejectsOversize()
    {
        string csv = Path.Combine(_dir, "inv.csv"); File.WriteAllText(csv, "host,php\n192.0.2.1,8.3.36\n", new UTF8Encoding(true));
        string json = Path.Combine(_dir, "inv.json"); File.WriteAllText(json, "[{\"host\":\"192.0.2.2\"}]");
        Assert.Equal("192.0.2.1", InventoryFile.Load(csv)[0].Target);
        Assert.Equal("192.0.2.2", InventoryFile.Load(json)[0].Target);
        string big = Path.Combine(_dir, "big.csv");
        using (var fs = File.Create(big)) fs.SetLength(InventoryFile.MaxBytes + 1);
        Assert.Throws<InvalidDataException>(() => InventoryFile.Load(big));
        Assert.Throws<FileNotFoundException>(() => InventoryFile.Load(Path.Combine(_dir, "manca.csv")));
    }

    // ---------- reti ----------

    [Fact]
    public void Network_Membership_Cidr_Range_Name()
    {
        var cidr = new InventoryEntry("192.0.2.0/28", "", "", "", "", "");
        Assert.True(cidr.Matches("192.0.2.1")); Assert.True(cidr.Matches("192.0.2.15")); Assert.False(cidr.Matches("192.0.2.16")); Assert.False(cidr.Matches("www.example.org"));
        var range = new InventoryEntry("198.51.100.10-20", "", "", "", "", "");
        Assert.True(range.Matches("198.51.100.10")); Assert.True(range.Matches("198.51.100.20")); Assert.False(range.Matches("198.51.100.21"));
        var full = new InventoryEntry("198.51.100.10-198.51.100.12", "", "", "", "", "");
        Assert.True(full.Matches("198.51.100.11")); Assert.False(full.Matches("198.51.100.13"));
        var v6 = new InventoryEntry("2001:db8::/32", "", "", "", "", "");
        Assert.True(v6.Matches("2001:db8:1::1")); Assert.False(v6.Matches("2001:db9::1"));
        var name = new InventoryEntry("www.example.org", "", "", "", "", "");
        Assert.True(name.Matches("WWW.EXAMPLE.ORG")); Assert.False(name.Matches("example.org")); Assert.False(name.IsNetwork);
    }

    // ---------- riconciliazione ----------

    private static List<InventoryEntry> Inventory() =>
    [
        new("192.0.2.10", "8.3.20", "prod", "Rossi", "sito pubblico", "WordPress"),
        new("192.0.2.11", "8.1.2", "prod", "Bianchi", "", ""),
        new("192.0.2.12", "7.4.33", "test", "Verdi", "", ""),
        new("192.0.2.13", "", "prod", "Neri", "", ""),
        new("203.0.113.0/24", "8.2.35", "dmz", "Infra", "", ""),
        new("shop.example.org", "", "prod", "Team Web", "", ""),
        new("192.0.2.99", "8.3.36", "prod", "Gialli", "", ""),
    ];

    [Fact]
    public void Reconcile_Statuses_And_Counters()
    {
        var ok = Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "8.3.20-1+deb12u1");          // stessa versione, suffisso ignorato
        var diff = Row("192.0.2.11", 443, Verdict.VulnerableByVersion, "8.1.30");                  // versione diversa
        var noPhp = Row("192.0.2.12", 443, Verdict.NoPhpDetected, phpDetected: false);              // dichiarato PHP, non osservato
        var noDecl = Row("192.0.2.13", 443, Verdict.Undetermined);                                  // nessuna versione dichiarata, PHP osservato
        var net = Row("203.0.113.7", 443, Verdict.FixedByVersion, "8.2.35");                        // coperto dalla rete
        var byName = Row("198.51.100.3", 443, Verdict.Undetermined); byName.DiscoveredNames = ["Shop.Example.org"];   // per nome scoperto
        var unknown = Row("198.51.100.9", 80, Verdict.NoPhpDetected, phpDetected: false);           // osservato, non inventariato
        var dead = Row("198.51.100.10", 443, Verdict.NotReachable, http: false);                    // non HTTP: non entra tra i non inventariati
        var results = new List<ScanResult> { ok, diff, noPhp, noDecl, net, byName, unknown, dead };

        var rep = InventoryMatcher.Reconcile(Inventory(), results);

        Assert.Equal(InventoryMatcher.StatusOk, ok.InventoryStatus); Assert.Equal("Rossi", ok.InventoryOwner); Assert.Equal("prod", ok.InventoryEnvironment); Assert.Equal("sito pubblico", ok.InventoryNote); Assert.Equal("8.3.20", ok.InventoryDeclaredVersion);
        Assert.Equal(InventoryMatcher.StatusVersionDiffers, diff.InventoryStatus);
        Assert.Equal(InventoryMatcher.StatusDeclaredPhpNotObserved, noPhp.InventoryStatus);
        Assert.Equal(InventoryMatcher.StatusOk, noDecl.InventoryStatus);
        Assert.Equal(InventoryMatcher.StatusOk, net.InventoryStatus); Assert.Equal("Infra", net.InventoryOwner);
        Assert.Equal("Team Web", byName.InventoryOwner);
        Assert.Equal("", unknown.InventoryStatus); Assert.Equal("", unknown.InventoryOwner);
        Assert.Equal("", dead.InventoryStatus);

        Assert.Equal(7, rep.Entries);
        Assert.Equal(6, rep.Matched);
        Assert.Single(rep.VersionMismatches);
        Assert.Equal(("8.1.2", "8.1.30"), (rep.VersionMismatches[0].Declared, rep.VersionMismatches[0].Observed));
        Assert.Equal("Bianchi", rep.VersionMismatches[0].Service.Owner);
        Assert.Single(rep.DeclaredNotObserved); Assert.Equal("192.0.2.99", rep.DeclaredNotObserved[0].Target);
        Assert.Single(rep.ObservedNotInventoried); Assert.Equal("198.51.100.9", rep.ObservedNotInventoried[0].Ip);
        Assert.Single(rep.DeclaredPhpNotObserved);
        Assert.Equal("Rossi", rep.OwnerOf(ok)); Assert.Equal("", rep.OwnerOf(unknown));
        Assert.Contains("7 voci", rep.Summary()); Assert.Contains("6 servizi riconciliati", rep.Summary());
    }

    [Fact]
    public void Reconcile_IsIdempotent_AndClearsStaleFields()
    {
        var r = Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "8.3.20");
        r.InventoryOwner = "vecchio"; r.InventoryStatus = "versione diversa";
        var inv = new List<InventoryEntry> { new("192.0.2.10", "8.3.20", "", "Rossi", "", "") };
        InventoryMatcher.ApplyToResults(inv, [r]);
        var again = InventoryMatcher.ApplyToResults(inv, [r]);
        Assert.Equal("Rossi", r.InventoryOwner); Assert.Equal(InventoryMatcher.StatusOk, r.InventoryStatus);
        Assert.Equal(1, again.Matched);
        // bersaglio tolto dall'inventario: i campi tornano vuoti
        InventoryMatcher.ApplyToResults([], [r]);
        Assert.Equal("", r.InventoryOwner); Assert.Equal("", r.InventoryStatus);
    }

    [Fact]
    public void SameVersion_IgnoresSuffix_BranchOnlyDeclaration()
    {
        Assert.True(InventoryMatcher.SameVersion("8.1.2", "PHP/8.1.2-1ubuntu2.14"));
        Assert.True(InventoryMatcher.SameVersion("8.3", "8.3.20"));
        Assert.False(InventoryMatcher.SameVersion("8.3.36", "8.3.20"));
        Assert.False(InventoryMatcher.SameVersion("7.4", "8.0.30"));
    }

    [Fact]
    public void NotReachable_Matched_IsNotObserved_AndDeclaredNotObserved()
    {
        var dead = Row("192.0.2.10", 443, Verdict.NotReachable, http: false);
        var rep = InventoryMatcher.Reconcile([new("192.0.2.10", "8.3.20", "", "Rossi", "", "")], [dead]);
        Assert.Equal(InventoryMatcher.StatusNotObserved, dead.InventoryStatus);
        Assert.Equal("Rossi", dead.InventoryOwner);
        Assert.Single(rep.DeclaredNotObserved);
    }

    // ---------- sezione del report ----------

    [Fact]
    public void Section_ContainsCounters_Names_Owners_Escaped()
    {
        var diff = Row("192.0.2.11", 443, Verdict.VulnerableByVersion, "8.1.30"); diff.DiscoveredNames = ["intranet.example.org"];
        var unknown = Row("198.51.100.9", 8080, Verdict.NoPhpDetected, phpDetected: false); unknown.DiscoveredNames = ["extra.example.org"];
        var inv = new List<InventoryEntry> { new("192.0.2.11", "8.1.2", "prod", "Bianchi <Web>", "", ""), new("192.0.2.99", "8.3.36", "prod", "Gialli", "", "") };
        var rep = InventoryMatcher.Reconcile(inv, [diff, unknown]);
        var s = new ScanSession { Results = [diff, unknown] };
        string html = InventoryReportSection.InventorySection(s, rep);
        Assert.StartsWith("<section", html); Assert.EndsWith("</section>", html);
        Assert.Contains("Inventario", html);
        Assert.Contains("Versioni diverse", html); Assert.Contains("Dichiarati ma non osservati", html); Assert.Contains("Osservati ma non inventariati", html);
        Assert.Contains("intranet.example.org", html); Assert.Contains("extra.example.org", html);
        Assert.Contains("Bianchi &lt;Web&gt;", html); Assert.DoesNotContain("Bianchi <Web>", html);
        Assert.Contains("Gialli", html); Assert.Contains("192.0.2.99", html);
        Assert.Contains("8.1.2", html); Assert.Contains("8.1.30", html);
        Assert.Equal("", InventoryReportSection.InventorySection(s, null));
    }

    // ---------- Apply: file inventario_vX.Y.json ----------

    [Fact]
    public void Apply_WritesInventoryJson_AndReadsItBack()
    {
        string inv = Path.Combine(_dir, "inventario.csv");
        File.WriteAllText(inv, "host;php;referente\n192.0.2.10;8.3.20;Rossi\n192.0.2.99;8.3.36;Gialli\n");
        var cfg = new ScanConfig { InventoryPath = inv };
        var s = new ScanSession { AppVersion = "1.6", Folder = Path.Combine(_dir, "sess"), Results = [Row("192.0.2.10", 443, Verdict.VulnerableByVersion, "8.3.20")] };
        var log = new List<string>();
        var rep = InventoryMatcher.Apply(cfg, s, log.Add);
        Assert.NotNull(rep);
        string file = Path.Combine(s.Folder, "inventario_v1.6.json");
        Assert.True(File.Exists(file));
        Assert.Contains("Gialli", File.ReadAllText(file));
        Assert.Equal("Rossi", s.Results[0].InventoryOwner);
        Assert.Contains(log, l => l.Contains("1 servizi riconciliati"));
        var back = InventoryMatcher.Read(s.Folder, "1.6");
        Assert.NotNull(back); Assert.Equal(1, back!.Matched); Assert.Single(back.DeclaredNotObserved);
        // senza inventario: null, nessun file; con file mancante: log, null
        Assert.Null(InventoryMatcher.Apply(new ScanConfig(), s, null));
        Assert.Null(InventoryMatcher.Apply(new ScanConfig { InventoryPath = Path.Combine(_dir, "no.csv") }, s, log.Add));
        Assert.Contains(log, l => l.Contains("Inventario non letto"));
    }

    // ---------- sonda di adozione dell'ID di sessione ----------

    private async Task<ScanContext> RunProbeAsync(FakePhpServer srv, bool enabled = true)
    {
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.1", PortsText = srv.Port.ToString(), PathsText = "/", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000,
            Level1InfoPages = false, Level1EasterEgg = false, Level2 = false, WafDetect = false, SurfaceDiscovery = false, DiscoverNames = false,
        };
        cfg.Advanced.SetAll(false);
        cfg.Advanced.SessionIdProbe = enabled;
        var r = new ScanResult { Input = "127.0.0.1", Host = "127.0.0.1", IsIpLiteral = true, Port = srv.Port, Scheme = "http", HostHeader = "127.0.0.1" };
        var ctx = new ScanContext { Config = cfg, Http = _http, Endpoint = new HttpEndpoint("http", "127.0.0.1", srv.Port), Result = r, Paths = ["/"], Log = _ => { }, Ct = CancellationToken.None };
        await PhpFingerprint.RunAsync(ctx);
        Assert.True(r.HttpReachable);
        int before = srv.Requests.Count;
        await SessionProbe.RunAsync(ctx);
        Assert.True(srv.Requests.Count - before <= 1, "la sonda invia al massimo una richiesta");
        return ctx;
    }

    [Fact]
    public async Task SessionProbe_Adopted_WhenServerIssuesNothing()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", SessionCookie = true, StrictMode = false };
        var ctx = await RunProbeAsync(srv);
        var r = ctx.Result;
        Assert.True(r.SessionIdAdopted);
        Assert.Contains("use_strict_mode spento", r.SessionIdDetail);
        var t = Assert.Single(r.Tests, t => t.Id == "ADV-SESSIONID");
        Assert.Equal(TestOutcome.Warn, t.Outcome);
        Assert.NotNull(srv.LastSessionIdReceived);
        Assert.Equal(26, srv.LastSessionIdReceived!.Length);
        Assert.All(srv.LastSessionIdReceived, c => Assert.True(c is >= '0' and <= '9' or >= 'a' and <= 'v'));
        Assert.Equal(t.Request, "GET " + ctx.PrimaryPath);   // lo snapshot della sonda è registrato tra le richieste
        Assert.Equal(r.Requests.Count, r.Tests.Count(x => x.Request.Length > 0));
        Assert.Contains(srv.Requests.Skip(1), q => q.StartsWith("GET /"));
    }

    [Fact]
    public async Task SessionProbe_StrictMode_ServerIssuesItsOwnId()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", SessionCookie = true, StrictMode = true };
        var ctx = await RunProbeAsync(srv);
        Assert.False(ctx.Result.SessionIdAdopted);
        Assert.Contains("use_strict_mode attivo", ctx.Result.SessionIdDetail);
        Assert.Equal(TestOutcome.Info, Assert.Single(ctx.Result.Tests, t => t.Id == "ADV-SESSIONID").Outcome);
    }

    [Fact]
    public async Task SessionProbe_NoSessionOnMainPath_NotApplicable_NoRequest()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", SessionCookie = false };
        var ctx = await RunProbeAsync(srv);
        Assert.Null(ctx.Result.SessionIdAdopted);
        Assert.Contains("non avvia una sessione", ctx.Result.SessionIdDetail);
        Assert.Single(srv.Requests);   // solo la GET di riferimento del livello 1: la sonda non ha inviato nulla
        Assert.Equal(TestOutcome.Info, Assert.Single(ctx.Result.Tests, t => t.Id == "ADV-SESSIONID").Outcome);
    }

    [Fact]
    public async Task SessionProbe_Disabled_DoesNothing()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", SessionCookie = true };
        var ctx = await RunProbeAsync(srv, enabled: false);
        Assert.Null(ctx.Result.SessionIdAdopted);
        Assert.Equal("", ctx.Result.SessionIdDetail);
        Assert.DoesNotContain(ctx.Result.Tests, t => t.Id == "ADV-SESSIONID");
    }

    [Fact]
    public void SessionProbe_NewId_FormatAndIssuedParsing()
    {
        string id = SessionProbe.NewSessionId();
        Assert.Equal(26, id.Length);
        Assert.NotEqual(id, SessionProbe.NewSessionId());
        var snap = new HttpSnapshot { Status = 200, Headers = [new("Set-Cookie", "other=1; path=/"), new("Set-Cookie", "PHPSESSID=abc123; path=/; HttpOnly")] };
        Assert.Equal("abc123", SessionProbe.IssuedSessionId(snap));
        Assert.Null(SessionProbe.IssuedSessionId(new HttpSnapshot { Status = 200 }));
        Assert.Null(SessionProbe.IssuedSessionId(null));
    }
}
