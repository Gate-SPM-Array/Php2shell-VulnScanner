using System.Net;
using System.Text;
using PhpVulnScanner.Core.Apps;
using Xunit.Abstractions;

namespace PhpVulnScanner.Tests;

/// <summary>
/// Aggiornamento del database applicazioni (<see cref="AppDbUpdater"/>) senza rete: il convertitore C# su un input sintetico, confrontato
/// byte per byte con l'uscita di <c>tools/build_appdb.py</c> sullo stesso input, e il percorso completo di <see cref="AppDbUpdater.UpdateAsync(HttpClient,string,IProgress{string}?,CancellationToken)"/>
/// con un <see cref="HttpMessageHandler"/> finto (elenco API, fallback, commit, scrittura atomica, nessuna sostituzione in caso di errore).
/// </summary>
public class AppDbUpdaterTests
{
    private readonly ITestOutputHelper _out;
    public AppDbUpdaterTests(ITestOutputHelper output) => _out = output;

    // ---- input sintetico (tre tecnologie di cui una duplicata, quattro pacchetti SPDX, sei asserzioni VEX + una su una CVE estranea) ----
    // <LS> = U+2028, <DEL> = U+007F: Python li scrive letterali con ensure_ascii=False, come fa PyJson.

    private const string Categories = """{"1":{"name":"CMS","priority":1},"18":{"name":"Web frameworks","priority":3},"27":{"name":"Programming languages"},"5":"not an object","007":{"name":"Padded"}}""";

    private const string TechUnderscore = """{"PHP": {"cats": [27, "18", true], "website": "http://php.net", "cpe": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "headers": {"X-Powered-By": "^PHP(?:/([\\d.]+))?\\;version:\\1", "Server": "php/?([\\d.]+)?\\;version:\\1", "Empty": "", "Skip": []}, "cookies": {"PHPSESSID": ""}, "js": {"foo": ""}, "url": "\\.php(?:$|\\?)", "dns": {"txt": "x"}}, "NotAnObject": 5}""";

    private const string TechW = """{"WordPress": {"cats": [1, 11], "website": "https://wordpress.org", "meta": {"generator": "^WordPress(?: ([\\d.]+))?\\;version:\\1"}, "html": "<link rel=[\"']stylesheet[\"'] [^>]+/wp-(?:content|includes)/", "dom": {"link[href*='/wp-content/']": {"exists": ""}, "div[data-x]": {"text": "x"}, "a[href^='/wp-admin/'], img[src$='.png'], meta[name=\"generator\"], span[data-a-b]": "", "div > span": ""}, "scriptSrc": "/wp-includes/", "scripts": ["/wp-includes/", "/wp-content/"], "implies": ["PHP", "MySQL"], "requires": [], "excludes": "Drupal", "description": "Caffè è ünicode — <LS> <&>'"}, "Matomo Analytics": {"cats": [10], "website": "https://matomo.org", "implies": ["Nginx\\;confidence:50"], "cookies": {"MATOMO_SESSID": ""}, "html": "Caffè \"q\" \\ \t tab <&>' <LS> <DEL>"}, "PHP": {"cats": [1], "website": "dup"}}""";

    private const string Spdx = """
        {"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[
        {"type":"security_Vulnerability","spdxId":"urn:vuln:1","name":"CVE-2026-109618"},
        {"type":"security_Vulnerability","spdxId":"urn:vuln:2","name":"CVE-2026-109619"},
        {"type":"security_Vulnerability","spdxId":"urn:vuln:3","name":"CVE-2020-1234"},
        {"type":"software_Package","spdxId":"urn:pkg:wp","name":" WordPress ","comment":"Category: CMS and publishing\nAliases: WordPress.org, wordpress/wordpress , \nNotes: x","externalRef":[{"type":"ExternalRef","locator":["https://wordpress.org/about/requirements/"]}]},
        {"type":"software_Package","spdxId":"urn:pkg:arch","name":"Arch Linux Extra PHP package","comment":"Category: Linux distributions","externalRef":[{"type":"ExternalRef","locator":[]},{"type":"ExternalRef","locator":["https://archlinux.org/packages/extra/x86_64/php/"]}]},
        {"type":"software_Package","spdxId":"urn:pkg:num","name":"123 Thing é"},
        {"type":"software_Package","spdxId":"urn:pkg:sym","name":"Ébauche"},
        {"type":"security_VexAffectedVulnAssessmentRelationship","spdxId":"urn:vex:1","from":"urn:vuln:1","to":["urn:pkg:wp"],"security_statusNotes":"Affected when deployed on an affected PHP runtime; see https://calif.io/php2shell/.","externalRef":[{"type":"ExternalRef","locator":["https://calif.io/php2shell/"]}]},
        {"type":"security_VexAffectedVulnAssessmentRelationship","spdxId":"urn:vex:2","from":"urn:vuln:2","to":["urn:pkg:wp"],"security_impactStatement":"  Same as above.  ","comment":"Reference: https://www.php.net/archive/2026.php#2026-10-21-5."},
        {"type":"security_VexFixedVulnAssessmentRelationship","spdxId":"urn:vex:3","from":"urn:vuln:1","to":["urn:pkg:arch","urn:pkg:num"],"security_statusNotes":"Fixed in php 8.5.12-1. Also 9.9.9 later. Not before 8.5.11"},
        {"type":"security_VexFixedVulnAssessmentRelationship","spdxId":"urn:vex:4","from":"urn:vuln:2","to":["urn:pkg:arch"],"security_statusNotes":"Upstream fixed PHP in 8.5.12, 8.4.27, 8.3.36, 8.2.35 and 1.0; Debian 8.2.35-1"},
        {"type":"security_VexNotAffectedVulnAssessmentRelationship","spdxId":"urn:vex:5","from":"urn:vuln:3","to":["urn:pkg:arch"],"security_statusNotes":"other CVE"},
        {"type":"security_VexUnderInvestigationVulnAssessmentRelationship","spdxId":"urn:vex:6","from":"urn:vuln:2","to":["urn:pkg:num"],"summary":"PHP relationship confirmed; CVE match unknown"}
        ]}
        """;

    // ---- uscita attesa: prodotta da `python3 -I tools/build_appdb.py` sullo stesso input (byte per byte, senza il newline finale) ----

    private const string ExpectedTechnologies = """{"Matomo Analytics":{"cats":[10],"website":"https://matomo.org","cookies":{"MATOMO_SESSID":[""]},"html":["Caffè \"q\" \\ \t tab <&>' <LS> <DEL>"],"implies":["Nginx\\;confidence:50","PHP"]},"PHP":{"cats":[27,18,1],"website":"http://php.net","cpe":"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*","headers":{"X-Powered-By":["^PHP(?:/([\\d.]+))?\\;version:\\1"],"Server":["php/?([\\d.]+)?\\;version:\\1"],"Empty":[""]},"cookies":{"PHPSESSID":[""]},"url":["\\.php(?:$|\\?)"]},"WordPress":{"cats":[1,11],"website":"https://wordpress.org","meta":{"generator":["^WordPress(?: ([\\d.]+))?\\;version:\\1"]},"html":["<link rel=[\"']stylesheet[\"'] [^>]+/wp-(?:content|includes)/","<link\\b[^>]*\\shref=[\\\"']?[^\\\"'>]*/wp\\-content/","<a\\b[^>]*\\shref=[\\\"']?/wp\\-admin/","<img\\b[^>]*\\ssrc=[\\\"']?[^\\\"'>]*\\.png[\\\"'\\s>/]","<meta\\b[^>]*\\sname=[\\\"']?generator[\\\"'\\s>/]","<span\\b[^>]*\\sdata\\-a\\-b(?:[\\s=>/]|$)"],"scriptSrc":["/wp-includes/","/wp-content/"],"implies":["PHP","MySQL"],"excludes":["Drupal"]}}""";

    private const string ExpectedCategories = """{"1":"CMS","18":"Web frameworks","27":"Programming languages","7":"Padded"}""";

    private const string ExpectedPackages = """[{"name":"123 Thing é","aliases":[],"category":"","url":"","vex":{"CVE-2026-109618":{"status":"Fixed","fixedVersion":"8.5.12-1","note":"Fixed in php 8.5.12-1. Also 9.9.9 later. Not before 8.5.11"},"CVE-2026-109619":{"status":"UnderInvestigation","note":"PHP relationship confirmed; CVE match unknown"}},"reference":"https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_0-9.md"},{"name":"Arch Linux Extra PHP package","aliases":[],"category":"Linux distributions","url":"https://archlinux.org/packages/extra/x86_64/php/","vex":{"CVE-2026-109618":{"status":"Fixed","fixedVersion":"8.5.12-1","note":"Fixed in php 8.5.12-1. Also 9.9.9 later. Not before 8.5.11"},"CVE-2026-109619":{"status":"Fixed","fixedVersion":"8.5.12, 8.4.27, 8.3.36, 8.2.35","note":"Upstream fixed PHP in 8.5.12, 8.4.27, 8.3.36, 8.2.35 and 1.0; Debian 8.2.35-1"}},"reference":"https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_a.md"},{"name":"WordPress","aliases":["WordPress.org","wordpress/wordpress"],"category":"CMS and publishing","url":"https://wordpress.org/about/requirements/","vex":{"CVE-2026-109618":{"status":"Affected","note":"Affected when deployed on an affected PHP runtime; see https://calif.io/php2shell/.","reference":"https://calif.io/php2shell/"},"CVE-2026-109619":{"status":"Affected","note":"Same as above.","reference":"https://www.php.net/archive/2026.php#2026-10-21-5"}},"reference":"https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_w.md"},{"name":"Ébauche","aliases":[],"category":"","url":"","vex":{},"reference":"https://github.com/NCSC-NL/php2shell/blob/main/software/software_list.md"}]""";

    private static string Real(string s) => s.Replace("<LS>", "\u2028").Replace("<DEL>", "\u007f");

    private static AppDbUpdater.ConvertedData ConvertSynthetic() =>
        AppDbUpdater.Convert(Categories, [("w.json", Real(TechW)), ("_.json", Real(TechUnderscore))], Spdx);   // ordine volutamente invertito: il convertitore ordina per nome file

    [Fact]
    public void Convert_MatchesPythonOutput_ByteForByte()
    {
        var d = ConvertSynthetic();
        _out.WriteLine(d.Stats.ToString());
        Assert.Equal(Real(ExpectedTechnologies), AppDbUpdater.PyJson.Serialize(d.Technologies));
        Assert.Equal(ExpectedCategories, AppDbUpdater.PyJson.Serialize(d.Categories));
        Assert.Equal(ExpectedPackages, AppDbUpdater.PyJson.Serialize(d.Packages));

        // stesse statistiche stampate dallo script Python
        Assert.Equal(16, d.Stats.Patterns);
        Assert.Equal(1, d.Stats.Duplicates);     // "PHP" in w.json dopo _.json
        Assert.Equal(5, d.Stats.DomConverted);
        Assert.Equal(2, d.Stats.DomSkipped);     // div[data-x] con condizione "text", "div > span" non semplice
        Assert.Equal(1, d.Stats.PhpFixups);      // Matomo Analytics
        Assert.Equal(6, d.Stats.Vex);            // la CVE-2020-1234 non conta
        Assert.Equal(3, d.Technologies.Count);
        Assert.Equal(4, d.Packages.Count);
    }

    [Fact]
    public void Convert_OutputLoadsIntoTechnologyDatabase()
    {
        var d = ConvertSynthetic();
        string dir = TempDir();
        try
        {
            AppDbUpdater.WriteAtomic(dir, d, AppDbUpdater.DataVersionText(d, "abc", "2026-10-24T00:00:00Z", "def", "2026-10-24T00:00:00Z"));
            var db = TechnologyDatabase.Load(dir);
            Assert.Equal(3, db.Count);
            Assert.True(db.ImpliesPhp("WordPress"));
            Assert.True(db.ImpliesPhp("Matomo Analytics"), "correzione implies PHP applicata");
            Assert.Equal("CMS", db.CategoryName(1));
            Assert.Equal(4, db.Inventory.Count);
            Assert.Equal(6, db.Inventory.VexCount);
            Assert.Equal("8.5.12-1", db.Inventory.Find("Arch Linux Extra PHP package")!.Vex["CVE-2026-109618"].FixedVersion);
            Assert.Equal(new[] { "WordPress.org", "wordpress/wordpress" }, db.Inventory.Find("WordPress")!.Aliases);
            Assert.Equal("webappanalyzer abc 2026-10-24T00:00:00Z 3 technologies; ncsc-nl/php2shell def 2026-10-24T00:00:00Z 4 packages 6 vex", db.DataVersion);
            Assert.Empty(Directory.GetDirectories(dir));   // cartella temporanea rimossa
            // il riconoscimento funziona sui dati convertiti
            var m = db.Match([new() { Url = "https://www.example.org/", Status = 200, Body = "<html><head><meta name=\"generator\" content=\"WordPress 6.5\"><link href=\"/wp-content/x.css\"></head></html>" }], null);
            Assert.Contains(m, x => x.Name == "WordPress" && x.Version == "6.5");
        }
        finally { Directory.Delete(dir, true); }
    }

    [Theory]
    [InlineData("link[href*='/wp-content/']", @"<link\b[^>]*\shref=[\""']?[^\""'>]*/wp\-content/")]
    [InlineData("a[href^='/wp-admin/']", @"<a\b[^>]*\shref=[\""']?/wp\-admin/")]
    [InlineData("img[src$='.png']", @"<img\b[^>]*\ssrc=[\""']?[^\""'>]*\.png[\""'\s>/]")]
    [InlineData("meta[name=\"generator\"]", @"<meta\b[^>]*\sname=[\""']?generator[\""'\s>/]")]
    [InlineData("[data-a-b]", @"<[a-zA-Z][a-zA-Z0-9-]*\b[^>]*\sdata\-a\-b(?:[\s=>/]|$)")]
    [InlineData("div > span", null)]
    [InlineData("div.cls[x]", null)]
    public void SelectorToRegex_LikePython(string selector, string? expected) => Assert.Equal(expected, AppDbUpdater.SelectorToRegex(selector));

    [Fact]
    public void PyReEscape_EscapesOnlyPythonSpecials()
    {
        Assert.Equal(@"/wp\-content/", AppDbUpdater.PyReEscape("/wp-content/"));
        Assert.Equal(@"a\ b\.c\#d\&e\~f\|g\(h\)\[i\]\{j\}\?\*\+\^\$\\", AppDbUpdater.PyReEscape("a b.c#d&e~f|g(h)[i]{j}?*+^$\\"));
        Assert.Equal("/:=<>!,'\"@%;_", AppDbUpdater.PyReEscape("/:=<>!,'\"@%;_"));
    }

    [Theory]
    [InlineData("Fixed in 8.5.12, 8.4.27, 8.3.36, 8.2.35 and 8.1.34 later", "8.5.12, 8.4.27, 8.3.36, 8.2.35")]
    [InlineData("Fixed in php 8.5.12-1. Also 9.9.9 later.", "8.5.12-1")]
    [InlineData("The vendor fixed this in release 6.4.2; see notes", "6.4.2")]
    [InlineData("Fixed upstream in version 1.2.3.4 of the plugin", "1.2.3.4")]
    [InlineData("Affected, no fix", "")]
    [InlineData("Fixed in file index.php of the tree", "")]
    public void FixedVersion_LikePython(string notes, string expected) => Assert.Equal(expected, AppDbUpdater.FixedVersion(notes));

    [Fact]
    public void PyJson_EscapesLikePythonJsonDump()
    {
        var o = new System.Text.Json.Nodes.JsonObject { ["k"] = "a\"b\\c\nd\re\tf\bg\fh\u0001i<&>'\u00e8\u2028\u007f/", ["n"] = 5, ["z"] = new System.Text.Json.Nodes.JsonArray() };
        Assert.Equal("{\"k\":\"a\\\"b\\\\c\\nd\\re\\tf\\bg\\fh\\u0001i<&>'\u00e8\u2028\u007f/\",\"n\":5,\"z\":[]}", AppDbUpdater.PyJson.Serialize(o));
    }

    // ---- percorso completo con rete finta ----

    /// <summary>Handler finto: risponde per URL; gli URL assenti danno 404; <c>Fail</c> fa fallire la richiesta corrispondente.</summary>
    private sealed class FakeHandler : HttpMessageHandler
    {
        public readonly Dictionary<string, string> Routes = new(StringComparer.Ordinal);
        public readonly List<string> Requested = [];
        public HashSet<string> Fail = new(StringComparer.Ordinal);
        public string? LastUserAgent;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            string url = request.RequestUri!.ToString();
            Requested.Add(url);
            LastUserAgent = request.Headers.UserAgent.ToString();
            if (Fail.Contains(url)) throw new HttpRequestException("connection refused (fake)");
            if (!Routes.TryGetValue(url, out var body)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("not found") });
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private static FakeHandler SyntheticGitHub(bool withApi)
    {
        var h = new FakeHandler();
        h.Routes[AppDbUpdater.WappalyzerRawBase + "categories.json"] = Categories;
        h.Routes[AppDbUpdater.NcscRawUrl] = Spdx;
        h.Routes[AppDbUpdater.WappalyzerRawBase + "technologies/_.json"] = Real(TechUnderscore);
        h.Routes[AppDbUpdater.WappalyzerRawBase + "technologies/w.json"] = Real(TechW);
        if (withApi)
        {
            h.Routes[AppDbUpdater.WappalyzerContentsApi] = """[{"name":"_.json","type":"file"},{"name":"w.json","type":"file"},{"name":"README.md","type":"file"},{"name":"sub","type":"dir"}]""";
            h.Routes[AppDbUpdater.WappalyzerCommitsApi] = """[{"sha":"d91f7e510e93457041bea874e8a9ffb011e3e4fe","commit":{"author":{"date":"2026-10-19T15:00:00Z"},"committer":{"date":"2026-10-19T15:09:50Z"}}}]""";
            h.Routes[AppDbUpdater.NcscCommitsApi] = """[{"sha":"2fdc314ded280d18868d13d2f33d092a15e5a231","commit":{"committer":{"date":"2026-10-23T12:50:49Z"}}}]""";
        }
        else
        {
            // senza API l'elenco è fisso: _.json più a.json…z.json; le lettere assenti rispondono con un oggetto vuoto
            foreach (var name in AppDbUpdater.FallbackTechnologyFiles)
                h.Routes.TryAdd(AppDbUpdater.WappalyzerRawBase + "technologies/" + name, "{}");
        }
        return h;
    }

    [Fact]
    public async Task UpdateAsync_WithApi_WritesFourFilesAndVersion()
    {
        var h = SyntheticGitHub(withApi: true);
        string dir = TempDir();
        var messages = new List<string>();
        try
        {
            using var client = new HttpClient(h);
            client.DefaultRequestHeaders.UserAgent.ParseAdd(AppDbUpdater.UserAgent);
            var res = await AppDbUpdater.UpdateAsync(client, dir, new Progress<string>(messages.Add), CancellationToken.None);
            Assert.Equal(3, res.Technologies);
            Assert.Equal(4, res.Categories);
            Assert.Equal(4, res.Packages);
            Assert.Equal(6, res.Vex);
            Assert.Equal("webappanalyzer d91f7e510e93457041bea874e8a9ffb011e3e4fe 2026-10-19T15:09:50Z 3 technologies\nncsc-nl/php2shell 2fdc314ded280d18868d13d2f33d092a15e5a231 2026-10-23T12:50:49Z 4 packages 6 vex", res.DataVersion);
            Assert.Equal(res.DataVersion + "\n", File.ReadAllText(Path.Combine(dir, "DATA-VERSION.txt")));
            Assert.Equal(Real(ExpectedTechnologies) + "\n", File.ReadAllText(Path.Combine(dir, "technologies.json")));
            Assert.Equal(ExpectedCategories + "\n", File.ReadAllText(Path.Combine(dir, "categories.json")));
            Assert.Equal(ExpectedPackages + "\n", File.ReadAllText(Path.Combine(dir, "ncsc_inventory.json")));
            Assert.Equal(4, Directory.GetFileSystemEntries(dir).Length);
            Assert.StartsWith("PhpVulnScanner/", h.LastUserAgent);
            Assert.DoesNotContain(h.Requested, u => u.EndsWith("/a.json"));   // l'elenco API ha vinto sul fallback
            Assert.Contains(messages, m => m.Contains("3 tecnologie"));
            Assert.NotNull(TechnologyDatabase.TryLoad(dir));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task UpdateAsync_WithoutApi_FallsBackToFixedList_AndUnknownCommit()
    {
        var h = SyntheticGitHub(withApi: false);
        string dir = TempDir();
        try
        {
            using var client = new HttpClient(h);
            var res = await AppDbUpdater.UpdateAsync(client, dir, null, CancellationToken.None);
            Assert.Equal(3, res.Technologies);
            Assert.Contains(h.Requested, u => u.EndsWith("/technologies/z.json"));
            Assert.Equal(27, h.Requested.Count(u => u.Contains("/technologies/")));
            Assert.StartsWith("webappanalyzer unknown 20", res.DataVersion);
            Assert.Contains("\nncsc-nl/php2shell unknown 20", res.DataVersion);
            Assert.Equal(Real(ExpectedTechnologies) + "\n", File.ReadAllText(Path.Combine(dir, "technologies.json")));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public async Task UpdateAsync_OnFailure_LeavesFolderUntouched()
    {
        string dir = TempDir();
        try
        {
            File.WriteAllText(Path.Combine(dir, "technologies.json"), "{\"Old\":{\"cats\":[1],\"website\":\"\"}}\n");
            File.WriteAllText(Path.Combine(dir, "categories.json"), "{\"1\":\"CMS\"}\n");
            File.WriteAllText(Path.Combine(dir, "ncsc_inventory.json"), "[]\n");
            File.WriteAllText(Path.Combine(dir, "DATA-VERSION.txt"), "old\n");
            var before = Directory.GetFiles(dir).ToDictionary(Path.GetFileName, File.ReadAllText);

            // 1. inventario NCSC non raggiungibile
            var h = SyntheticGitHub(withApi: true);
            h.Fail.Add(AppDbUpdater.NcscRawUrl);
            using (var client = new HttpClient(h))
                await Assert.ThrowsAsync<HttpRequestException>(() => AppDbUpdater.UpdateAsync(client, dir, null, CancellationToken.None));
            AssertUnchanged(dir, before);

            // 2. un file di firme manca (404)
            h = SyntheticGitHub(withApi: true);
            h.Routes.Remove(AppDbUpdater.WappalyzerRawBase + "technologies/w.json");
            using (var client = new HttpClient(h))
                await Assert.ThrowsAsync<HttpRequestException>(() => AppDbUpdater.UpdateAsync(client, dir, null, CancellationToken.None));
            AssertUnchanged(dir, before);

            // 3. JSON non valido
            h = SyntheticGitHub(withApi: true);
            h.Routes[AppDbUpdater.WappalyzerRawBase + "categories.json"] = "{ not json";
            using (var client = new HttpClient(h))
                await Assert.ThrowsAnyAsync<System.Text.Json.JsonException>(() => AppDbUpdater.UpdateAsync(client, dir, null, CancellationToken.None));
            AssertUnchanged(dir, before);

            // 4. annullamento
            h = SyntheticGitHub(withApi: true);
            using (var client = new HttpClient(h))
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AppDbUpdater.UpdateAsync(client, dir, null, new CancellationToken(canceled: true)));
            AssertUnchanged(dir, before);
            Assert.Empty(Directory.GetDirectories(dir));
        }
        finally { Directory.Delete(dir, true); }
    }

    private static void AssertUnchanged(string dir, Dictionary<string, string> before)
    {
        var now = Directory.GetFiles(dir).ToDictionary(Path.GetFileName, File.ReadAllText);
        Assert.Equal(before.Keys.Order(), now.Keys.Order());
        foreach (var kv in before) Assert.Equal(kv.Value, now[kv.Key]);
    }

    private static string TempDir()
    {
        string dir = Path.Combine(Path.GetTempPath(), "phpvs_appdb_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
