using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Apps;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using Xunit.Abstractions;

namespace PhpVulnScanner.Tests;

/// <summary>Database applicazioni (firme Wappalyzer + inventario NCSC-NL) caricato dalla cartella data/ del repository.</summary>
[Collection("AppDbDefault")]
public class AppDbTests
{
    private static readonly Lazy<TechnologyDatabase> Db = new(() => TechnologyDatabase.Load(Path.Combine(LocalizationTests.RepoRoot(), "data")));
    private readonly ITestOutputHelper _out;
    public AppDbTests(ITestOutputHelper output) => _out = output;

    private static HttpSnapshot Snap(string url = "https://www.example.org/", int status = 200, string body = "", params (string, string)[] headers) =>
        new() { Url = url, Status = status, Reason = "OK", Body = body, BodyLength = body.Length, Headers = headers.Select(h => new KeyValuePair<string, string>(h.Item1, h.Item2)).ToList() };

    private static TechMatch? Find(IReadOnlyList<TechMatch> m, string name) => m.FirstOrDefault(x => x.Name == name);

    // ---------- caricamento ----------

    [Fact]
    public void Load_ReadsAllFiles_AndVersion()
    {
        var db = Db.Value;
        Assert.True(db.Count > 7000, $"tecnologie: {db.Count}");
        Assert.Contains("webappanalyzer", db.DataVersion);
        Assert.Contains("ncsc-nl/php2shell", db.DataVersion);
        Assert.Equal("CMS", db.CategoryName(1));
        Assert.Equal("Message boards", db.CategoryName(2));
        Assert.True(db.Inventory.Count > 700, $"pacchetti NCSC: {db.Inventory.Count}");
        Assert.True(db.Inventory.VexCount >= db.Inventory.Count, $"VEX: {db.Inventory.VexCount}");
        Assert.True(db.ImpliesPhp("PHP"));
        Assert.True(db.ImpliesPhp("WordPress"));
        Assert.True(db.ImpliesPhp("WooCommerce"), "WooCommerce → WordPress → PHP (transitivo)");
        Assert.False(db.ImpliesPhp("IIS"));
    }

    [Fact]
    public void TryLoad_ReturnsNull_WhenFolderMissing()
    {
        Assert.Null(TechnologyDatabase.TryLoad(Path.Combine(Path.GetTempPath(), "phpvs_nonexistent_" + Guid.NewGuid().ToString("N"))));
        Assert.Throws<DirectoryNotFoundException>(() => TechnologyDatabase.Load(Path.Combine(Path.GetTempPath(), "phpvs_nonexistent_" + Guid.NewGuid().ToString("N"))));
    }

    [Fact]
    public void AllPatterns_Compile_WithFewInvalid()
    {
        var db = Db.Value;
        int invalid = db.CompileAll();
        _out.WriteLine($"pattern: {db.PatternCount}, non validi in .NET: {invalid}");
        Assert.True(db.PatternCount > 8000);
        Assert.True(invalid < db.PatternCount / 100, $"troppi pattern non validi: {invalid}");
    }

    // ---------- conversione dei pattern ----------

    [Fact]
    public void Pattern_SplitsVersionAndConfidence()
    {
        var p = TechnologyDatabase.SigPattern.Parse(@"^WordPress(?: ([\d.]+))?\;version:\1");
        Assert.Equal(@"^WordPress(?: ([\d.]+))?", p.Source);
        Assert.Equal(@"\1", p.VersionExpr);
        Assert.Equal(100, p.Confidence);
        Assert.Equal("wordpress", p.Literal);

        var c = TechnologyDatabase.SigPattern.Parse(@"<div class=""pill\;confidence:50");
        Assert.Equal(50, c.Confidence);
        Assert.Equal("", c.VersionExpr);

        var presence = TechnologyDatabase.SigPattern.Parse("");
        Assert.True(presence.Presence);
        Assert.True(presence.TryMatch(Db.Value, "qualsiasi", null, out _, out _));
    }

    [Fact]
    public void Version_BackReference_AndTernary()
    {
        var m = Regex.Match("WordPress 6.5.2", @"^WordPress(?: ([\d.]+))?");
        Assert.Equal("6.5.2", TechnologyDatabase.SigPattern.ResolveVersion(@"\1", m));
        var none = Regex.Match("WordPress", @"^WordPress(?: ([\d.]+))?");
        Assert.Equal("", TechnologyDatabase.SigPattern.ResolveVersion(@"\1", none));

        // ternario Wappalyzer: \1?a:b → a se il gruppo è presente, altrimenti b; a e b possono contenere \1
        var withGroup = Regex.Match("jquery-3.6.0.min.js", @"jquery-([\d.]+)(\.min)?\.js");
        Assert.Equal("3.6.0", TechnologyDatabase.SigPattern.ResolveVersion(@"\1?\1:", withGroup));
        Assert.Equal("Next", TechnologyDatabase.SigPattern.ResolveVersion(@"\2?Next:", withGroup));
        var noMin = Regex.Match("jquery-3.6.0.js", @"jquery-([\d.]+)(\.min)?\.js");
        Assert.Equal("", TechnologyDatabase.SigPattern.ResolveVersion(@"\2?Next:", noMin));
        Assert.Equal("1 (Community)", TechnologyDatabase.SigPattern.ResolveVersion(@"\2?1 (Enterprise):1 (Community)", noMin));
        Assert.Equal("1 (Enterprise)", TechnologyDatabase.SigPattern.ResolveVersion(@"\2?1 (Enterprise):1 (Community)", withGroup));
    }

    [Fact]
    public void LiteralHint_FindsMandatorySubstring()
    {
        Assert.Equal("<link rel=", TechnologyDatabase.SigPattern.LiteralHint(@"<link rel=[""']stylesheet[""'] [^>]+/wp-(?:content|includes)/"));
        Assert.Equal("wordpress", TechnologyDatabase.SigPattern.LiteralHint(@"^WordPress(?: ([\d.]+))?"));
        Assert.Null(TechnologyDatabase.SigPattern.LiteralHint(@"(?: \| phpMyAdmin ([\d.]+)<\/title>|PMA_sendHeaderLocation\()"));   // tutto dentro un gruppo con alternative: nessun letterale obbligatorio
        Assert.Null(TechnologyDatabase.SigPattern.LiteralHint(@"foo|bar"));
        Assert.Null(TechnologyDatabase.SigPattern.LiteralHint(@"abc?d"));   // "ab" è troppo corto (< 3): nessun prefiltro
        Assert.Equal("powered by <a", TechnologyDatabase.SigPattern.LiteralHint(@"Powered by <a[^>]+phpBB"));
        Assert.Equal("matomo.js", TechnologyDatabase.SigPattern.LiteralHint(@"matomo\.js$"));
        Assert.Equal("php", TechnologyDatabase.SigPattern.LiteralHint(@"php/?([\d.]+)?"));
    }

    // ---------- riconoscimento per campo ----------

    [Fact]
    public void Header_XPoweredBy_GivesPhpWithVersion()
    {
        var m = Db.Value.Match([Snap(headers: [("X-Powered-By", "PHP/8.1.2"), ("Server", "nginx")])], null);
        var php = Find(m, "PHP");
        Assert.NotNull(php);
        Assert.Equal("8.1.2", php.Version);
        Assert.True(php.ImpliesPhp);
        Assert.False(php.Implied);
        Assert.Contains("X-Powered-By", php.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(Find(m, "Nginx"));
    }

    [Fact]
    public void Cookies_WordPressAndLaravel_ImplyPhp()
    {
        // il cookie del plugin WPML (requires WordPress) porta a WordPress e, per implicazione, a PHP
        var m = Db.Value.Match([Snap(headers: [("Set-Cookie", "wp-wpml_current_language=it; Path=/; HttpOnly")])], null);
        Assert.NotNull(Find(m, "WPML"));
        var wp = Find(m, "WordPress");
        Assert.NotNull(wp);
        Assert.True(wp.ImpliesPhp);
        Assert.True(wp.Implied);
        Assert.Equal("richiesto da WPML", wp.Evidence);
        Assert.NotNull(Find(m, "PHP"));
        Assert.True(Find(m, "PHP")!.Implied);

        m = Db.Value.Match([Snap(headers: [("Set-Cookie", "PHPSESSID=0123456789abcdef; path=/")])], null);
        Assert.NotNull(Find(m, "PHP"));
        Assert.False(Find(m, "PHP")!.Implied);
        Assert.Equal("cookie PHPSESSID", Find(m, "PHP")!.Evidence);

        m = Db.Value.Match([Snap(headers: [("Set-Cookie", "laravel_session=eyJpdiI6; path=/; httponly; samesite=lax")])], null);
        var laravel = Find(m, "Laravel");
        Assert.NotNull(laravel);
        Assert.True(laravel.ImpliesPhp);
        Assert.Contains("laravel_session", laravel.Evidence);
    }

    [Fact]
    public void Meta_Generator_WordPressWithVersion()
    {
        var body = "<html><head><meta name=\"generator\" content=\"WordPress 6.5\" /><title>x</title></head><body></body></html>";
        var m = Db.Value.Match([Snap(body: body)], null);
        var wp = Find(m, "WordPress");
        Assert.NotNull(wp);
        Assert.Equal("6.5", wp.Version);
        Assert.Equal(100, wp.Confidence);
    }

    [Fact]
    public void ScriptSrc_WpIncludes_IsWordPress()
    {
        var body = "<html><head><script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1' id='jquery-core-js'></script></head></html>";
        var m = Db.Value.Match([Snap(body: body)], null);
        var wp = Find(m, "WordPress");
        Assert.NotNull(wp);
        Assert.StartsWith("script", wp.Evidence);
        Assert.NotNull(Find(m, "jQuery"));
    }

    public static IEnumerable<object[]> HandApps() =>
    [
        ["WordPress", "<link rel=\"stylesheet\" href=\"https://www.example.org/wp-content/themes/x/style.css\">"],
        ["Joomla", "<meta name=\"generator\" content=\"Joomla! - Open Source Content Management\">"],
        ["Drupal", "<meta name=\"generator\" content=\"Drupal 10 (https://www.drupal.org)\">"],
        ["phpMyAdmin", "<title>127.0.0.1 / localhost | phpMyAdmin 5.2.1</title>"],
        ["Nextcloud", "SET-COOKIE:__Host-nc_sameSiteCookiestrict=true; path=/; httponly; secure; samesite=strict"],
        ["Moodle", "<meta name=\"keywords\" content=\"moodle, Corso: Esempio\">"],
        ["TYPO3 CMS", "<meta name=\"generator\" content=\"TYPO3 CMS\">"],
        ["MediaWiki", "<meta name=\"generator\" content=\"MediaWiki 1.41.0\">"],
        ["RoundCube", "<title>RoundCube Webmail :: Welcome</title>"],
        ["phpBB", "<div class=\"copyright\">Powered by <a href=\"https://www.phpbb.com/\">phpBB</a>&reg; Forum Software</div>"],
        ["MyBB", "SET-COOKIE:mybb[lastvisit]=1700000000; path=/; httponly"],
        ["Matomo Analytics", "<script type=\"text/javascript\" src=\"//stats.example.org/matomo.js\" async defer></script>"],
    ];

    [Theory]
    [MemberData(nameof(HandApps))]
    public void HandSignatureApps_AreInDatabase_AndMatchSnippet(string name, string snippet)
    {
        var db = Db.Value;
        Assert.True(db.Contains(name), $"{name} assente dal database");
        var snap = snippet.StartsWith("SET-COOKIE:", StringComparison.Ordinal)
            ? Snap(body: "<html></html>", headers: [("Set-Cookie", snippet["SET-COOKIE:".Length..])])
            : Snap(body: "<html><head>" + snippet + "</head><body></body></html>");
        var m = db.Match([snap], null);
        var hit = Find(m, name);
        Assert.True(hit != null, $"{name} non riconosciuto: {string.Join(", ", m.Select(x => x.Name))}");
        Assert.True(hit.ImpliesPhp, $"{name} non implica PHP");
        Assert.False(hit.Implied);
        Assert.NotNull(Find(m, "PHP"));
    }

    [Fact]
    public void Versions_FromGenerator_ForDrupalMediaWikiPhpMyAdmin()
    {
        Assert.Equal("10", Find(Db.Value.Match([Snap(body: "<meta name=\"generator\" content=\"Drupal 10 (https://www.drupal.org)\">")], null), "Drupal")!.Version);
        Assert.Equal("1.41.0", Find(Db.Value.Match([Snap(body: "<meta name=\"generator\" content=\"MediaWiki 1.41.0\">")], null), "MediaWiki")!.Version);
        Assert.Equal("5.2.1", Find(Db.Value.Match([Snap(body: "<title>x | phpMyAdmin 5.2.1</title>")], null), "phpMyAdmin")!.Version);
    }

    [Fact]
    public void Implies_AreTransitive_WithEvidence()
    {
        var body = "<meta name=\"generator\" content=\"WooCommerce 8.9.1\"><link rel=\"stylesheet\" href=\"/wp-content/plugins/woocommerce/assets/css/woocommerce.css\">";
        var m = Db.Value.Match([Snap(body: body)], null);
        var woo = Find(m, "WooCommerce");
        Assert.NotNull(woo);
        Assert.Equal("8.9.1", woo.Version);
        Assert.True(woo.ImpliesPhp);
        var php = Find(m, "PHP");
        Assert.NotNull(php);
        Assert.True(php.Implied);
        Assert.Equal("implicato da WordPress", php.Evidence);
        Assert.NotNull(Find(m, "MySQL"));
    }

    [Fact]
    public void Excludes_RemoveTechnology()
    {
        // Backdrop (fork di Drupal) invia lo stesso Expires "19 Nov 1978" di Drupal: Drupal viene riconosciuto ma Backdrop lo esclude
        var m = Db.Value.Match([Snap(body: "<meta name=\"generator\" content=\"Backdrop CMS 1.27\">", headers: [("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")])], null);
        var backdrop = Find(m, "Backdrop");
        Assert.NotNull(backdrop);
        Assert.Equal("1.27", backdrop.Version);
        Assert.True(backdrop.ImpliesPhp);
        Assert.Null(Find(m, "Drupal"));
        // senza Backdrop, l'intestazione Expires basta per Drupal
        m = Db.Value.Match([Snap(headers: [("Expires", "Sun, 19 Nov 1978 05:00:00 GMT")])], null);
        Assert.NotNull(Find(m, "Drupal"));
        // HTTP/3 esclude HTTP/2 quando Alt-Svc annuncia entrambi
        m = Db.Value.Match([Snap(headers: [("Alt-Svc", "h3=\":443\"; ma=86400, h2=\":443\"; ma=86400")])], null);
        Assert.NotNull(Find(m, "HTTP/3"));
        Assert.Null(Find(m, "HTTP/2"));
    }

    [Fact]
    public void Requires_ActsAsImplication()
    {
        // "WooCommerce" richiede WordPress: con il solo cookie woocommerce_recently_viewed WordPress (e quindi PHP) sono dedotti
        var m = Db.Value.Match([Snap(headers: [("Set-Cookie", "woocommerce_recently_viewed=1; path=/")])], null);
        Assert.NotNull(Find(m, "WooCommerce"));
        Assert.True(Find(m, "WooCommerce")!.ImpliesPhp);
        Assert.Equal("richiesto da WooCommerce", Find(m, "WordPress")!.Evidence);
        Assert.NotNull(Find(m, "PHP"));
    }

    [Fact]
    public void NonPhp_IIS_DoesNotImplyPhp()
    {
        var m = Db.Value.Match([Snap(headers: [("Server", "Microsoft-IIS/10.0"), ("X-Powered-By", "ASP.NET")])], null);
        var iis = Find(m, "IIS");
        Assert.NotNull(iis);
        Assert.Equal("10.0", iis.Version);
        Assert.False(iis.ImpliesPhp);
        Assert.NotNull(Find(m, "Microsoft ASP.NET"));
        Assert.DoesNotContain(m, x => x.ImpliesPhp);
        Assert.NotNull(Find(m, "Windows Server"));
    }

    [Fact]
    public void Url_OnlyBaseRequestCounts()
    {
        // il percorso /index.php sondato dallo scanner su un server non PHP non deve "dimostrare" PHP
        var m = Db.Value.Match([Snap(url: "https://www.example.org/", headers: [("Server", "nginx")]), Snap(url: "https://www.example.org/index.php", status: 404)], null);
        Assert.Null(Find(m, "PHP"));
        m = Db.Value.Match([Snap(url: "https://www.example.org/app/index.php")], null);
        Assert.NotNull(Find(m, "PHP"));
    }

    // ---------- NCSC-NL ----------

    [Fact]
    public void Ncsc_FindWordPress_HasVexAndSummary()
    {
        var inv = Db.Value.Inventory;
        var wp = inv.Find("WordPress");
        Assert.NotNull(wp);
        Assert.Equal("WordPress", wp.Name);
        Assert.True(wp.Vex.ContainsKey("CVE-2026-109618"));
        Assert.True(wp.Vex.ContainsKey("CVE-2026-109619"));
        Assert.Contains(wp.Vex["CVE-2026-109618"].Status, new[] { "Affected", "Fixed", "NotAffected", "UnderInvestigation" });
        Assert.StartsWith("https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_w.md", wp.Reference);
        string s = inv.Summary(wp);
        _out.WriteLine(s);
        // WordPress è "Affected" su entrambe le CVE senza versione corretta: la sintesi lo dice in chiaro invece di ripetere le due CVE
        Assert.True(NcscInventory.AllAffectedNoFix(wp));
        Assert.Equal("NCSC-NL: prodotto affetto in quanto dipende dalla versione di PHP (nessuna versione del prodotto corregge da sola)", s);
        Assert.Equal("affetto (dipende dalla versione di PHP)", inv.ShortStatus(wp));
    }

    [Fact]
    public void Ncsc_Find_DoesNotMapRuntimeOrExtensionsToPackages()
    {
        var inv = Db.Value.Inventory;
        // "PHP" non è "PHP DBA" né "PHP CLI": le parole aggiunte dal pacchetto devono essere generiche o versioni
        Assert.Null(inv.Find("PHP"));
        Assert.Null(inv.Find("PHP 8.3.36"));
        // l'alias "openssl" dell'estensione PHP non deve catturare l'OpenSSL del banner Apache
        Assert.Null(inv.Find("OpenSSL"));
        Assert.Null(inv.Find("MySQL"));
        Assert.Null(inv.Find("Apache HTTP Server"));
        Assert.Null(inv.Find("Nginx"));
        Assert.Null(inv.Find("Java"));
        // le voci legittime restano raggiungibili
        Assert.Equal("Plesk for Linux", inv.Find("Plesk")!.Name);
        Assert.Equal("Symfony framework", inv.Find("Symfony")!.Name);
        Assert.Equal("Shopware 5", inv.Find("Shopware")!.Name);
        Assert.Equal("MyBB", inv.Find("MyBulletinBoard")!.Name);   // alias con maiuscole
        Assert.False(NcscInventory.AliasIsDistinctive("openssl"));
        Assert.True(NcscInventory.AliasIsDistinctive("ext/openssl"));
        Assert.True(NcscInventory.AliasIsDistinctive("Laravel 13"));
    }

    [Fact]
    public void Ncsc_ShortStatus_AndVersionCheck()
    {
        var inv = Db.Value.Inventory;
        var arch = inv.Find("Arch Linux Extra PHP package")!;
        Assert.Equal("corretto in 8.5.12-1", inv.ShortStatus(arch));
        Assert.Equal("8.5.12 ≥ corretto in 8.5.12-1", NcscInventory.VersionCheck("8.5.12", arch));
        Assert.Equal("8.5.11 < corretto in 8.5.12-1", NcscInventory.VersionCheck("8.5.11", arch));
        Assert.Equal("", NcscInventory.VersionCheck("", arch));
        Assert.Equal("", NcscInventory.VersionCheck("6.4.2", inv.Find("WordPress")!));   // nessuna versione corretta: non confrontabile

        var mixed = new NcscPackage("X", [], "", "", "", new Dictionary<string, NcscVex>
        {
            ["CVE-2026-109618"] = new("Fixed", "6.4.2", "", ""),
            ["CVE-2026-109619"] = new("UnderInvestigation", "", "", ""),
        });
        Assert.Equal("CVE-2026-109618 corretto in 6.4.2; CVE-2026-109619 in esame", inv.ShortStatus(mixed));
        Assert.Equal("6.4.1 < corretto in 6.4.2", NcscInventory.VersionCheck("6.4.1", mixed));
        Assert.Equal("6.4.2-1ubuntu ≥ corretto in 6.4.2", NcscInventory.VersionCheck("6.4.2-1ubuntu", mixed));
        Assert.Equal("6.5 ≥ corretto in 6.4.2", NcscInventory.VersionCheck("6.5", mixed));
        Assert.Equal("6.4 < corretto in 6.4.2", NcscInventory.VersionCheck("6.4", mixed));
        Assert.Equal("", NcscInventory.VersionCheck("beta", mixed));

        // più rami: si confronta con quello della stessa serie
        var multi = new NcscPackage("Y", [], "", "", "", new Dictionary<string, NcscVex> { ["CVE-2026-109618"] = new("Fixed", "8.5.12, 8.4.27, 8.3.36, 8.2.35", "", ""), ["CVE-2026-109619"] = new("Fixed", "8.5.12, 8.4.27, 8.3.36, 8.2.35", "", "") });
        Assert.Equal("corretto in 8.5.12, 8.4.27, 8.3.36, 8.2.35", inv.ShortStatus(multi));
        Assert.Equal("8.3.35 < corretto in 8.3.36", NcscInventory.VersionCheck("8.3.35", multi));
        Assert.Equal("8.3.36 ≥ corretto in 8.3.36", NcscInventory.VersionCheck("8.3.36", multi));
        Assert.Equal("8.1.33 < corretto in 8.2.35", NcscInventory.VersionCheck("8.1.33", multi));   // ramo assente: la più bassa
        Assert.Equal("v8.4.27 ≥ corretto in 8.4.27", NcscInventory.VersionCheck("v8.4.27", multi));

        Assert.Equal(0, NcscInventory.CompareVersions("8.3.36", "8.3.36-1"));
        Assert.True(NcscInventory.CompareVersions("8.3.9", "8.3.10") < 0);
        Assert.True(NcscInventory.CompareVersions("10", "9.9.9") > 0);

        var none = new NcscPackage("Z", [], "", "", "", new Dictionary<string, NcscVex>());
        Assert.Equal("in inventario, nessuna asserzione VEX", inv.ShortStatus(none));
        Assert.Equal("NCSC-NL: Z in inventario, nessuna asserzione VEX", inv.Summary(none));
        var ui = new NcscPackage("U", [], "", "", "", new Dictionary<string, NcscVex> { ["CVE-2026-109618"] = new("UnderInvestigation", "", "", ""), ["CVE-2026-109619"] = new("UnderInvestigation", "", "", "") });
        Assert.Equal("in esame", inv.ShortStatus(ui));
        Assert.Equal("NCSC-NL: CVE-2026-109618 in esame; CVE-2026-109619 in esame", inv.Summary(ui));
    }

    [Fact]
    public void Ncsc_Find_IsTolerant()
    {
        var inv = Db.Value.Inventory;
        Assert.Equal("phpMyAdmin", inv.Find("phpmyadmin")!.Name);
        Assert.Equal("phpMyAdmin", inv.Find("phpmyadmin/phpmyadmin")!.Name);   // alias
        Assert.Equal("Craft CMS", inv.Find("CraftCMS")!.Name);
        Assert.Equal("Nextcloud Server", inv.Find("Nextcloud")!.Name);
        Assert.Equal("Roundcube Webmail", inv.Find("RoundCube")!.Name);
        Assert.Equal("Grav CMS", inv.Find("Grav")!.Name);
        Assert.Equal("Joomla 6.x", inv.Find("Joomla")!.Name);
        Assert.Equal("TYPO3 13.4", inv.Find("TYPO3 CMS")!.Name);
        Assert.Equal("TYPO3 13.4", inv.Find("TYPO3")!.Name);
        Assert.Equal("Matomo On-Premise", inv.Find("Matomo Analytics")!.Name);
        Assert.Equal("Zabbix web frontend", inv.Find("Zabbix")!.Name);
        Assert.Equal("CakePHP framework", inv.Find("CakePHP")!.Name);
        Assert.Null(inv.Find("Liferay"));
        Assert.Null(inv.Find("IIS"));
        Assert.Null(inv.Find("Microsoft IIS"));
        Assert.Null(inv.Find(""));
    }

    [Fact]
    public void Ncsc_Summary_FixedWithVersion()
    {
        var inv = Db.Value.Inventory;
        var arch = inv.Find("Arch Linux Extra PHP package");
        Assert.NotNull(arch);
        Assert.Equal("Fixed", arch.Vex["CVE-2026-109618"].Status);
        Assert.Equal("8.5.12-1", arch.Vex["CVE-2026-109618"].FixedVersion);
        Assert.Equal("NCSC-NL: CVE-2026-109618 corretto in 8.5.12-1; CVE-2026-109619 corretto in 8.5.12-1", inv.Summary(arch));

        var fake = new NcscPackage("X", [], "", "", "", new Dictionary<string, NcscVex>
        {
            ["CVE-2026-109618"] = new("Fixed", "6.4.2", "", ""),
            ["CVE-2026-109619"] = new("UnderInvestigation", "", "", ""),
        });
        Assert.Equal("NCSC-NL: CVE-2026-109618 corretto in 6.4.2; CVE-2026-109619 in esame", inv.Summary(fake));
        var fake2 = new NcscPackage("Y", [], "", "", "", new Dictionary<string, NcscVex> { ["CVE-2026-109618"] = new("Affected", "", "", ""), ["CVE-2026-109619"] = new("NotAffected", "", "", "") });
        Assert.Equal("NCSC-NL: CVE-2026-109618 affetto; CVE-2026-109619 non affetto", inv.Summary(fake2));
    }

    // ---------- prestazioni ----------

    [Fact]
    public void Match_On64KiBBody_IsFast()
    {
        var db = Db.Value;
        var sb = new StringBuilder("<!DOCTYPE html><html lang=\"it\"><head><meta charset=\"utf-8\"><meta name=\"generator\" content=\"WordPress 6.5\"><title>Esempio</title>");
        sb.Append("<link rel=\"stylesheet\" href=\"/wp-content/themes/twentytwentyfour/style.css\"><script src=\"/wp-includes/js/jquery/jquery.min.js?ver=3.7.1\"></script>");
        var rnd = new Random(42);
        while (sb.Length < 64 * 1024 - 200)
        {
            sb.Append("<div class=\"entry-content c").Append(rnd.Next(1000)).Append("\"><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit ").Append(rnd.Next());
            sb.Append("</p><a href=\"/articolo-").Append(rnd.Next(10000)).Append("/\">link</a><img src=\"/wp-content/uploads/2026/10/img").Append(rnd.Next(999)).Append(".jpg\" alt=\"\"></div>\n");
        }
        sb.Append("</body></html>");
        var snaps = new List<HttpSnapshot>
        {
            Snap(body: sb.ToString(), headers: [("Server", "Apache/2.4.62 (Debian)"), ("X-Powered-By", "PHP/8.2.26"), ("Set-Cookie", "PHPSESSID=abc; path=/"), ("Link", "<https://www.example.org/wp-json/>; rel=\"https://api.w.org/\""), ("Content-Type", "text/html; charset=UTF-8")]),
            Snap(url: "https://www.example.org/index.php", status: 404, body: "<html><body><h1>Not Found</h1></body></html>", headers: [("Server", "Apache/2.4.62 (Debian)")]),
        };
        db.CompileAll();
        var warm = db.Match(snaps, "R3");   // riscaldamento (compilazione pigra già fatta, cache JIT)
        Assert.NotNull(Find(warm, "WordPress"));
        var sw = Stopwatch.StartNew();
        const int n = 5;
        IReadOnlyList<TechMatch> m = [];
        for (int i = 0; i < n; i++) m = db.Match(snaps, "R3");
        sw.Stop();
        double perCall = sw.Elapsed.TotalMilliseconds / n;
        _out.WriteLine($"Match su {sb.Length / 1024} KiB: {perCall:F1} ms per chiamata, {m.Count} tecnologie: {string.Join(", ", m.Select(x => x.Name + (x.Version.Length > 0 ? " " + x.Version : "")))}");
        Assert.True(perCall < 200, $"troppo lento: {perCall:F1} ms");
        Assert.Equal("8.2.26", Find(m, "PHP")!.Version);
        Assert.Equal("6.5", Find(m, "WordPress")!.Version);
    }

    // ---------- integrazione nel risultato ----------

    [Fact]
    public void ApplyTo_FillsTechnologiesApplicationAndNcsc()
    {
        var old = TechnologyDatabase.Default;
        try
        {
            TechnologyDatabase.Default = Db.Value;
            var r = new ScanResult { Host = "192.0.2.10", Port = 443, HttpReachable = true, ServerHeader = "nginx" };
            var body = "<html><head><meta name=\"generator\" content=\"WordPress 6.5\"><link rel=\"stylesheet\" href=\"/wp-content/themes/x/style.css\"></head><body></body></html>";
            TechnologyDatabase.ApplyTo(r, [Snap(body: body, headers: [("Server", "nginx")])]);
            Assert.Equal("WordPress", r.Application);
            Assert.Equal("6.5", r.ApplicationVersion);
            Assert.StartsWith("database firme: WordPress (", r.ApplicationEvidence);
            Assert.Contains("software_list_w.md", r.ApplicationReference);
            Assert.True(r.PhpDetected);
            Assert.Contains("tecnologia PHP riconosciuta: WordPress", r.PhpEvidence);
            Assert.Contains("WordPress 6.5", r.Technologies);
            Assert.Equal("WordPress 6.5", r.Technologies[0]);
            Assert.True(r.Technologies.Count <= 12);
            Assert.Equal("NCSC-NL: prodotto affetto in quanto dipende dalla versione di PHP (nessuna versione del prodotto corregge da sola)", r.NcscStatus);
            Assert.Contains("software_list_w.md", r.NcscReference);
            Assert.Equal("", r.AppVersionCheck);   // WordPress: nessuna versione del prodotto da confrontare
            Assert.Contains("WordPress: affetto (dipende dalla versione di PHP)", r.TechnologyStatuses);
            Assert.DoesNotContain(r.TechnologyStatuses, t => t.StartsWith("PHP:"));   // il runtime non è un pacchetto dell'inventario
            Assert.DoesNotContain(r.TechnologyStatuses, t => t.StartsWith("MySQL:"));
            Assert.True(r.TechnologyStatuses.Count <= 12);

            // applicazione già riconosciuta dalle firme manuali: non viene sovrascritta, ma riceve versione e stato NCSC
            var h = new ScanResult { Host = "192.0.2.11", Port = 443, HttpReachable = true, Application = "Drupal", ApplicationEvidence = "X-Generator", ApplicationReference = "x", PhpDetected = true, PhpEvidence = "X-Powered-By" };
            TechnologyDatabase.ApplyTo(h, [Snap(body: "<meta name=\"generator\" content=\"Drupal 10 (https://www.drupal.org)\">", headers: [("X-Generator", "Drupal 10 (https://www.drupal.org)")])]);
            Assert.Equal("Drupal", h.Application);
            Assert.Equal("x", h.ApplicationReference);
            Assert.Equal("10", h.ApplicationVersion);
            Assert.Equal("X-Powered-By", h.PhpEvidence);
            Assert.StartsWith("NCSC-NL:", h.NcscStatus);

            // server non PHP: niente applicazione, PHP non segnalato
            var n = new ScanResult { Host = "192.0.2.12", Port = 80, HttpReachable = true };
            TechnologyDatabase.ApplyTo(n, [Snap(headers: [("Server", "Microsoft-IIS/10.0"), ("X-Powered-By", "ASP.NET")])]);
            Assert.Equal("", n.Application);
            Assert.False(n.PhpDetected);
            Assert.Contains("IIS 10.0", n.Technologies);
            Assert.Equal("", n.NcscStatus);
            Assert.Empty(n.TechnologyStatuses);
            Assert.Equal("", n.AppVersionCheck);

            // applicazione con versione e VEX "Fixed" con versione corretta: confronto compilato
            var old2 = TechnologyDatabase.Default;
            var fixedInv = new NcscInventory([new NcscPackage("WordPress", [], "", "", "https://example.org/w", new Dictionary<string, NcscVex> { ["CVE-2026-109618"] = new("Fixed", "6.6", "", ""), ["CVE-2026-109619"] = new("Fixed", "6.6", "", "") })]);
            var v = new ScanResult { Host = "192.0.2.15", Port = 443, HttpReachable = true };
            Db.Value.Apply(v, [Snap(body: body)]);          // il database reale: WordPress 6.5 riconosciuto
            Assert.Equal("6.5", v.ApplicationVersion);
            Assert.Equal("6.5 < corretto in 6.6", NcscInventory.VersionCheck(v.ApplicationVersion, fixedInv.Find("WordPress")!));
            Assert.Equal("corretto in 6.6", fixedInv.ShortStatus(fixedInv.Find("WordPress")!));
            TechnologyDatabase.Default = old2;

            // nessuna risposta: nessun effetto
            var e = new ScanResult { Host = "192.0.2.13", Port = 80 };
            TechnologyDatabase.ApplyTo(e, [new HttpSnapshot { Status = 0, Error = "timeout" }]);
            Assert.Empty(e.Technologies);

            TechnologyDatabase.Default = null;
            var z = new ScanResult { Host = "192.0.2.14", Port = 80, HttpReachable = true };
            TechnologyDatabase.ApplyTo(z, [Snap(body: body)]);
            Assert.Empty(z.Technologies);
        }
        finally { TechnologyDatabase.Default = old; }
    }
}
