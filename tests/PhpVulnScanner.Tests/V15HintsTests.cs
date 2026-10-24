using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;

namespace PhpVulnScanner.Tests;

/// <summary>v1.5: indizi passivi di PHP (PhpHints), impostazioni da phpinfo (PhpInfoParser), indice di loquacità (Verbosity).</summary>
public class V15HintsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v15h_" + Guid.NewGuid().ToString("N"));
    public V15HintsTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private static ScanResult R(params HttpSnapshot[] snaps)
    {
        var r = new ScanResult { Host = "192.0.2.1", Port = 443, Scheme = "https", HttpReachable = true };
        r.Requests.AddRange(snaps);
        return r;
    }

    private static HttpSnapshot Snap(string path = "/", int status = 200, string body = "<html><body>ok</body></html>", params (string, string)[] headers) => new()
    {
        Method = "GET", Url = "https://192.0.2.1" + path, Status = status, Reason = "OK", Body = body, BodyLength = body.Length,
        Headers = headers.Select(h => new KeyValuePair<string, string>(h.Item1, h.Item2)).ToList(),
    };

    private static int Weight(string hint) => int.Parse(hint.Split(':')[0]);

    // ---------- PhpHints ----------

    [Fact]
    public void Hints_FixedExpiresHeader_IsStrong()
    {
        var r = R(Snap(headers: [("Expires", PhpHints.SessionExpires)]));
        PhpHints.Compute(r);
        var h = Assert.Single(r.PhpHints);
        Assert.Equal(3, Weight(h));
        Assert.Contains("session_start()", h);
        Assert.Equal(3, r.PhpHintScore);
        Assert.Equal("maybe", r.PhpPresence);
    }

    [Fact]
    public void Hints_SessionIdFormat_26Chars_IsStrong_32HexIsNot()
    {
        var r = R(Snap(headers: [("Set-Cookie", "sess=abcdefghij0123456789klmnop; path=/; HttpOnly")]));
        PhpHints.Compute(r);
        Assert.Contains(r.PhpHints, h => Weight(h) == 3 && h.Contains("nome sess"));

        // 32 esadecimali con nome generico: token troppo comune, non conta
        Assert.False(PhpHints.LooksLikePhpSid("token", "0123456789abcdef0123456789abcdef"));
        // 32 caratteri a 6 bit (maiuscole, virgola, trattino) con nome sconosciuto: conta
        Assert.True(PhpHints.LooksLikePhpSid("sid", "aB3,xY-9kLmN0pQrStUvWxYz01234567"));
        // ma non con un nome di piattaforma non PHP
        Assert.False(PhpHints.LooksLikePhpSid("JSESSIONID", "aB3,xY-9kLmN0pQrStUvWxYz01234567"));
        Assert.False(PhpHints.LooksLikePhpSid("x", "abcdefghij0123456789klmnopq"));   // 27 caratteri
        Assert.False(PhpHints.LooksLikePhpSid("x", "abcdefghij0123456789klmnwx"));    // 'w' e 'x' fuori da [0-9a-v]
    }

    [Theory]
    [InlineData("laravel_session=eyJpdiI6; path=/", "Laravel")]
    [InlineData("ci_session=abc; path=/", "CodeIgniter")]
    [InlineData("SESS0123456789abcdef0123456789abcdef=xyz; path=/", "Drupal")]
    [InlineData("SSESSdeadbeef=xyz; secure", "Drupal")]
    [InlineData("MoodleSession=abc", "Moodle")]
    [InlineData("fe_typo_user=abc", "TYPO3")]
    [InlineData("phpbb3_abc_sid=1", "phpBB")]
    [InlineData("OCSESSID=abc", "OpenCart")]
    [InlineData("PrestaShop-abc=def", "PrestaShop")]
    [InlineData("wordpress_test_cookie=WP+Cookie+check", "WordPress")]
    [InlineData("wp-settings-1=abc", "WordPress")]
    [InlineData("PHPSESSID=abc", "PHPSESSID")]
    [InlineData("CAKEPHP=abc", "CakePHP")]
    [InlineData("craftsessionid=abc", "Craft CMS")]
    [InlineData("MYBBUSER=abc", "MyBB")]
    [InlineData("0123456789abcdef0123456789abcdef=xyz; path=/", "Joomla")]
    public void Hints_FrameworkCookies_AreMedium(string setCookie, string label)
    {
        var r = R(Snap(headers: [("Set-Cookie", setCookie)]));
        PhpHints.Compute(r);
        Assert.Contains(r.PhpHints, h => Weight(h) == 2 && h.Contains("cookie di framework PHP: " + label));
        Assert.Equal("maybe", r.PhpPresence);
    }

    [Fact]
    public void Hints_UnknownCookie_GivesNothing()
    {
        var r = R(Snap(headers: [("Set-Cookie", "JSESSIONID=1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D; Path=/")]));
        PhpHints.Compute(r);
        Assert.Empty(r.PhpHints);
        Assert.Equal(0, r.PhpHintScore);
        Assert.Equal("no", r.PhpPresence);
        Assert.DoesNotContain(r.Tests, t => t.Id == "L1-HINTS");
    }

    [Fact]
    public void Hints_ApplicationHeaders_AreMedium_OncePerHeader()
    {
        var r = R(
            Snap(headers: [("X-Pingback", "https://192.0.2.1/xmlrpc.php"), ("Link", "<https://192.0.2.1/wp-json/>; rel=\"https://api.w.org/\""), ("X-Generator", "Drupal 10 (https://www.drupal.org)")]),
            Snap("/index.php", headers: [("X-Pingback", "https://192.0.2.1/xmlrpc.php"), ("Link", "<https://x/>; rel=\"preload\"")]));
        PhpHints.Compute(r);
        Assert.Equal(3, r.PhpHints.Count);
        Assert.All(r.PhpHints, h => Assert.Equal(2, Weight(h)));
        Assert.Contains("2: intestazione X-Pingback", r.PhpHints);
        Assert.Contains("2: intestazione Link", r.PhpHints);
        Assert.Contains("2: intestazione X-Generator", r.PhpHints);
        Assert.Equal(6, r.PhpHintScore);
    }

    [Fact]
    public void Hints_PoweredByPhp_CountsOnlyWithoutProof_PleskAlways()
    {
        var r = R(Snap(headers: [("X-Powered-By", "PHP/8.1.2")]));
        PhpHints.Compute(r);
        Assert.Contains(r.PhpHints, h => h.StartsWith("2: intestazione X-Powered-By: PHP/8.1.2"));
        r.PhpDetected = true;
        PhpHints.Compute(r);
        Assert.Empty(r.PhpHints);
        Assert.Equal("yes", r.PhpPresence);

        var p = R(Snap(headers: [("X-Powered-By", "PleskLin")]));
        p.PoweredBy = "PleskLin";
        PhpHints.Compute(p);
        Assert.Contains(p.PhpHints, h => h.StartsWith("2: intestazione X-Powered-By: PleskLin"));
        Assert.Contains(p.PhpHints, h => h == "1: pannello di hosting (Plesk)");
    }

    [Fact]
    public void Hints_BodyPatterns_OnePerPattern_MaxFour()
    {
        string body = "<html><head><link href=\"/wp-content/themes/a/style.css\"><script src=\"/wp-includes/js/jquery.js\"></script></head>" +
                      "<body><form action=\"/login.php\"><a href=\"/index.php/about\">x</a><a href=\"/a.php\">y</a><img src=\"/sites/default/files/x.png\"><a href=\"/typo3conf/x\">z</a></body></html>";
        var r = R(Snap(body: body));
        PhpHints.Compute(r);
        Assert.Equal(4, r.PhpHints.Count);
        Assert.All(r.PhpHints, h => Assert.StartsWith("2: nel corpo: ", h));
        Assert.Contains("2: nel corpo: link a *.php sullo stesso host (3)", r.PhpHints);   // form action + 2 href relativi
        Assert.Contains("2: nel corpo: /wp-content/", r.PhpHints);
        Assert.Equal(8, r.PhpHintScore);
    }

    [Fact]
    public void Hints_PhpLinks_OnlySameHost_SingleLinkIsWeak()
    {
        // 99 pagine su 115 nella /20 linkavano l'index.php del portale centrale: non dice nulla sull'host scansionato
        var other = R(Snap(body: "<a href=\"https://portal.example.org/index.php\">portale</a>"));
        PhpHints.Compute(other);
        Assert.DoesNotContain(other.PhpHints, h => h.Contains("link a *.php"));
        Assert.Equal("no", other.PhpPresence);

        var one = R(Snap(body: "<a href=\"/index.php\">home</a>"));
        PhpHints.Compute(one);
        Assert.Contains("1: nel corpo: link a *.php sullo stesso host (1)", one.PhpHints);
        Assert.Equal("no", one.PhpPresence);   // un solo link non basta da solo

        var abs = R(Snap(body: "<a href=\"https://192.0.2.1/index.php\">a</a><a href=\"https://192.0.2.1/login.php\">b</a>"));
        PhpHints.Compute(abs);
        Assert.Contains("2: nel corpo: link a *.php sullo stesso host (2)", abs.PhpHints);
        Assert.Equal("maybe", abs.PhpPresence);
    }

    [Fact]
    public void Hints_SurfaceProbe_WithoutProof_IsMedium()
    {
        var r = R(Snap());
        r.PhpSurfaceProbe = "Fpm";
        PhpHints.Compute(r);
        Assert.Contains("2: il file .php inesistente è trattato da un handler (Fpm)", r.PhpHints);
        r.PhpDetected = true;
        PhpHints.Compute(r);
        Assert.DoesNotContain(r.PhpHints, h => h.Contains("handler"));
    }

    [Fact]
    public void Hints_Robots_IsWeak()
    {
        var r = R(Snap(), Snap("/robots.txt", body: "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n"));
        PhpHints.Compute(r);
        var h = Assert.Single(r.PhpHints);
        Assert.Equal("1: robots.txt esclude percorsi PHP (/wp-admin/)", h);
        Assert.Equal("no", r.PhpPresence);   // 1 < soglia 2
    }

    [Fact]
    public void Hints_CacheTriplet_AndCharset_OnlyTogether()
    {
        var charsetOnly = R(Snap(headers: [("Content-Type", "text/html; charset=UTF-8"), ("ETag", "\"abc\"")]));
        PhpHints.Compute(charsetOnly);
        Assert.Empty(charsetOnly.PhpHints);

        var triplet = R(Snap(headers: [("Cache-Control", "no-store, no-cache, must-revalidate"), ("Pragma", "no-cache"), ("Content-Type", "text/html; charset=UTF-8")]));
        PhpHints.Compute(triplet);
        Assert.Equal(2, triplet.PhpHints.Count);
        Assert.Contains("1: terna di cache di PHP senza ETag/Last-Modified", triplet.PhpHints);
        Assert.Contains(triplet.PhpHints, h => h.StartsWith("1: Content-Type con la grafia predefinita di PHP"));
        Assert.Equal("maybe", triplet.PhpPresence);

        var withEtag = R(Snap(headers: [("Cache-Control", "no-store, no-cache, must-revalidate"), ("Pragma", "no-cache"), ("ETag", "\"x\"")]));
        PhpHints.Compute(withEtag);
        Assert.Empty(withEtag.PhpHints);
    }

    [Fact]
    public void Hints_HostingPanel_Technologies_Names_AreWeak()
    {
        var r = new ScanResult { Host = "192.0.2.1", Port = 8443, Scheme = "https", HttpReachable = true };
        r.Requests.Add(Snap(headers: [("Server", "nginx")]));
        r.Technologies.Add("WordPress 6.5");
        r.Technologies.Add("jQuery 3.7");
        r.DiscoveredNames.Add("moodle.example.org");
        r.DiscoveredNames.Add("mail.example.org");
        r.Tls = new TlsInfo { Handshake = true, Subject = "wp.example.org", SubjectAltNames = ["wp.example.org", "newport.example.org"] };
        PhpHints.Compute(r);
        Assert.Contains("1: pannello di hosting (porta 8443)", r.PhpHints);
        Assert.Contains("1: tecnologia dell'ecosistema PHP: WordPress 6.5", r.PhpHints);
        Assert.DoesNotContain(r.PhpHints, h => h.Contains("jQuery"));
        var names = Assert.Single(r.PhpHints, h => h.StartsWith("1: nomi che richiamano"));
        Assert.Contains("moodle.example.org", names);
        Assert.Contains("wp.example.org", names);
        Assert.DoesNotContain("newport", names);
        Assert.DoesNotContain("mail.example.org", names);
        Assert.Equal(3, r.PhpHintScore);
    }

    [Fact]
    public void Hints_Presence_Thresholds()
    {
        var none = R(Snap());
        PhpHints.Compute(none);
        Assert.Equal("no", none.PhpPresence);

        var one = R(Snap(), Snap("/robots.txt", body: "Disallow: /xmlrpc.php\n"));
        PhpHints.Compute(one);
        Assert.Equal(1, one.PhpHintScore);
        Assert.Equal("no", one.PhpPresence);

        var two = R(Snap(headers: [("X-Pingback", "x")]));
        PhpHints.Compute(two);
        Assert.Equal("maybe", two.PhpPresence);
        var line = Assert.Single(two.Tests, t => t.Id == "L1-HINTS");
        Assert.Equal(TestOutcome.Info, line.Outcome);
        Assert.Contains("presenza maybe", line.Detail);

        var proof = R(Snap());
        proof.PhpDetected = true;
        PhpHints.Compute(proof);
        Assert.Equal("yes", proof.PhpPresence);
        Assert.Equal(0, proof.PhpHintScore);
    }

    [Fact]
    public void Hints_Compute_IsIdempotent()
    {
        var r = R(Snap(headers: [("Expires", PhpHints.SessionExpires), ("X-Pingback", "x")]));
        PhpHints.Compute(r);
        PhpHints.Compute(r);
        PhpHints.Compute(r);
        Assert.Equal(2, r.PhpHints.Count);
        Assert.Equal(5, r.PhpHintScore);
        Assert.Single(r.Tests, t => t.Id == "L1-HINTS");
    }

    // ---------- PhpInfoParser ----------

    private const string PhpInfoHtml = """
        <!DOCTYPE html><html><head><title>PHP 8.1.2 - phpinfo()</title></head><body>
        <div class="center">
        <table><tr class="h"><td><a href="http://www.php.net/"><img border="0" src="data:image/png;base64,x" alt="PHP logo" /></a><h1 class="p">PHP Version 8.1.2</h1></td></tr></table>
        <table>
        <tr><td class="e">System </td><td class="v">Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64 </td></tr>
        <tr><td class="e">Server API </td><td class="v">FPM/FastCGI </td></tr>
        <tr><td class="e">Loaded Configuration File </td><td class="v">/etc/php/8.1/fpm/php.ini </td></tr>
        </table>
        <h2><a name="module_core">Core</a></h2>
        <table>
        <tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
        <tr><td class="e">display_errors</td><td class="v">Off</td><td class="v">Off</td></tr>
        <tr><td class="e">expose_php</td><td class="v">On</td><td class="v">On</td></tr>
        <tr><td class="e">memory_limit</td><td class="v">256M</td><td class="v">128M</td></tr>
        <tr><td class="e">post_max_size</td><td class="v">8M</td><td class="v">8M</td></tr>
        <tr><td class="e">upload_max_filesize</td><td class="v">2M</td><td class="v">2M</td></tr>
        <tr><td class="e">max_input_vars</td><td class="v">1000</td><td class="v">1000</td></tr>
        <tr><td class="e">allow_url_fopen</td><td class="v">On</td><td class="v">On</td></tr>
        <tr><td class="e">disable_functions</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
        <tr><td class="e">open_basedir</td><td class="v"><i>no value</i></td><td class="v"><i>no value</i></td></tr>
        </table>
        <h2><a name="module_session">session</a></h2>
        <table>
        <tr><td class="e">session.save_handler</td><td class="v">files</td><td class="v">files</td></tr>
        <tr><td class="e">session.save_path</td><td class="v">/var/lib/php/sessions</td><td class="v">/var/lib/php/sessions</td></tr>
        <tr><td class="e">session.serialize_handler</td><td class="v">php</td><td class="v">php</td></tr>
        <tr>
          <td class="e">session.upload_progress.cleanup</td>
          <td class="v">On</td>
          <td class="v">On</td>
        </tr>
        <tr><td class="e">session.upload_progress.enabled</td><td class="v">{UP}</td><td class="v">On</td></tr>
        <tr><td class="e">session.upload_progress.name</td><td class="v">PHP_SESSION_UPLOAD_PROGRESS</td><td class="v">PHP_SESSION_UPLOAD_PROGRESS</td></tr>
        </table>
        <h2>PHP License</h2>
        </div></body></html>
        """;

    [Fact]
    public void PhpInfo_Parse_ThreeColumnFixture()
    {
        var ini = PhpInfoParser.Parse(PhpInfoHtml.Replace("{UP}", "Off"));
        Assert.Contains("PHP Version=8.1.2", ini);
        Assert.Contains("Server API=FPM/FastCGI", ini);
        Assert.Contains("System=Linux web01 5.15.0-91-generic #101-Ubuntu SMP x86_64", ini);
        Assert.Contains("Loaded Configuration File=/etc/php/8.1/fpm/php.ini", ini);
        Assert.Contains("session.upload_progress.enabled=Off", ini);
        Assert.Contains("session.upload_progress.name=PHP_SESSION_UPLOAD_PROGRESS", ini);
        Assert.Contains("session.upload_progress.cleanup=On", ini);   // riga su più righe
        Assert.Contains("session.serialize_handler=php", ini);
        Assert.Contains("session.save_handler=files", ini);
        Assert.Contains("session.save_path=/var/lib/php/sessions", ini);
        Assert.Contains("expose_php=On", ini);
        Assert.Contains("memory_limit=256M", ini);   // valore locale, non master
        Assert.Contains("post_max_size=8M", ini);
        Assert.Contains("upload_max_filesize=2M", ini);
        Assert.Contains("max_input_vars=1000", ini);
        Assert.Contains("display_errors=Off", ini);
        Assert.Contains("allow_url_fopen=On", ini);
        Assert.Contains("disable_functions=no value", ini);
        Assert.Contains("open_basedir=no value", ini);
        Assert.Equal(19, ini.Count);
        Assert.Equal("PHP Version=8.1.2", ini[0]);   // ordine di Wanted
    }

    [Fact]
    public void PhpInfo_Parse_TwoColumnAndEntities()
    {
        string html = "<table><tr><td class=\"e\">Server&nbsp;API</td><td class=\"v\">Apache 2.0 Handler</td></tr>" +
                      "<tr><td class='e'>disable_functions</td><td class='v'>" + string.Join(",", Enumerable.Range(0, 60).Select(i => "func_" + i)) + "</td></tr></table>";
        var ini = PhpInfoParser.Parse(html);
        Assert.Contains("Server API=Apache 2.0 Handler", ini);
        var df = Assert.Single(ini, x => x.StartsWith("disable_functions="));
        Assert.Equal("disable_functions=".Length + 200 + 3, df.Length);
        Assert.EndsWith("...", df);
        Assert.Empty(PhpInfoParser.Parse("<html><body>Hello</body></html>"));
    }

    [Theory]
    [InlineData("FPM/FastCGI", "fpm")]
    [InlineData("Apache 2.0 Handler", "mod_php")]
    [InlineData("Apache 2.4 Handler", "mod_php")]
    [InlineData("CGI/FastCGI", "cgi")]
    [InlineData("LiteSpeed V8.1", "lsapi")]
    [InlineData("Command Line Interface", "")]
    public void PhpInfo_SapiMapping(string serverApi, string expected) => Assert.Equal(expected, PhpInfoParser.SapiFromServerApi(serverApi));

    [Fact]
    public void PhpInfo_Apply_UploadProgressOff_IsInfoWithMitigation()
    {
        var r = R(Snap(), Snap("/phpinfo.php", body: PhpInfoHtml.Replace("{UP}", "Off")));
        PhpInfoParser.Apply(r);
        Assert.NotEmpty(r.IniHints);
        Assert.Equal("fpm", r.Sapi);
        Assert.Equal("Server API in phpinfo: FPM/FastCGI", r.SapiEvidence);
        var line = Assert.Single(r.Tests, t => t.Id == "L1-PHPINFO-INI");
        Assert.Equal(TestOutcome.Info, line.Outcome);
        Assert.Contains("session.upload_progress.enabled=Off: mitigazione per CVE-2026-109619 e CVE-2026-115560 applicata", line.Detail);
        Assert.Contains("session.serialize_handler=php", line.Detail);
        Assert.Contains("Server API=FPM/FastCGI", line.Detail);
        Assert.Contains("memory_limit=256M", line.Detail);
        Assert.Contains("post_max_size=8M", line.Detail);
    }

    [Fact]
    public void PhpInfo_Apply_UploadProgressOn_IsWarn_AndIdempotent_AndKeepsExistingSapi()
    {
        var r = R(Snap(), Snap("/phpinfo.php", body: PhpInfoHtml.Replace("{UP}", "On")));
        r.Sapi = "mod_php"; r.SapiEvidence = "banner";
        PhpInfoParser.Apply(r);
        PhpInfoParser.Apply(r);
        var line = Assert.Single(r.Tests, t => t.Id == "L1-PHPINFO-INI");
        Assert.Equal(TestOutcome.Warn, line.Outcome);
        Assert.Contains("session.upload_progress.enabled=On: esposto a CVE-2026-115560 se l'applicazione cambia session.serialize_handler a runtime; mitigazione per CVE-2026-109619 non applicata", line.Detail);
        Assert.Equal("mod_php", r.Sapi);
        Assert.Equal("banner", r.SapiEvidence);
        Assert.Equal(19, r.IniHints.Count);
    }

    [Fact]
    public void PhpInfo_Apply_WithoutPhpInfoPage_DoesNothing()
    {
        var r = R(Snap(), Snap("/info.php", status: 404, body: "Not Found"));
        PhpInfoParser.Apply(r);
        Assert.Empty(r.IniHints);
        Assert.Empty(r.Tests);
    }

    // ---------- Verbosity ----------

    [Fact]
    public void Verbosity_Silent_IsZero_NoTestLine()
    {
        var r = R(Snap());
        Verbosity.Compute(r);
        Assert.Equal(0, r.VerbosityScore);
        Assert.Empty(r.VerbosityItems);
        Assert.DoesNotContain(r.Tests, t => t.Id == "L1-VERBOSITY");
    }

    [Fact]
    public void Verbosity_Composition_SingleItems()
    {
        var r = R(Snap());
        r.ServerHeader = "Apache/2.4.58 (Debian)";
        r.OsHint = "Debian";
        r.PhpVersionRaw = "8.1.2"; r.PhpVersionSource = "X-Powered-By";
        Verbosity.Compute(r);
        Assert.Equal(3, r.VerbosityScore);
        Assert.Equal(3, r.VerbosityItems.Count);
        Assert.All(r.VerbosityItems, i => Assert.StartsWith("1: ", i));
        var line = Assert.Single(r.Tests, t => t.Id == "L1-VERBOSITY");
        Assert.StartsWith("3/5: ", line.Detail);

        var v = R(Snap());
        v.PhpVersionRaw = "8.1.2"; v.PhpVersionSource = "/phpinfo.php";   // versione da una pagina, non da un'intestazione
        v.AllowedMethods = "GET, HEAD, POST, OPTIONS, TRACE";
        v.ApplicationVersion = "6.5";
        v.Libraries.Add("monolog/monolog 3.5.0");
        v.Tls = new TlsInfo { Handshake = true, Subject = "web01.corp.local", SubjectAltNames = ["web01.corp.local", "www.example.org"] };
        v.Exposures.Add("/.git/HEAD (200): repository Git esposto");
        Verbosity.Compute(v);
        Assert.Equal(5, v.VerbosityItems.Count);
        Assert.Equal(5, v.VerbosityScore);
        Assert.DoesNotContain(v.VerbosityItems, i => i.Contains("intestazione"));
        Assert.Contains(v.VerbosityItems, i => i.Contains("web01.corp.local") && !i.Contains("www.example.org"));
        Assert.Contains("1: metodo TRACE consentito", v.VerbosityItems);
    }

    [Fact]
    public void Verbosity_HeavyItems_CapAtFive_AndIdempotent()
    {
        var r = R(Snap());
        r.IniHints.Add("expose_php=On");                                                   // 2 phpinfo
        r.Exposures.Add("/server-status (200): stato di Apache pubblico");                  // 2 stato
        r.Tests.Add(new TestEvidence { Id = "ADV-DEBUGPAGE", Name = "x" });                 // 2 debug
        r.Requests.Add(Snap("/uploads/", body: "<html><title>Index of /uploads</title></html>"));   // 2 listing
        r.ServerHeader = "nginx/1.24.0";                                                    // 1
        Verbosity.Compute(r);
        Verbosity.Compute(r);
        Assert.Equal(5, r.VerbosityItems.Count);
        Assert.Equal(9, r.VerbosityItems.Sum(i => int.Parse(i.Split(':')[0])));
        Assert.Equal(5, r.VerbosityScore);
        var line = Assert.Single(r.Tests, t => t.Id == "L1-VERBOSITY");
        Assert.StartsWith("5/5: ", line.Detail);
        Assert.Contains("2: pagina phpinfo esposta", r.VerbosityItems);
        Assert.Contains("2: directory listing esposto", r.VerbosityItems);
    }

    [Fact]
    public void Verbosity_IsComputedByVerdictEngine()
    {
        var r = R(Snap());
        r.ServerHeader = "Apache/2.4.58";
        VerdictEngine.Apply(r);
        Assert.Equal(1, r.VerbosityScore);
        Assert.Single(r.Tests, t => t.Id == "L1-VERBOSITY");
        VerdictEngine.Apply(r);
        Assert.Single(r.Tests, t => t.Id == "L1-VERBOSITY");
    }

    // ---------- motore ----------

    private ScanConfig Cfg(FakePhpServer srv) => new()
    {
        TargetsText = "127.0.0.1", PortsText = srv.Port.ToString(), PathsText = "/ /index.php", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 4, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [srv.Port], UdpPorts = [], TimeoutMs = 1000, SkipIfNotAlive = true },
        Level1InfoPages = false, Level1EasterEgg = false, Level2 = false, WafDetect = false, WafBehaviour = false, SizeProbeKiB = 16,
        SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false,
        Advanced = new AdvancedOptions().Also(o => o.SetAll(false)),
    };

    [Fact]
    public async Task Engine_HintsOnly_GivesMaybe_WithoutProof()
    {
        using var srv = new FakePhpServer { PoweredBy = null, Server = "nginx" };
        srv.ExtraHeaders.Add(new("Expires", PhpHints.SessionExpires));
        srv.ExtraHeaders.Add(new("Set-Cookie", "sess=abcdefghij0123456789klmnop; path=/; HttpOnly"));
        var r = Assert.Single((await new ScanEngine().RunAsync(Cfg(srv), CancellationToken.None)).Results);
        Assert.True(r.HttpReachable);
        Assert.False(r.PhpDetected);
        Assert.Equal("maybe", r.PhpPresence);
        Assert.Equal(6, r.PhpHintScore);
        Assert.Contains(r.PhpHints, h => h.Contains("session_start()"));
        Assert.Contains(r.PhpHints, h => h.Contains("nome sess"));
        Assert.Equal(Verdict.NoPhpDetected, r.Verdict);   // "maybe" non è un verdetto
        Assert.Single(r.Tests, t => t.Id == "L1-HINTS");
    }

    [Fact]
    public async Task Engine_PhpInfoPage_FillsIniHints()
    {
        using var srv = new FakePhpServer { PoweredBy = null, Server = "nginx" };
        srv.PathBodies["/phpinfo.php"] = (200, PhpInfoHtml.Replace("{UP}", "On"), "text/html; charset=utf-8");
        var cfg = Cfg(srv);
        cfg.Level1InfoPages = true;
        var r = Assert.Single((await new ScanEngine().RunAsync(cfg, CancellationToken.None)).Results);
        Assert.True(r.PhpDetected);
        Assert.Equal("yes", r.PhpPresence);
        Assert.Contains("session.upload_progress.enabled=On", r.IniHints);
        Assert.Contains("Server API=FPM/FastCGI", r.IniHints);
        Assert.Equal("fpm", r.Sapi);
        Assert.Equal("8.1.2", r.PhpVersionRaw);
        var line = Assert.Single(r.Tests, t => t.Id == "L1-PHPINFO-INI");
        Assert.Equal(TestOutcome.Warn, line.Outcome);
        Assert.True(r.VerbosityScore >= 2);
        Assert.Contains("2: pagina phpinfo esposta", r.VerbosityItems);
    }
}
