using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// v1.5: indizi passivi di PHP, letti solo da ciò che il bersaglio ha già risposto (nessuna richiesta in più).
/// Ogni indizio pesa 3 (forte), 2 (medio) o 1 (debole) e viene registrato come "peso: descrizione" in
/// <see cref="ScanResult.PhpHints"/>; la somma è <see cref="ScanResult.PhpHintScore"/> e decide
/// <see cref="ScanResult.PhpPresence"/>: "yes" quando c'è una prova (PhpDetected), "maybe" con punteggio ≥ 2, altrimenti "no".
/// "maybe" è un inventario di indizi, mai un verdetto. Il calcolo è idempotente (il motore può ricalcolare).
/// </summary>
public static class PhpHints
{
    /// <summary>Soglia di punteggio per "maybe".</summary>
    public const int MaybeThreshold = 2;

    /// <summary>Intestazione Expires fissa che session_start() emette con session.cache_limiter=nocache (valore cablato in ext/session).</summary>
    public const string SessionExpires = "Thu, 19 Nov 1981 08:52:00 GMT";

    private static readonly Regex Sid26Rx = new(@"^[0-9a-v]{26}$", RegexOptions.CultureInvariant);
    private static readonly Regex Sid32Rx = new(@"^[0-9a-zA-Z,-]{32}$", RegexOptions.CultureInvariant);
    private static readonly Regex HexRx = new(@"^[0-9a-f]+$", RegexOptions.CultureInvariant);
    private static readonly Regex CookieRx = new(@"^\s*([^=;\s]+)=([^;]*)", RegexOptions.CultureInvariant);

    /// <summary>Nomi di cookie di sessione di piattaforme non PHP: un valore di 32 caratteri con questi nomi non conta.</summary>
    private static readonly HashSet<string> NonPhpCookieNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "JSESSIONID", "ASP.NET_SessionId", ".AspNetCore.Session", "connect.sid", "csrftoken", "sessionid", "XSRF-TOKEN", "_csrf",
        "rack.session", "_session_id", "PLAY_SESSION", "ring-session", "koa.sess", "express.sid", "_ga", "_gid", "AWSALB", "AWSALBCORS", "ARRAffinity",
    };

    /// <summary>Cookie di framework e CMS PHP (nome, espressione sul nome del cookie).</summary>
    private static readonly (string Label, Regex Rx)[] FrameworkCookies =
    [
        ("PHPSESSID", new Regex(@"^PHPSESSID$", RegexOptions.IgnoreCase)),
        ("Laravel", new Regex(@"^laravel_session$", RegexOptions.IgnoreCase)),
        ("CodeIgniter", new Regex(@"^ci_session$", RegexOptions.IgnoreCase)),
        ("Drupal", new Regex(@"^S?SESS[a-f0-9]{32}$")),
        ("Drupal", new Regex(@"^SSESS")),
        ("Moodle", new Regex(@"^MoodleSession", RegexOptions.IgnoreCase)),
        ("TYPO3", new Regex(@"^fe_typo_user$", RegexOptions.IgnoreCase)),
        ("phpBB", new Regex(@"^phpbb3?_", RegexOptions.IgnoreCase)),
        ("OpenCart", new Regex(@"^OCSESSID$", RegexOptions.IgnoreCase)),
        ("PrestaShop", new Regex(@"^PrestaShop", RegexOptions.IgnoreCase)),
        ("WordPress", new Regex(@"^wordpress_test_cookie$", RegexOptions.IgnoreCase)),
        ("WordPress", new Regex(@"^wp-settings-", RegexOptions.IgnoreCase)),
        ("WordPress", new Regex(@"^wordpress_", RegexOptions.IgnoreCase)),
        ("Symfony", new Regex(@"^symfony", RegexOptions.IgnoreCase)),
        ("CakePHP", new Regex(@"^CAKEPHP", RegexOptions.IgnoreCase)),
        ("Yii", new Regex(@"^yii", RegexOptions.IgnoreCase)),
        ("Craft CMS", new Regex(@"^craftsession", RegexOptions.IgnoreCase)),
        ("MyBB", new Regex(@"^MYBB", RegexOptions.IgnoreCase)),
        ("Joomla", new Regex(@"^joomla_", RegexOptions.IgnoreCase)),
        ("Joomla", new Regex(@"^[a-f0-9]{32}$")),   // il cookie di sessione di Joomla ha come NOME 32 esadecimali
    ];

    /// <summary>Intestazioni di risposta tipiche di applicazioni PHP (nome, filtro sul valore o null = qualunque valore).</summary>
    private static readonly (string Name, Func<string, bool>? Match)[] HintHeaders =
    [
        ("X-Pingback", null),
        ("Link", v => v.Contains("rel=\"https://api.w.org/\"", StringComparison.OrdinalIgnoreCase)),
        ("X-Redirect-By", null),
        ("X-Drupal-Cache", null),
        ("X-Drupal-Dynamic-Cache", null),
        ("X-Generator", null),
    ];

    /// <summary>Tracce nel corpo (etichetta, espressione), una per schema, al massimo 4.</summary>
    private static readonly (string Label, Regex Rx)[] BodyPatterns =
    [
        ("?PHPSESSID=", new Regex(@"[?&]PHPSESSID=", RegexOptions.CultureInvariant)),
        ("/wp-content/", new Regex(@"/wp-content/", RegexOptions.IgnoreCase)),
        ("/wp-includes/", new Regex(@"/wp-includes/", RegexOptions.IgnoreCase)),
        ("/sites/default/files/", new Regex(@"/sites/default/files/", RegexOptions.IgnoreCase)),
        ("/media/jui/", new Regex(@"/media/jui/", RegexOptions.IgnoreCase)),
        ("/components/com_", new Regex(@"/components/com_", RegexOptions.IgnoreCase)),
        ("/typo3conf/", new Regex(@"/typo3conf/", RegexOptions.IgnoreCase)),
        ("/vendor/", new Regex(@"(?:href|src)\s*=\s*[""'][^""']*/vendor/", RegexOptions.IgnoreCase)),
        ("/index.php/", new Regex(@"/index\.php/", RegexOptions.IgnoreCase)),
    ];

    private static readonly Regex PhpLinkRx = new(@"(href|src|action)\s*=\s*[""']([^""']*\.php)(?:[?""'#/])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Link, src e action verso file .php di questo host: "attributo=percorso". Gli assoluti verso altri host non contano.</summary>
    internal static List<string> SameHostPhpLinks(ScanResult r, IReadOnlyList<HttpSnapshot> responses)
    {
        var mine = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { r.Host, r.HostHeader };
        foreach (var n in r.DiscoveredNames) mine.Add(n);
        foreach (var ip in r.ResolvedIps) mine.Add(ip);
        mine.Remove("");
        var list = new List<string>();
        foreach (var s in responses)
        {
            if (s.Body.Length == 0) continue;
            foreach (Match m in PhpLinkRx.Matches(s.Body))
            {
                string url = m.Groups[2].Value;
                if (url.StartsWith("//", StringComparison.Ordinal)) url = "https:" + url;
                if (url.Contains("://", StringComparison.Ordinal))   // su Linux Uri.TryCreate prende "/x.php" come file:// assoluto: decidere prima
                {
                    if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || !mine.Contains(u.Host)) continue;
                    url = u.AbsolutePath;
                }
                else if (url.Contains(':')) continue;   // mailto:, javascript:
                list.Add(m.Groups[1].Value.ToLowerInvariant() + "=" + url);
                if (list.Count >= 20) return list;
            }
        }
        return list;
    }

    private static readonly string[] PanelWords = ["Plesk", "cPanel", "Webmin", "DirectAdmin", "ISPConfig", "CloudPanel"];
    private static readonly int[] PanelPorts = [8443, 8880, 2083, 2087, 10000];

    private static readonly string[] EcosystemTechs =
    [
        "WordPress", "Drupal", "Joomla", "TYPO3", "Moodle", "Laravel", "Symfony", "CodeIgniter", "CakePHP", "Yii", "Magento", "PrestaShop",
        "OpenCart", "MediaWiki", "phpMyAdmin", "Nextcloud", "ownCloud", "Matomo", "MyBB", "phpBB", "Plesk", "cPanel",
    ];

    /// <summary>v1.6: versione di PHP scritta in chiaro nel corpo ("PHP/8.1.2", "PHP Version 7.4.33", "PHP 8.2.0"), fuori da phpinfo.</summary>
    private static readonly Regex BodyVersionRx = new(@"PHP(?:/| Version | version |\s)(\d+\.\d+\.\d+(?:[-+~][A-Za-z0-9.+~_-]+)?)", RegexOptions.CultureInvariant);

    /// <summary>Numero massimo di versioni dichiarate nel corpo conservate.</summary>
    public const int MaxBodyVersions = 5;

    /// <summary>Versioni di PHP dichiarate nel corpo delle risposte GET, escluse le pagine phpinfo (che sono una prova, non un indizio): distinte, al massimo <see cref="MaxBodyVersions"/>.</summary>
    public static List<string> BodyDeclaredVersions(IReadOnlyList<HttpSnapshot> responses)
    {
        var list = new List<string>();
        foreach (var s in responses)
        {
            if (!s.HasResponse || s.Method != "GET" || s.Body.Length == 0 || PhpInfoParser.LooksLikePhpInfo(s.Body)) continue;
            foreach (Match m in BodyVersionRx.Matches(s.Body))
            {
                string v = m.Groups[1].Value;
                if (!list.Contains(v, StringComparer.OrdinalIgnoreCase)) list.Add(v);
                if (list.Count >= MaxBodyVersions) return list;
            }
        }
        return list;
    }

    private static readonly string[] CacheStatusHeaders = ["X-Cache", "CF-Cache-Status", "X-Proxy-Cache", "X-Cache-Status", "X-Cache-Lookup"];

    /// <summary>
    /// v1.6: cache o intermediario davanti all'origine, dalle intestazioni (Via, Age, X-Cache, CF-Cache-Status, X-Varnish, X-Served-By,
    /// X-Cache-Hits, X-Proxy-Cache, Cache-Control s-maxage): "" nessuno, altrimenti la descrizione con l'evidenza.
    /// Serve a leggere l'assenza di X-Powered-By/Set-Cookie: una risposta servita da una cache non porta le intestazioni dell'origine.
    /// </summary>
    public static string CacheHint(IReadOnlyList<HttpSnapshot> responses) => CacheHintCore(responses).Text;

    /// <summary>Come <see cref="CacheHint"/>, con l'indicazione separata di un HIT (risposta uscita dalla cache, non dall'origine).</summary>
    internal static (string Text, bool Hit) CacheHintCore(IReadOnlyList<HttpSnapshot> responses)
    {
        var evidence = new List<string>();
        bool hit = false, intermediary = false;
        void Add(string e) { if (!evidence.Contains(e, StringComparer.OrdinalIgnoreCase)) evidence.Add(e); }
        foreach (var s in responses)
        {
            if (!s.HasResponse) continue;
            foreach (var h in s.Headers)
            {
                string k = h.Key, v = h.Value.Trim();
                if (k.Equals("Age", StringComparison.OrdinalIgnoreCase))
                {
                    if (long.TryParse(v, out long age) && age > 0) { hit = true; Add("Age: " + v); }
                }
                else if (k.Equals("Via", StringComparison.OrdinalIgnoreCase)) { intermediary = true; Add("Via: " + Short(v)); }
                else if (k.Equals("X-Varnish", StringComparison.OrdinalIgnoreCase)) { intermediary = true; Add("X-Varnish: " + Short(v)); if (v.Trim().Contains(' ')) hit = true; }   // due XID = hit
                else if (k.Equals("X-Served-By", StringComparison.OrdinalIgnoreCase)) { intermediary = true; Add("X-Served-By: " + Short(v)); }
                else if (k.Equals("X-Cache-Hits", StringComparison.OrdinalIgnoreCase)) { intermediary = true; Add("X-Cache-Hits: " + v); if (int.TryParse(v.Split(',')[0].Trim(), out int n) && n > 0) hit = true; }
                else if (CacheStatusHeaders.Any(c => c.Equals(k, StringComparison.OrdinalIgnoreCase)))
                {
                    intermediary = true;
                    Add(k + ": " + Short(v));
                    if (v.Contains("HIT", StringComparison.OrdinalIgnoreCase) || v.StartsWith("REVALIDATED", StringComparison.OrdinalIgnoreCase)) hit = true;
                }
                else if (k.Equals("Cache-Control", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(v, @"\bs-maxage\s*=\s*[1-9]", RegexOptions.IgnoreCase))
                    Add("Cache-Control: " + Short(v));   // debole: dice solo che una cache condivisa è prevista
            }
        }
        if (evidence.Count == 0) return ("", false);
        string ev = string.Join("; ", evidence.Take(6));
        if (hit) return (L.F("risposta servita da una cache ({0})", ev), true);
        if (intermediary) return (L.F("intermediario dichiarato ({0})", ev), false);
        return (L.F("cache condivisa prevista dall'origine ({0})", ev), false);
    }

    private static readonly string[] NameWords = ["php", "wordpress", "moodle", "joomla", "drupal", "typo3", "plesk"];
    private static readonly Regex WpNameRx = new(@"(?:^|[.-])wp(?:[.-]|\d|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Ricalcola indizi, punteggio e presenza da ciò che il risultato contiene. Idempotente.</summary>
    public static void Compute(ScanResult r)
    {
        var hints = new List<string>();
        int score = 0;
        void Hint(int weight, string text)
        {
            string line = weight + ": " + text;
            if (hints.Contains(line, StringComparer.Ordinal)) return;   // lo stesso indizio da più risposte conta una volta
            hints.Add(line);
            score += weight;
        }

        var responses = r.Requests.Where(s => s.HasResponse).ToList();
        var main = MainResponse(r);

        // --- forti ---------------------------------------------------------------------------------------------------------
        if (responses.Any(s => s.HeaderValues("Expires").Any(v => v.Trim() == SessionExpires)))
            Hint(3, L.T("intestazione Expires fissa di session_start()"));

        foreach (var s in responses)
            foreach (var c in s.HeaderValues("Set-Cookie"))
            {
                var m = CookieRx.Match(c);
                if (!m.Success) continue;
                string name = m.Groups[1].Value, value = m.Groups[2].Value.Trim();
                if (LooksLikePhpSid(name, value)) Hint(3, L.F("cookie con valore nel formato dell'ID di sessione PHP (nome {0})", name));
            }

        // --- medi -----------------------------------------------------------------------------------------------------------
        foreach (var s in responses)
            foreach (var c in s.HeaderValues("Set-Cookie"))
            {
                var m = CookieRx.Match(c);
                if (!m.Success) continue;
                string name = m.Groups[1].Value;
                foreach (var (label, rx) in FrameworkCookies)
                    if (rx.IsMatch(name)) { Hint(2, L.F("cookie di framework PHP: {0}", label + " (" + name + ")")); break; }
            }

        foreach (var s in responses)
        {
            foreach (var (hname, match) in HintHeaders)
                foreach (var v in s.HeaderValues(hname))
                    if (match == null || match(v)) { Hint(2, L.F("intestazione {0}", hname)); break; }
            foreach (var v in s.HeaderValues("X-Powered-By"))
            {
                bool plesk = v.Contains("PleskLin", StringComparison.OrdinalIgnoreCase) || v.Contains("PleskWin", StringComparison.OrdinalIgnoreCase);
                bool php = !r.PhpDetected && v.Contains("PHP", StringComparison.OrdinalIgnoreCase);
                if (plesk || php) Hint(2, L.F("intestazione {0}", "X-Powered-By: " + Short(v)));
            }
        }

        int bodyHits = 0;
        // link a *.php: contano solo quelli verso QUESTO host (relativi, o assoluti con lo stesso host/nome): nella /20 di riferimento
        // 99 pagine su 115 linkavano l'index.php del portale centrale, che non dice nulla sull'host scansionato.
        // Peso 2 con un form (action=) o più percorsi distinti, 1 con un solo link.
        var phpLinks = SameHostPhpLinks(r, responses);
        if (phpLinks.Count > 0)
        {
            bool form = phpLinks.Any(l => l.StartsWith("action", StringComparison.OrdinalIgnoreCase));
            Hint(form || phpLinks.Select(l => l[(l.IndexOf('=') + 1)..]).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 2 ? 2 : 1,
                L.F("nel corpo: {0}", "link a *.php sullo stesso host (" + phpLinks.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + ")"));
            bodyHits++;
        }
        foreach (var (label, rx) in BodyPatterns)
        {
            if (bodyHits >= 4) break;
            if (responses.Any(s => s.Body.Length > 0 && rx.IsMatch(s.Body))) { Hint(2, L.F("nel corpo: {0}", label)); bodyHits++; }
        }

        if (r.PhpSurfaceProbe.Length > 0 && !r.PhpDetected)
            Hint(2, L.F("il file .php inesistente è trattato da un handler ({0})", r.PhpSurfaceProbe));

        // v1.6: versione di PHP scritta nel corpo (footer, pagine di errore, pagine di stato): indizio, mai verdetto (PhpVersionRaw non cambia)
        r.BodyDeclaredVersions = BodyDeclaredVersions(responses);
        if (r.BodyDeclaredVersions.Count > 0)
            Hint(2, L.F("versione di PHP dichiarata nel corpo (non verificata): {0}", string.Join(", ", r.BodyDeclaredVersions)));

        // --- deboli ---------------------------------------------------------------------------------------------------------
        var robots = responses.FirstOrDefault(s => s.Status == 200 && s.Url.EndsWith("/robots.txt", StringComparison.OrdinalIgnoreCase));
        if (robots != null)
        {
            var dis = robots.Body.Split('\n').Select(l => l.Trim()).Where(l => l.StartsWith("Disallow:", StringComparison.OrdinalIgnoreCase)).Select(l => l[9..].Trim()).ToList();
            var hit = dis.FirstOrDefault(d => d.Contains(".php", StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(d, @"wp-admin|administrator|typo3|xmlrpc", RegexOptions.IgnoreCase));
            if (hit != null) Hint(1, L.F("robots.txt esclude percorsi PHP ({0})", Short(hit)));
        }

        bool triplet = false;
        if (main != null && main.Status == 200 && main.Header("ETag") == null && main.Header("Last-Modified") == null)
        {
            string cc = string.Join(", ", main.HeaderValues("Cache-Control"));
            bool pragma = main.HeaderValues("Pragma").Any(v => v.Contains("no-cache", StringComparison.OrdinalIgnoreCase));
            if (cc.Contains("no-store, no-cache, must-revalidate", StringComparison.OrdinalIgnoreCase) && pragma)
            {
                triplet = true;
                Hint(1, L.T("terna di cache di PHP senza ETag/Last-Modified"));
                if ((main.Header("Content-Type") ?? "").Trim() == "text/html; charset=UTF-8")
                    Hint(1, L.T("Content-Type con la grafia predefinita di PHP (text/html; charset=UTF-8)"));
            }
        }
        _ = triplet;

        string? panel = PanelContext(r, responses);
        if (panel != null) Hint(1, L.F("pannello di hosting ({0})", panel));

        foreach (var t in r.Technologies)
        {
            string? eco = EcosystemTechs.FirstOrDefault(e => t.Contains(e, StringComparison.OrdinalIgnoreCase));
            if (eco != null) Hint(1, L.F("tecnologia dell'ecosistema PHP: {0}", t));
        }

        var names = r.DiscoveredNames.Concat(r.Tls?.SubjectAltNames ?? []).Concat(r.Tls == null ? [] : [r.Tls.Subject])
            .Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(n => NameWords.Any(w => n.Contains(w, StringComparison.OrdinalIgnoreCase)) || WpNameRx.IsMatch(n)).Take(3).ToList();
        if (names.Count > 0) Hint(1, L.F("nomi che richiamano PHP o un suo CMS: {0}", string.Join(", ", names)));

        // --- esito ------------------------------------------------------------------------------------------------------------
        r.PhpHints = hints;
        r.PhpHintScore = score;
        r.PhpPresence = r.PhpDetected ? "yes" : score >= MaybeThreshold ? "maybe" : "no";

        // v1.6: cache o intermediario davanti all'origine (non pesa: spiega l'eventuale assenza di indizi, non li aggiunge)
        var (cache, cacheHit) = CacheHintCore(responses);
        r.CacheHint = cache;

        r.Tests.RemoveAll(t => t.Id is "L1-HINTS" or "L1-CACHE");
        if (hints.Count > 0)
            r.Add("L1-HINTS", L.T("Indizi di PHP"), TestOutcome.Info,
                L.F("punteggio {0}, presenza {1}: {2}", score, r.PhpPresence, string.Join("; ", hints)) + (cache.Length > 0 ? "; " + cache : ""));
        if (cache.Length > 0)
            r.Add("L1-CACHE", L.T("Cache o intermediario"), TestOutcome.Info,
                cache + (cacheHit ? ": " + L.T("le intestazioni dell'origine (X-Powered-By, Set-Cookie) possono mancare") : ""));
    }

    /// <summary>Valore nel formato dell'ID di sessione PHP: 26 caratteri [0-9a-v] (sid_length 26, 5 bit per carattere, predefinito dalla 7.1)
    /// oppure 32 caratteri [0-9a-zA-Z,-] (6 bit) quando il nome non è di una piattaforma non PHP e il valore non è un semplice token esadecimale.</summary>
    public static bool LooksLikePhpSid(string name, string value)
    {
        if (Sid26Rx.IsMatch(value)) return true;
        if (!Sid32Rx.IsMatch(value)) return false;
        if (NonPhpCookieNames.Contains(name)) return false;
        return !HexRx.IsMatch(value);   // 32 esadecimali: token generico (Django, Rails, md5), troppo comune per contare
    }

    private static HttpSnapshot? MainResponse(ScanResult r)
    {
        var gets = r.Requests.Where(s => s.HasResponse && s.Method == "GET").ToList();
        return gets.FirstOrDefault(s => Path(s.Url) is "/" or "/index.php") ?? gets.FirstOrDefault();
    }

    private static string Path(string url)
    {
        int i = url.IndexOf("://", StringComparison.Ordinal);
        if (i < 0) return url;
        int s = url.IndexOf('/', i + 3);
        if (s < 0) return "/";
        string p = url[s..];
        int q = p.IndexOf('?');
        return q < 0 ? p : p[..q];
    }

    private static string? PanelContext(ScanResult r, List<HttpSnapshot> responses)
    {
        if (PanelPorts.Contains(r.Port)) return L.F("porta {0}", r.Port);
        foreach (var w in PanelWords)
        {
            if (r.ServerHeader.Contains(w, StringComparison.OrdinalIgnoreCase) || r.PoweredBy.Contains(w, StringComparison.OrdinalIgnoreCase)) return w;
            if (responses.Any(s => s.Headers.Any(h => h.Value.Contains(w, StringComparison.OrdinalIgnoreCase)))) return w;
        }
        return null;
    }

    private static string Short(string v) => v.Length <= 80 ? v : v[..77] + "...";
}
