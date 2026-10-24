using System.Security.Cryptography;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// Scoperta della superficie PHP di un host già raggiunto, in sola lettura (HEAD/GET, nessun corpo di richiesta):
/// 1) sonda del file .php inesistente: la risposta rivela chi gestisce l'estensione (PHP-FPM "File not found.", php-cgi
///    "No input file specified.", mod_php con X-Powered-By sulla 404) indipendentemente da banner e applicazione;
/// 2) punti di ingresso comuni (login, admin, wp-login.php, xmlrpc.php, phpmyadmin/…): esistono se rispondono in modo
///    diverso dal file inesistente (200, 401, 403, redirect specifico);
/// 3) link, action dei form e src verso .php trovati nei corpi già scaricati, sullo stesso host (un livello, max 20).
/// Il livello 2 usa poi il miglior .php trovato quando i percorsi configurati non ne offrono uno.
/// </summary>
public static class SurfaceDiscovery
{
    public static readonly string[] EntryPoints =
    [
        "/login.php", "/admin.php", "/admin/", "/administrator/index.php", "/user/login", "/login/", "/index.php/login",
        "/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-json/", "/wp-cron.php",
        "/phpmyadmin/", "/pma/", "/myadmin/", "/adminer.php", "/adminer/",
        "/api.php", "/ajax.php", "/upload.php", "/cron.php", "/install.php", "/setup.php", "/update.php", "/config.php",
        "/core/install.php", "/typo3/", "/glpi/", "/moodle/login/index.php", "/nextcloud/", "/owncloud/", "/roundcube/", "/webmail/",
        "/zabbix/", "/dolibarr/", "/matomo/", "/piwik/", "/status.php", "/robots.txt", "/sitemap.xml",
    ];

    public const int MaxLinks = 20;

    private static readonly Regex LinkRx = new(@"(?:href|src|action)\s*=\s*[""']([^""'#?\s]+\.php)(?:[?""'#\s])", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex RobotsRx = new(@"^(?:Dis)?allow:\s*(/\S*)", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant);

    /// <summary>Esito della sonda del file inesistente. ServerError (v1.6): 5xx uguale a quello delle pagine configurate, backend morto o solo gateway.</summary>
    public enum MissingFileKind { Unknown, Fpm, Cgi, ModPhp, CatchAll, RedirectAll, ForbiddenAll, ServerError }

    /// <summary>
    /// Vero (v1.6) quando il file inesistente e tutte le pagine configurate che hanno risposto danno lo stesso stato 5xx: 502/503/504 bastano
    /// (è il gateway che parla, il backend non c'è), per gli altri 5xx serve anche un corpo di lunghezza simile (±10%). Su un host così ogni
    /// sonda su percorso riceve la stessa pagina di errore: punti di ingresso, file e comportamenti non sono verificabili e costano solo tempo
    /// (sulla /20 alcuni servizi 502 hanno consumato minuti di sonde per nulla).
    /// </summary>
    public static bool IsServerErrorEverywhere(HttpSnapshot miss, IEnumerable<HttpSnapshot> pages)
    {
        if (!miss.HasResponse || miss.Status < 500) return false;
        var answered = pages.Where(s => s.HasResponse).ToList();
        if (answered.Count == 0 || answered.Any(s => s.Status != miss.Status)) return false;
        if (miss.Status is 502 or 503 or 504) return true;
        long len = miss.BodyLength;
        return answered.All(s => Math.Abs(s.BodyLength - len) <= Math.Max(len, s.BodyLength) * 0.10);
    }

    /// <summary>Risposte GET/HEAD (senza query) ai percorsi configurati già presenti nel risultato.</summary>
    public static List<HttpSnapshot> PageSnapshots(ScanContext ctx) =>
        ctx.Result.Requests.Where(q => q.Method is "GET" or "HEAD" && !q.Url.Contains('?') && ctx.Paths.Any(p => q.Url.EndsWith(ctx.Endpoint.Url(p), StringComparison.Ordinal))).ToList();

    /// <summary>Classificazione del file inesistente tenendo conto delle pagine configurate: 5xx ovunque = <see cref="MissingFileKind.ServerError"/>.</summary>
    public static MissingFileKind ClassifyMissingPhp(HttpSnapshot s, IEnumerable<HttpSnapshot> pages) =>
        IsServerErrorEverywhere(s, pages) ? MissingFileKind.ServerError : ClassifyMissingPhp(s);

    public static MissingFileKind ClassifyMissingPhp(HttpSnapshot s)
    {
        if (!s.HasResponse) return MissingFileKind.Unknown;
        string body = s.Body.Trim();
        if (s.Status is >= 300 and < 400) return MissingFileKind.RedirectAll;
        if (s.Status == 403) return MissingFileKind.ForbiddenAll;
        if (s.Status is >= 200 and < 300) return MissingFileKind.CatchAll;
        if (body.StartsWith("File not found.", StringComparison.Ordinal) || body == "File not found" || (s.Status == 404 && body.Contains("File not found.", StringComparison.Ordinal) && body.Length < 200)) return MissingFileKind.Fpm;
        if (body.Contains("No input file specified", StringComparison.OrdinalIgnoreCase)) return MissingFileKind.Cgi;
        if (s.Status == 404 && (s.Header("X-Powered-By") ?? "").Contains("PHP", StringComparison.OrdinalIgnoreCase)) return MissingFileKind.ModPhp;
        return MissingFileKind.Unknown;
    }

    /// <summary>Esegue la scoperta e aggiorna risultato ed evidenze. Restituisce i percorsi .php che rispondono 2xx, utili al livello 2.</summary>
    public static async Task<List<string>> RunAsync(ScanContext ctx)
    {
        var r = ctx.Result;
        var found = new List<string>();
        var phpOk = new List<string>();

        // 1) file inesistente
        string probe = "/" + RandomName() + ".php";
        var miss = await ctx.GetAsync(probe).ConfigureAwait(false);
        var kind = ClassifyMissingPhp(miss, PageSnapshots(ctx));
        string probeShown = "/<casuale>.php";
        switch (kind)
        {
            case MissingFileKind.Fpm:
                SetSapi(r, "fpm", L.F("il file .php inesistente risponde {0} \"File not found.\": è la risposta di PHP-FPM dietro il web server", miss.Status));
                r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), TestOutcome.Warn, L.F("{0}: {1} \"File not found.\" = PHP-FPM raggiunto (prova di PHP indipendente dal banner)", probeShown, miss.Status), miss);
                break;
            case MissingFileKind.Cgi:
                SetSapi(r, "cgi", L.F("il file .php inesistente risponde {0} \"No input file specified.\": è la risposta di php-cgi", miss.Status));
                r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), TestOutcome.Warn, L.F("{0}: {1} \"No input file specified.\" = php-cgi raggiunto (prova di PHP indipendente dal banner)", probeShown, miss.Status), miss);
                break;
            case MissingFileKind.ModPhp:
                // Il banner prevale sulla sonda: con mod_fcgid/proxy_fcgi anche un .php inesistente passa a PHP (FastCGI) e porta X-Powered-By
                if (Regex.IsMatch(r.ServerHeader, @"mod_fcgid|mod_proxy_fcgi|proxy_fcgi", RegexOptions.IgnoreCase))
                {
                    SetSapi(r, "cgi", L.F("il file .php inesistente risponde 404 con X-Powered-By, ma il banner dichiara un modulo FastCGI ({0}): PHP gira come FastCGI, non come modulo", r.ServerHeader));
                    r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), TestOutcome.Warn, L.F("{0}: 404 con X-Powered-By: {1}, inoltrato a PHP via FastCGI (banner: {2})", probeShown, miss.Header("X-Powered-By"), r.ServerHeader), miss);
                    break;
                }
                SetSapi(r, "mod_php", L.T("la pagina 404 del web server porta X-Powered-By: PHP: il modulo PHP è caricato nel server"));
                r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), TestOutcome.Warn, L.F("{0}: 404 con X-Powered-By: {1} = PHP come modulo del web server", probeShown, miss.Header("X-Powered-By")), miss);
                break;
            case MissingFileKind.CatchAll:
                r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), TestOutcome.Info, L.F("{0} risponde {1}: il server risponde a qualunque percorso (catch-all), i punti di ingresso non sono distinguibili", probeShown, miss.Status), miss);
                break;
            case MissingFileKind.RedirectAll:
                r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), TestOutcome.Info, L.F("{0} risponde {1} verso {2}: redirect globale, i punti di ingresso vanno cercati sulla destinazione", probeShown, miss.Status, miss.Header("Location") ?? "?"), miss);
                break;
            case MissingFileKind.ForbiddenAll:
                r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), TestOutcome.Info, L.F("{0} risponde 403: accesso negato a priori, i punti di ingresso non sono distinguibili", probeShown), miss);
                break;
            case MissingFileKind.ServerError:
                r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), TestOutcome.Warn, L.F("{0} risponde {1}: errore del server su qualunque percorso (backend non raggiungibile dal gateway), punti di ingresso non verificabili", probeShown, miss.Status), miss);
                return phpOk;   // v1.6: ogni percorso riceve la stessa pagina di errore, né punti di ingresso né link insegnano qualcosa
            default:
                r.Add("L1-SURFACE-PROBE", L.T("Sonda del file .php inesistente"), miss.HasResponse ? TestOutcome.Info : TestOutcome.Error,
                    miss.HasResponse ? L.F("{0}: {1}, pagina 404 generica senza firma di PHP", probeShown, miss.Summary) : miss.Error ?? "", miss);
                break;
        }
        if (kind is MissingFileKind.Fpm or MissingFileKind.Cgi or MissingFileKind.ModPhp) r.PhpSurfaceProbe = kind.ToString();
        if (!miss.HasResponse && miss.ErrorKind is "connect" or "tls" or "reset") return phpOk;

        bool distinguishable = kind is not (MissingFileKind.CatchAll or MissingFileKind.RedirectAll or MissingFileKind.ForbiddenAll);

        // 2) punti di ingresso comuni + 3) link dai corpi già scaricati
        var candidates = new List<string>();
        if (distinguishable) candidates.AddRange(EntryPoints);
        foreach (var link in LinksFromBodies(ctx)) if (!candidates.Contains(link, StringComparer.OrdinalIgnoreCase)) candidates.Add(link);
        foreach (var p in ctx.Paths) candidates.Remove(p);

        int missStatus = miss.HasResponse ? miss.Status : -1;
        int checkedCount = 0;
        // indice, non foreach: robots.txt aggiunge candidati durante il giro (v1.3 lanciava "Collection was modified" e perdeva
        // SAPI, applicazione e livello 2 di ogni servizio con un robots.txt con Disallow: WordPress, Drupal, Matomo…)
        int skippedForBudget = 0;
        for (int i = 0; i < candidates.Count; i++)
        {
            string path = candidates[i];
            ctx.Ct.ThrowIfCancellationRequested();
            if (ctx.OverBudget) { skippedForBudget = candidates.Count - i; break; }   // v1.6: budget di tempo del servizio esaurito
            var s = await ctx.HeadAsync(path).ConfigureAwait(false);
            if (s.HasResponse && s.Status is 405 or 501) s = await ctx.GetAsync(path).ConfigureAwait(false);
            checkedCount++;
            if (!s.HasResponse)
            {
                if (s.ErrorKind is "connect" or "tls" or "reset") break;
                continue;
            }
            bool exists = s.Status is 200 or 204 or 401 or 403 or 405 || (s.Status is 301 or 302 or 303 or 307 or 308 && !IsGlobalRedirect(s, path));
            if (path is "/robots.txt" or "/sitemap.xml")
            {
                if (s.Status == 200)
                {
                    var g = await ctx.GetAsync(path).ConfigureAwait(false);
                    foreach (var extra in PathsFromRobots(g.Body).Take(10)) if (!candidates.Contains(extra, StringComparer.OrdinalIgnoreCase) && candidates.Count < EntryPoints.Length + MaxLinks + 10) candidates.Add(extra);
                }
                continue;
            }
            if (!exists || s.Status == missStatus) continue;
            found.Add($"{path} ({s.Status})");
            if (path.EndsWith(".php", StringComparison.OrdinalIgnoreCase) && s.Status is 200 or 401) phpOk.Add(path);
        }

        r.PhpSurface = found;
        if (skippedForBudget > 0) r.SkippedForBudget.Add(L.F("superficie PHP ({0} punti di ingresso non provati)", skippedForBudget));
        if (found.Count > 0)
            r.Add("L1-SURFACE", L.T("Superficie PHP scoperta"), TestOutcome.Info,
                L.F("{0} percorsi esistenti su {1} provati: {2}", found.Count, checkedCount, string.Join(", ", found.Take(25)) + (found.Count > 25 ? " …" : "")));
        else if (checkedCount > 0)
            r.Add("L1-SURFACE", L.T("Superficie PHP scoperta"), TestOutcome.Info, L.F("nessun punto di ingresso noto tra i {0} provati", checkedCount));
        return phpOk;
    }

    private static void SetSapi(ScanResult r, string sapi, string evidence)
    {
        r.Sapi = sapi;
        r.SapiEvidence = evidence;
    }

    /// <summary>Redirect "globale" (http→https o verso un altro host con lo stesso percorso): non dice nulla sull'esistenza del percorso.</summary>
    public static bool IsGlobalRedirect(HttpSnapshot s, string path)
    {
        string loc = s.Header("Location") ?? "";
        if (loc.Length == 0) return true;
        if (Uri.TryCreate(loc, UriKind.Absolute, out var u)) return u.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase) || u.AbsolutePath.TrimEnd('/').Equals(path.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
        return loc.TrimEnd('/').Equals(path.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Percorsi .php sullo stesso host presi da href/src/action dei corpi già scaricati (relativi o assoluti verso lo stesso host).</summary>
    public static List<string> LinksFromBodies(ScanContext ctx)
    {
        var list = new List<string>();
        foreach (var s in ctx.Result.Requests.Where(q => q.HasResponse && q.Method == "GET" && q.Body.Length > 0))
        {
            foreach (Match m in LinkRx.Matches(s.Body))
            {
                string v = m.Groups[1].Value.Trim();
                string? path = ToSameHostPath(v, ctx.Endpoint.Host, ctx.Result.HostHeader);
                if (path == null || path.Length > 200) continue;
                if (!list.Contains(path, StringComparer.OrdinalIgnoreCase)) list.Add(path);
                if (list.Count >= MaxLinks) return list;
            }
        }
        return list;
    }

    private static string? ToSameHostPath(string href, string host, string hostHeader)
    {
        if (href.StartsWith("//", StringComparison.Ordinal)) href = "https:" + href;
        if (Uri.TryCreate(href, UriKind.Absolute, out var abs))
        {
            if (abs.Scheme is not ("http" or "https")) return null;
            bool same = abs.Host.Equals(host, StringComparison.OrdinalIgnoreCase) || (hostHeader.Length > 0 && abs.Host.Equals(hostHeader, StringComparison.OrdinalIgnoreCase));
            return same ? abs.AbsolutePath : null;
        }
        if (href.StartsWith('/')) return href.Split('?')[0];
        if (href.Contains(':')) return null;   // mailto:, javascript:, data:
        return "/" + href.Split('?')[0].TrimStart("./".ToCharArray());
    }

    public static IEnumerable<string> PathsFromRobots(string body)
    {
        foreach (Match m in RobotsRx.Matches(body))
        {
            string p = m.Groups[1].Value.Trim();
            if (p.Length > 1 && p.Length < 120 && !p.Contains('*') && !p.Contains('$')) yield return p;
        }
    }

    private static string RandomName()
    {
        Span<byte> b = stackalloc byte[6];
        RandomNumberGenerator.Fill(b);
        return "pvs" + Convert.ToHexString(b).ToLowerInvariant();
    }
}
