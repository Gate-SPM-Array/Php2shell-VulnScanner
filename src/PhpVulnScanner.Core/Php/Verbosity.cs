using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// v1.5: indice di loquacità 0-5, quanto l'host racconta di sé senza che nessuno glielo chieda (versioni nei banner, phpinfo,
/// directory listing, pagine di stato e di debug, composer, repository e file di ambiente, nomi interni nel certificato, TRACE).
/// Somma pesata delle voci poi tagliata a 5; le voci restano in <see cref="ScanResult.VerbosityItems"/> come "peso: descrizione".
/// Dipende dalle sonde avanzate, perciò viene calcolato alla fine di VerdictEngine.Apply. Idempotente.
/// </summary>
public static class Verbosity
{
    public const int Max = 5;

    private static readonly Regex VersionDigitRx = new(@"/\d", RegexOptions.CultureInvariant);
    private static readonly Regex InternalNameRx = new(@"(\.(local|lan|internal|corp|intranet|home|localdomain)$)|(^localhost$)|(^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static void Compute(ScanResult r)
    {
        var items = new List<string>();
        int sum = 0;
        void Item(int weight, string text) { items.Add(weight + ": " + text); sum += weight; }

        bool phpinfo = r.IniHints.Count > 0 || r.Exposures.Any(e => e.Contains("phpinfo", StringComparison.OrdinalIgnoreCase))
                       || r.Tests.Any(t => t.Id is "L1-PHPINFO" or "ADV-PHPINFO");
        if (phpinfo) Item(2, L.T("pagina phpinfo esposta"));

        if (r.PhpVersionRaw.Length > 0 && r.PhpVersionSource is "X-Powered-By" or "Server")
            Item(1, L.F("versione di PHP nell'intestazione {0}", r.PhpVersionSource));

        if (VersionDigitRx.IsMatch(r.ServerHeader)) Item(1, L.F("versione del server web nel banner ({0})", Short(r.ServerHeader)));

        if (r.OsHint.Length > 0) Item(1, L.F("sistema operativo o distribuzione dichiarati ({0})", r.OsHint));

        bool listing = r.Exposures.Any(e => e.Contains("directory listing", StringComparison.OrdinalIgnoreCase) || e.Contains("Index of", StringComparison.OrdinalIgnoreCase))
                       || r.Requests.Any(s => s.HasResponse && s.Body.Contains("<title>Index of /", StringComparison.OrdinalIgnoreCase));
        if (listing) Item(2, L.T("directory listing esposto"));

        bool status = r.Tests.Any(t => t.Id.StartsWith("ADV-STATUS-", StringComparison.Ordinal))
                      || r.Exposures.Any(e => Regex.IsMatch(e, @"^/(server-status|server-info|nginx_status|status|fpm-status|php-fpm-status|fpm_status)\b", RegexOptions.IgnoreCase));
        if (status) Item(2, L.T("pagine di stato del server o di PHP-FPM leggibili"));

        bool debug = r.Tests.Any(t => t.Id == "ADV-DEBUGPAGE") || r.Exposures.Any(e => e.Contains("debug", StringComparison.OrdinalIgnoreCase));
        if (debug) Item(2, L.T("pagine di debug o stack trace raggiungibili"));

        if (r.Libraries.Count > 0 || r.PhpVersionFloor.Length > 0) Item(1, L.T("composer.json o installed.json leggibili"));

        bool repo = r.Exposures.Any(e => Regex.IsMatch(e, @"^/\.(git|svn|env)\b|backup|\.bak\b|\.sql\b", RegexOptions.IgnoreCase));
        if (repo) Item(1, L.T("repository, file di ambiente o backup raggiungibili"));

        var internalNames = (r.Tls?.SubjectAltNames ?? []).Concat(r.Tls == null ? [] : [r.Tls.Subject])
            .Where(n => !string.IsNullOrWhiteSpace(n) && InternalNameRx.IsMatch(n.Trim())).Distinct(StringComparer.OrdinalIgnoreCase).Take(3).ToList();
        if (internalNames.Count > 0) Item(1, L.F("nomi interni nel certificato ({0})", string.Join(", ", internalNames)));

        if (r.ApplicationVersion.Length > 0) Item(1, L.F("versione dell'applicazione dichiarata ({0})", r.ApplicationVersion));

        if (Regex.IsMatch(r.AllowedMethods, @"\bTRACE\b", RegexOptions.IgnoreCase)) Item(1, L.T("metodo TRACE consentito"));

        r.VerbosityItems = items;
        r.VerbosityScore = Math.Min(Max, sum);

        r.Tests.RemoveAll(t => t.Id == "L1-VERBOSITY");
        if (r.VerbosityScore > 0)
            r.Add("L1-VERBOSITY", L.T("Loquacità dell'host"), TestOutcome.Info, L.F("{0}/5: {1}", r.VerbosityScore, string.Join("; ", items)));
    }

    private static string Short(string v) => v.Length <= 60 ? v : v[..57] + "...";
}
