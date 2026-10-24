using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Apps;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// Deduzioni passive dai banner e dai corpi già scaricati: SAPI (mod_php contro FPM), sistema operativo o distribuzione,
/// applicazione PHP riconosciuta. Nessuna richiesta aggiuntiva. Tutto è dichiarato come indizio con la sua evidenza.
/// </summary>
public static class StackFingerprint
{
    public const string NcscInventoryBase = "https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_";

    private sealed record AppSig(string Name, string Where, Regex Rx, string Letter);
    private static AppSig Body(string name, string pattern, string letter) => new(name, "body", new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), letter);
    private static AppSig Cookie(string name, string pattern, string letter) => new(name, "cookie", new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), letter);
    private static AppSig Header(string name, string pattern, string letter) => new(name, "header", new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant), letter);

    /// <summary>Firme di applicazioni PHP diffuse; la lettera rimanda alla pagina dell'inventario NCSC-NL.</summary>
    private static readonly AppSig[] Apps =
    [
        Body("WordPress", @"<meta name=""generator"" content=""WordPress|/wp-content/|/wp-includes/|wp-json", "w"),
        Cookie("WordPress", @"^(wordpress_|wp-settings-)", "w"),
        Body("Joomla", @"<meta name=""generator"" content=""Joomla|/media/jui/|/media/system/js/", "j"),
        Header("Drupal", @"^X-Generator: Drupal|^X-Drupal-", "d"),
        Body("Drupal", @"<meta name=""generator"" content=""Drupal|/sites/default/files/|drupal-settings-json", "d"),
        Body("phpMyAdmin", @"phpMyAdmin|pma_|phpmyadmin\.css", "p"),
        Cookie("phpMyAdmin", @"^(phpMyAdmin|pma_lang|pmaCookieVer)", "p"),
        Body("Nextcloud", @"Nextcloud|/core/css/|oc_sessionPassphrase|data-requesttoken", "n"),
        Cookie("Nextcloud", @"^(nc_session_id|oc_sessionPassphrase|nc_token)", "n"),
        Cookie("ownCloud", @"^(oc[a-z0-9]{10,}|ocPassphrase)", "o"),
        Cookie("Laravel", @"^(laravel_session|XSRF-TOKEN)", "l"),
        Cookie("Symfony", @"^(sf_redirect|MOCKSESSID)", "s"),
        Cookie("CakePHP", @"^CAKEPHP=", "c"),
        Cookie("Moodle", @"^MoodleSession", "m"),
        Body("Moodle", @"<meta name=""keywords"" content=""moodle|M\.cfg\s*=", "m"),
        Cookie("GLPI", @"^glpi_", "g"),
        Body("GLPI", @"GLPI - Authentication|/glpi/", "g"),
        Cookie("TYPO3", @"^(fe_typo_user|be_typo_user)", "t"),
        Body("TYPO3", @"<meta name=""generator"" content=""TYPO3", "t"),
        Cookie("PrestaShop", @"^PrestaShop-", "p"),
        Header("Magento", @"^X-Magento-", "m"),
        Cookie("Magento", @"^(mage-|form_key|PHPSESSID.*store)", "m"),
        Body("MediaWiki", @"<meta name=""generator"" content=""MediaWiki|mw-config|/load\.php\?", "m"),
        Cookie("Roundcube", @"^roundcube_sessid", "r"),
        Body("Roundcube", @"Roundcube Webmail|rcmail", "r"),
        Cookie("Zabbix", @"^zbx_session", "z"),
        Cookie("Matomo", @"^(MATOMO_SESSID|PIWIK_SESSID)", "m"),
        Cookie("Dolibarr", @"^DOLSESSID", "d"),
        Body("SuiteCRM", @"SuiteCRM|sugar_user_theme", "s"),
        Body("osTicket", @"osTicket|/scp/login\.php", "o"),
        Body("Zimbra", @"Zimbra Web Client", "z"),
        Header("Plesk", @"^X-Powered-By: Plesk", "p"),
        Cookie("cPanel", @"^cpsession", "c"),
        Body("Horde", @"Horde Groupware|horde\.js", "h"),
        Body("MantisBT", @"MantisBT|mantis\.css", "m"),
        Body("Piwigo", @"Piwigo", "p"),
        Body("OpenCart", @"index\.php\?route=|OpenCart", "o"),
        Body("Craft CMS", @"<meta name=""generator"" content=""Craft", "c"),
        Body("Concrete CMS", @"<meta name=""generator"" content=""concrete", "c"),
        Body("Grav", @"<meta name=""generator"" content=""Grav", "g"),
        Body("Kirby", @"<meta name=""generator"" content=""Kirby", "k"),
        Body("Vanilla Forums", @"<meta name=""generator"" content=""Vanilla", "v"),
        Body("phpBB", @"phpBB|/styles/prosilver/", "p"),
        Body("MyBB", @"MyBB|mybb_", "m"),
        Body("XenForo", @"XenForo", "x"),
        Body("Invision Community", @"ips\.setSetting|Invision Community", "i"),
        Body("Adminer", @"Adminer", "a"),
        Body("LimeSurvey", @"LimeSurvey", "l"),
        Body("Dokuwiki", @"DokuWiki|dokuwiki", "d"),
        Body("YOURLS", @"YOURLS", "y"),
        Body("FreePBX", @"FreePBX", "f"),
        Body("Icinga Web", @"Icinga Web", "i"),
        Body("LibreNMS", @"LibreNMS", "l"),
        Body("Cacti", @"Cacti", "c"),
    ];

    public static void Apply(ScanResult r, IReadOnlyList<HttpSnapshot> responses)
    {
        var ok = responses.Where(s => s.HasResponse).ToList();
        if (ok.Count == 0) return;

        // SAPI
        string server = r.ServerHeader;
        string powered = r.PoweredBy;
        bool phpInServer = Regex.IsMatch(server, @"\bPHP/\d", RegexOptions.IgnoreCase);
        bool phpPowered = powered.Contains("PHP", StringComparison.OrdinalIgnoreCase);
        bool fcgiModule = Regex.IsMatch(server, @"mod_fcgid|mod_proxy_fcgi|proxy_fcgi", RegexOptions.IgnoreCase);
        if (r.Sapi.Length > 0 && r.SapiEvidence.Length > 0)
        {
            // già dedotta da una prova più diretta (sonda del file inesistente): non si tocca
        }
        else if (fcgiModule && (phpInServer || phpPowered || r.PhpDetected))
        {
            // mod_fcgid nel banner: PHP gira come FastCGI (php-cgi), non come modulo; la versione può comparire comunque nel banner
            r.Sapi = "cgi"; r.SapiEvidence = L.F("il banner Server dichiara un modulo FastCGI: {0}", server);
        }
        else if (phpInServer)
        {
            r.Sapi = "mod_php"; r.SapiEvidence = L.F("il banner Server include PHP: {0}", server);
        }
        else if (Regex.IsMatch(server, @"^(nginx|LiteSpeed|Caddy|openresty|lighttpd)", RegexOptions.IgnoreCase) && (phpPowered || r.PhpDetected))
        {
            r.Sapi = Regex.IsMatch(server, "LiteSpeed", RegexOptions.IgnoreCase) ? "lsapi" : "fpm";
            r.SapiEvidence = L.F("{0} davanti a PHP: FastCGI (FPM) o LSAPI, mai mod_php", server);
        }
        else if (Regex.IsMatch(server, @"^Apache", RegexOptions.IgnoreCase) && phpPowered)
        {
            r.Sapi = ""; r.SapiEvidence = L.T("Apache con PHP: mod_php o php-fpm via proxy_fcgi, non distinguibile dal banner (ServerTokens ridotto)");
        }
        else if (Regex.IsMatch(server, @"^Microsoft-IIS", RegexOptions.IgnoreCase) && phpPowered)
        {
            r.Sapi = "cgi"; r.SapiEvidence = L.F("{0} con PHP: FastCGI (php-cgi)", server);
        }

        // Sistema operativo / distribuzione dal banner
        var os = Regex.Match(server, @"\((Debian|Ubuntu|Red Hat(?: Enterprise Linux)?|CentOS|Rocky Linux|AlmaLinux|Fedora|Oracle(?: Linux(?: Server)?)?|SUSE|openSUSE|Amazon|FreeBSD|OpenBSD|Win32|Win64|Windows)\)", RegexOptions.IgnoreCase);
        if (os.Success) r.OsHint = NormalizeOs(os.Groups[1].Value);
        else if (Regex.IsMatch(server, "^Microsoft-(IIS|HTTPAPI)", RegexOptions.IgnoreCase)) r.OsHint = "Windows";
        else if (powered.Contains("PleskLin", StringComparison.OrdinalIgnoreCase)) r.OsHint = "Linux (Plesk)";
        else if (powered.Contains("PleskWin", StringComparison.OrdinalIgnoreCase)) r.OsHint = "Windows (Plesk)";
        if (r.OsHint.Length == 0 && Regex.IsMatch(r.PhpVersionRaw, @"deb\d|ubuntu", RegexOptions.IgnoreCase))
            r.OsHint = r.PhpVersionRaw.Contains("ubuntu", StringComparison.OrdinalIgnoreCase) ? "Ubuntu" : "Debian";

        // Applicazione
        foreach (var sig in Apps)
        {
            string? ev = null;
            foreach (var s in ok)
            {
                if (sig.Where == "body") { var m = sig.Rx.Match(s.Body); if (m.Success) { ev = L.F("corpo di {0}: \"{1}\"", Path(s.Url), Short(m.Value)); break; } }
                else if (sig.Where == "cookie") { var c = s.HeaderValues("Set-Cookie").FirstOrDefault(v => sig.Rx.IsMatch(v)); if (c != null) { ev = "Set-Cookie: " + c.Split('=')[0]; break; } }
                else { var h = s.Headers.FirstOrDefault(h => sig.Rx.IsMatch($"{h.Key}: {h.Value}")); if (h.Key != null) { ev = $"{h.Key}: {Short(h.Value)}"; break; } }
            }
            if (ev == null) continue;
            r.Application = sig.Name;
            r.ApplicationEvidence = ev;
            r.ApplicationReference = NcscInventoryBase + sig.Letter + ".md";
            break;
        }

        // Database delle tecnologie (webappanalyzer + inventario NCSC-NL): completa, non sostituisce, le firme a mano
        TechnologyDatabase.ApplyTo(r, ok);
    }

    /// <summary>Nomi di distribuzione uniformi (centos/CentOS, Win64 → Windows), così i filtri e i conteggi non si spezzano sulle maiuscole.</summary>
    public static string NormalizeOs(string s) => s.ToLowerInvariant() switch
    {
        "centos" => "CentOS",
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "rocky linux" => "Rocky Linux",
        "almalinux" => "AlmaLinux",
        "fedora" => "Fedora",
        "red hat" or "red hat enterprise linux" => "Red Hat",
        "oracle" or "oracle linux" or "oracle linux server" => "Oracle Linux",
        "suse" or "opensuse" => "SUSE",
        "amazon" => "Amazon Linux",
        "freebsd" => "FreeBSD",
        "openbsd" => "OpenBSD",
        "win32" or "win64" or "windows" => "Windows",
        _ => s,
    };

    private static string Path(string url)
    {
        int i = url.IndexOf("://", StringComparison.Ordinal);
        int s = i < 0 ? -1 : url.IndexOf('/', i + 3);
        return s < 0 ? "/" : url[s..];
    }

    private static string Short(string s) => s.Length <= 60 ? s : s[..57] + "...";
}
