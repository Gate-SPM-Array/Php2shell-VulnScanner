using System.Net;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// v1.5: lettura delle impostazioni da una pagina phpinfo() già scaricata (nessuna richiesta in più).
/// Estrae le direttive che contano per PHP2Shell (session.upload_progress.*, session.serialize_handler, session.save_handler…)
/// e il contesto (Server API, versione, sistema, file di configurazione) in <see cref="ScanResult.IniHints"/> come "nome=valore".
/// Solo il valore locale; nessun segreto (session.save_path è un percorso, non una credenziale).
/// </summary>
public static class PhpInfoParser
{
    /// <summary>Direttive e righe estratte, nell'ordine di uscita.</summary>
    public static readonly string[] Wanted =
    [
        "PHP Version", "System", "Server API", "Loaded Configuration File",
        "session.upload_progress.enabled", "session.upload_progress.name", "session.upload_progress.cleanup",
        "session.serialize_handler", "session.save_handler", "session.save_path",
        "expose_php", "memory_limit", "post_max_size", "upload_max_filesize", "max_input_vars",
        "display_errors", "allow_url_fopen", "disable_functions", "open_basedir",
    ];

    private static readonly Regex RowRx = new(
        @"<tr[^>]*>\s*<td[^>]*class=[""']?e[""']?[^>]*>(?<n>.*?)</td>\s*<td[^>]*class=[""']?v[""']?[^>]*>(?<l>.*?)</td>(?:\s*<td[^>]*class=[""']?v[""']?[^>]*>(?<m>.*?)</td>)?\s*</tr>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex H1Rx = new(@"<h1[^>]*class=[""']?p[""']?[^>]*>\s*PHP Version\s*(?<v>[^<]+?)\s*</h1>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex TagRx = new(@"<[^>]+>", RegexOptions.CultureInvariant);
    private static readonly Regex WsRx = new(@"\s+", RegexOptions.CultureInvariant);
    private static readonly Regex PhpInfoRx = new(@"PHP Version\s*(?:</[^>]+>\s*)?(?:<[^>]+>\s*)*(\d+\.\d+\.\d+[A-Za-z0-9~+._-]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Vero quando il corpo è una pagina phpinfo (stessa euristica di PhpFingerprint e AdvancedProbes).</summary>
    public static bool LooksLikePhpInfo(string body) =>
        body.Length > 0 && (PhpInfoRx.IsMatch(body) || body.Contains("phpinfo()", StringComparison.OrdinalIgnoreCase) || body.Contains("PHP License", StringComparison.Ordinal));

    /// <summary>Estrae "nome=valore" (valore locale) per le direttive in <see cref="Wanted"/>; tollera spazi, entità e la forma a due colonne.</summary>
    public static List<string> Parse(string html)
    {
        var found = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var h1 = H1Rx.Match(html);
        if (h1.Success) found["PHP Version"] = Clean(h1.Groups["v"].Value);

        foreach (Match m in RowRx.Matches(html))
        {
            string name = Clean(m.Groups["n"].Value);
            if (name.Length == 0 || found.ContainsKey(name)) continue;
            if (!Wanted.Contains(name, StringComparer.OrdinalIgnoreCase)) continue;
            string local = Clean(m.Groups["l"].Value);
            found[name] = local;
        }

        var list = new List<string>();
        foreach (var w in Wanted)
        {
            if (!found.TryGetValue(w, out var v)) continue;
            int max = w == "disable_functions" ? 200 : w == "System" ? 120 : 300;
            if (v.Length > max) v = v[..max] + "...";
            list.Add(w + "=" + v);
        }
        return list;
    }

    /// <summary>SAPI dal valore "Server API" di phpinfo: "fpm", "mod_php", "cgi", "lsapi" oppure "".</summary>
    public static string SapiFromServerApi(string serverApi)
    {
        string v = serverApi.Trim();
        if (v.Contains("FPM", StringComparison.OrdinalIgnoreCase)) return "fpm";
        if (v.Contains("Apache", StringComparison.OrdinalIgnoreCase) && v.Contains("Handler", StringComparison.OrdinalIgnoreCase)) return "mod_php";
        if (v.Contains("LiteSpeed", StringComparison.OrdinalIgnoreCase)) return "lsapi";
        if (v.Contains("CGI", StringComparison.OrdinalIgnoreCase)) return "cgi";
        return "";
    }

    /// <summary>Cerca tra le risposte una pagina phpinfo, compila IniHints, SAPI (se vuota) e la riga di evidenza L1-PHPINFO-INI. Idempotente.</summary>
    public static void Apply(ScanResult r)
    {
        var snap = r.Requests.FirstOrDefault(s => s.HasResponse && s.Status == 200 && LooksLikePhpInfo(s.Body));
        if (snap == null) return;
        var ini = Parse(snap.Body);
        r.IniHints = ini;
        r.Tests.RemoveAll(t => t.Id == "L1-PHPINFO-INI");
        if (ini.Count == 0) return;

        string Get(string name) => ini.FirstOrDefault(x => x.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))?[(name.Length + 1)..] ?? "";

        string sapiRaw = Get("Server API");
        if (sapiRaw.Length > 0 && r.Sapi.Length == 0)
        {
            string sapi = SapiFromServerApi(sapiRaw);
            if (sapi.Length > 0)
            {
                r.Sapi = sapi;
                r.SapiEvidence = L.F("Server API in phpinfo: {0}", sapiRaw);
            }
        }

        var parts = new List<string>();
        string up = Get("session.upload_progress.enabled");
        bool? upOn = IsOn(up);
        if (upOn != null)
            parts.Add(L.F("session.upload_progress.enabled={0}: {1}", up,
                upOn == false
                    ? L.T("mitigazione per CVE-2026-109619 e CVE-2026-115560 applicata")
                    : L.T("esposto a CVE-2026-115560 se l'applicazione cambia session.serialize_handler a runtime; mitigazione per CVE-2026-109619 non applicata")));
        string sh = Get("session.serialize_handler");
        if (sh.Length > 0) parts.Add("session.serialize_handler=" + sh);
        if (sapiRaw.Length > 0) parts.Add("Server API=" + sapiRaw);
        string ml = Get("memory_limit"), pm = Get("post_max_size");
        if (ml.Length > 0) parts.Add("memory_limit=" + ml);
        if (pm.Length > 0) parts.Add("post_max_size=" + pm);
        if (parts.Count == 0) parts.Add(string.Join(", ", ini.Take(4)));

        r.Add("L1-PHPINFO-INI", L.T("Impostazioni dalla pagina phpinfo"), upOn == true ? TestOutcome.Warn : TestOutcome.Info, string.Join("; ", parts));
    }

    /// <summary>On/1/true → vero; Off/0/no value/vuoto → falso; null se il valore manca.</summary>
    private static bool? IsOn(string v)
    {
        if (v.Length == 0) return null;
        string t = v.Trim();
        if (t.Equals("On", StringComparison.OrdinalIgnoreCase) || t == "1" || t.Equals("true", StringComparison.OrdinalIgnoreCase) || t.Equals("yes", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string Clean(string cell)
    {
        string s = TagRx.Replace(cell, " ");
        s = WebUtility.HtmlDecode(s).Replace(' ', ' ');
        return WsRx.Replace(s, " ").Trim();
    }
}
