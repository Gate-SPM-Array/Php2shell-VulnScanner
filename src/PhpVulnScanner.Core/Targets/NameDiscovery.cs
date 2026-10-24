using System.Net;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;

namespace PhpVulnScanner.Core.Targets;

/// <summary>
/// Raccolta dei nomi DNS che un IP "confessa" da solo: CN e SAN del certificato TLS, host delle intestazioni Location,
/// (i link nei corpi restano fuori: puntano a CDN e servizi terzi). Una scansione per IP vede solo il vhost predefinito: con questi nomi la seconda
/// passata (Host e SNI = nome, TCP verso lo stesso IP) raggiunge i siti veri. Nessuna richiesta, nessun DNS.
/// </summary>
public static class NameDiscovery
{
    private static readonly Regex LabelRx = new(@"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant);
    private static readonly HashSet<string> FileExtensions = new(StringComparer.OrdinalIgnoreCase)
        { "php", "html", "htm", "aspx", "asp", "jsp", "js", "css", "json", "xml", "txt", "png", "jpg", "gif", "svg", "ico", "pdf", "do", "action", "cgi", "pl" };

    /// <summary>TLD di tre lettere riconosciuti (IANA, i più diffusi): un TLD di tre lettere fuori da questo elenco (es. "clp" dei certificati interni di CloudPanel) non è un nome pubblico. Due lettere = ccTLD, sempre accettato; quattro o più lettere = gTLD nuovi, accettati.</summary>
    private static readonly HashSet<string> ThreeLetterTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "com", "net", "org", "edu", "gov", "mil", "int", "biz", "pro", "cat", "tel", "xxx", "app", "dev", "xyz", "top", "art", "bar", "bet", "bid", "bio", "box", "buy", "cab", "cam", "car", "ceo", "cfd", "com", "day", "dog", "eat", "eco", "eus", "fan", "fit", "fun", "fyi", "gal", "gay", "gdn", "gle", "gmx", "goo", "hiv", "hot", "how", "ibm", "ice", "ink", "jio", "jmp", "jot", "joy", "kim", "kpn", "krd", "law", "lol", "ltd", "men", "mma", "moe", "moi", "mom", "mov", "msd", "nab", "nba", "new", "nhk", "now", "nra", "nrw", "ntt", "nyc", "one", "ong", "onl", "ooo", "org", "ott", "ovh", "pay", "pet", "phd", "pid", "pin", "pnc", "pub", "pwc", "qvc", "red", "ren", "ril", "rio", "rip", "run", "rwe", "sap", "sbi", "sbs", "scb", "ses", "sew", "sex", "sfr", "ski", "sky", "soy", "spa", "srl", "stc", "tab", "tax", "tci", "tdk", "tjx", "top", "trv", "tui", "tvs", "ubs", "uno", "uol", "ups", "vet", "vig", "vin", "vip", "wed", "win", "wme", "wow", "wtc", "wtf", "you", "yun", "zip", "abb", "abc", "aco", "ads", "aeg", "afl", "aig", "anz", "aol", "arpa", "aws", "axa", "bbc", "bbt", "bcg", "bcn", "bms", "bmw", "bnl", "bom", "boo", "bot", "bzh", "cal", "cba", "cbn", "cbs", "crs", "csc", "dad", "dds", "dhl", "diy", "dnp", "dot", "dtv", "dvr", "esq", "fly", "foo", "frl", "ftr", "gap", "gea", "gmo", "got", "hbo", "hkt", "htc", "ifm", "img", "itv", "jcb", "jll", "jnj", "kfh", "kia", "lat", "lds", "llc", "llp", "map", "mba", "mit", "mlb", "mls", "mtn", "mtr", "nec", "nfl", "ngo", "nhk", "pru", "qpon", "rmit", "sca", "scot", "sksy", "tdk", "thd", "tkmaxx", "vana", "wien", "wiki", "zara",
    };

    /// <summary>Nome DNS valido e plausibile: etichette regolari, almeno un punto, non un IP, ultima etichetta alfabetica e non un'estensione di file (scarta i redirect "incollati" come host.itindex.php).</summary>
    public static bool IsValidHostName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        name = name.Trim().TrimEnd('.').ToLowerInvariant();
        if (name.Length > 253 || !name.Contains('.')) return false;
        if (IPAddress.TryParse(name, out _)) return false;
        var labels = name.Split('.');
        if (labels.Any(l => !LabelRx.IsMatch(l))) return false;
        string tld = labels[^1];
        if (!tld.All(char.IsAsciiLetter) || tld.Length < 2 || FileExtensions.Contains(tld)) return false;
        if (tld.Length == 3 && !ThreeLetterTlds.Contains(tld)) return false;
        if (name.EndsWith(".local", StringComparison.Ordinal) || name.EndsWith(".localhost", StringComparison.Ordinal) || name.EndsWith(".invalid", StringComparison.Ordinal)) return false;
        return true;
    }

    /// <summary>Nomi dal risultato, in ordine di scoperta: prima il certificato, poi le Location, poi i link. I wildcard (*.dominio) restano come informazione ma non sono scansionabili.</summary>
    public static List<string> Collect(ScanResult r)
    {
        var names = new List<string>();
        void Add(string? n)
        {
            if (n == null) return;
            n = n.Trim().TrimEnd('.').ToLowerInvariant();
            bool wildcard = n.StartsWith("*.", StringComparison.Ordinal);
            string check = wildcard ? n[2..] : n;
            if (!IsValidHostName(check)) return;
            if (!names.Contains(n)) names.Add(n);
        }
        if (r.Tls is { Handshake: true } tls)
        {
            var cn = Regex.Match(tls.Subject, @"(?:^|,\s*)CN=([^,]+)");
            Add(cn.Success ? cn.Groups[1].Value : tls.Subject);
            foreach (var san in tls.SubjectAltNames) Add(san);
        }
        foreach (var q in r.Requests)
        {
            foreach (var h in q.Headers)
            {
                if (!h.Key.Equals("Location", StringComparison.OrdinalIgnoreCase)) continue;
                if (Uri.TryCreate(h.Value, UriKind.Absolute, out var u) && u.Scheme is "http" or "https") Add(u.Host);
            }
        }
        // I link assoluti nei corpi (CDN, font, tracker) non sono vhost di questo IP: restano fuori per non sprecare passate.
        return names;
    }

    /// <summary>Nomi su cui vale la pena una seconda passata: non wildcard, diversi dall'host e dal nome già usato come Host, al massimo <paramref name="max"/>.</summary>
    public static List<string> Rescannable(IEnumerable<string> names, string host, string? usedHostHeader, int max)
    {
        var list = new List<string>();
        foreach (var n in names)
        {
            if (n.StartsWith("*.", StringComparison.Ordinal)) continue;
            if (n.Equals(host, StringComparison.OrdinalIgnoreCase)) continue;
            if (usedHostHeader != null && n.Equals(usedHostHeader, StringComparison.OrdinalIgnoreCase)) continue;
            if (!list.Contains(n)) list.Add(n);
            if (list.Count >= max) break;
        }
        return list;
    }
}
