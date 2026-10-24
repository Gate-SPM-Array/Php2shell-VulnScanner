using System.Text;
using System.Text.Json;

namespace PhpVulnScanner.Core.Apps;

/// <summary>Asserzione VEX dell'inventario NCSC-NL per una CVE: stato (chiave stabile: Affected, Fixed, NotAffected, UnderInvestigation),
/// versione corretta quando dichiarata, nota originale e riferimento.</summary>
public sealed record NcscVex(string Status, string FixedVersion, string Note, string Reference);

/// <summary>Pacchetto dell'inventario PHP2Shell di NCSC-NL (software/spdx/PHP_Downstream_Inventory.spdx3.json), con il rimando alla pagina
/// pubblica software_list_&lt;lettera&gt;.md dove lo stato viene aggiornato nel tempo.</summary>
public sealed record NcscPackage(string Name, IReadOnlyList<string> Aliases, string Category, string Url, string Reference, IReadOnlyDictionary<string, NcscVex> Vex);

/// <summary>
/// Inventario NCSC-NL dei prodotti che dipendono da PHP, caricato da <c>data/ncsc_inventory.json</c> (prodotto da tools/build_appdb.py).
/// La ricerca per nome è tollerante: nome esatto, alias, poi confronto senza maiuscole e punteggiatura ("phpMyAdmin"/"phpmyadmin",
/// "Craft CMS"/"CraftCMS"), infine il pacchetto che aggiunge al nome solo qualificatori generici ("Grav" → "Grav CMS", "Zabbix" → "Zabbix web frontend").
/// </summary>
public sealed class NcscInventory
{
    private readonly List<NcscPackage> _packages;
    private readonly Dictionary<string, NcscPackage> _byName = new(StringComparer.Ordinal);
    private readonly Dictionary<string, NcscPackage> _byNameCi = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, NcscPackage> _byAlias = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, NcscPackage> _byNormalized = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<(string[] Words, NcscPackage Package)>> _byFirstWord = new(StringComparer.Ordinal);

    /// <summary>Parole che un nome di pacchetto può aggiungere al nome della tecnologia senza cambiare prodotto.</summary>
    private static readonly HashSet<string> GenericWords = new(StringComparer.Ordinal)
    {
        "cms", "framework", "webmail", "server", "core", "edition", "community", "classic", "premise", "on", "for", "and",
        "linux", "windows", "web", "frontend", "lms", "erp", "crm", "php", "application", "open", "source", "management",
        "groupware", "platform", "project", "suite", "x", "lts", "analytics",
    };

    public static readonly NcscInventory Empty = new([]);

    public NcscInventory(IEnumerable<NcscPackage> packages)
    {
        _packages = packages.ToList();
        foreach (var p in _packages)
        {
            _byName.TryAdd(p.Name, p);
            _byNameCi.TryAdd(p.Name, p);
            _byNormalized.TryAdd(Normalize(p.Name), p);
            var words = Words(p.Name);
            if (words.Length > 0)
            {
                if (!_byFirstWord.TryGetValue(words[0], out var list)) _byFirstWord[words[0]] = list = [];
                list.Add((words, p));
            }
        }
        // gli alias dopo i nomi: un nome ha sempre la precedenza su un alias omonimo. Gli alias "piatti" delle estensioni PHP
        // ("openssl", "curl", "json", "session"…) non valgono come chiave: "OpenSSL" del banner Apache non è "PHP OpenSSL extension".
        foreach (var p in _packages)
            foreach (var a in p.Aliases)
            {
                if (!AliasIsDistinctive(a)) continue;
                _byAlias.TryAdd(a, p);
                _byNormalized.TryAdd(Normalize(a), p);
            }
    }

    /// <summary>Un alias è usabile come chiave se contiene un separatore, un punto, una cifra o una maiuscola ("phpmyadmin/phpmyadmin", "WordPress.org", "Laravel 13", "MyBulletinBoard").</summary>
    internal static bool AliasIsDistinctive(string alias) => alias.Any(c => !(c is >= 'a' and <= 'z'));

    public int Count => _packages.Count;
    public int VexCount => _packages.Sum(p => p.Vex.Count);
    public IReadOnlyList<NcscPackage> Packages => _packages;

    /// <summary>Legge il file <c>ncsc_inventory.json</c>.</summary>
    public static NcscInventory LoadFile(string path)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException(L.F("{0}: atteso un elenco JSON di pacchetti", Path.GetFileName(path)));
        var list = new List<NcscPackage>();
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            string name = Str(e, "name");
            if (name.Length == 0) continue;
            var aliases = new List<string>();
            if (e.TryGetProperty("aliases", out var al) && al.ValueKind == JsonValueKind.Array)
                foreach (var a in al.EnumerateArray()) if (a.ValueKind == JsonValueKind.String && a.GetString() is { Length: > 0 } s) aliases.Add(s);
            var vex = new Dictionary<string, NcscVex>(StringComparer.OrdinalIgnoreCase);
            if (e.TryGetProperty("vex", out var vx) && vx.ValueKind == JsonValueKind.Object)
                foreach (var cve in vx.EnumerateObject())
                    vex[cve.Name] = new NcscVex(Str(cve.Value, "status"), Str(cve.Value, "fixedVersion"), Str(cve.Value, "note"), Str(cve.Value, "reference"));
            list.Add(new NcscPackage(name, aliases, Str(e, "category"), Str(e, "url"), Str(e, "reference"), vex));
        }
        return new NcscInventory(list);
    }

    private static string Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    /// <summary>Cerca il pacchetto corrispondente al nome di una tecnologia; null se l'inventario non lo contiene.</summary>
    public NcscPackage? Find(string technologyName)
    {
        if (string.IsNullOrWhiteSpace(technologyName)) return null;
        string name = technologyName.Trim();
        if (_byName.TryGetValue(name, out var p) || _byNameCi.TryGetValue(name, out p) || _byAlias.TryGetValue(name, out p)) return p;
        string norm = Normalize(name);
        if (norm.Length == 0) return null;
        if (_byNormalized.TryGetValue(norm, out p)) return p;

        // "Grav" → "Grav CMS", "Laravel" → "Laravel 13 framework", "TYPO3 CMS" → "TYPO3 13.4": stesso primo termine; le parole che il pacchetto
        // aggiunge devono essere tutte generiche o versioni (cms/framework/webmail, 13.4), altrimenti è un prodotto diverso ("PHP" non è
        // "PHP DBA" né "PHP CLI"); tra le parole che la tecnologia ha in più al massimo una non generica ("Matomo Analytics" → "Matomo On-Premise").
        var words = Words(name);
        if (words.Length == 0 || words[0].Length < 3 || !_byFirstWord.TryGetValue(words[0], out var candidates)) return null;
        NcscPackage? best = null;
        (int Specific, int Extra, int Length) bestScore = (int.MaxValue, int.MaxValue, int.MaxValue);
        foreach (var (pw, pkg) in candidates)
        {
            var pkgExtra = pw.Where(w => !words.Contains(w)).ToList();
            var techExtra = words.Where(w => !pw.Contains(w)).ToList();
            if (pkgExtra.Any(IsSpecific)) continue;
            int specific = techExtra.Count(IsSpecific);
            if (specific > 1) continue;
            var score = (specific, pkgExtra.Count + techExtra.Count, pkg.Name.Length);
            if (score.CompareTo(bestScore) < 0) { bestScore = score; best = pkg; }
        }
        return best;
    }

    /// <summary>
    /// Riga di sintesi, es. "NCSC-NL: CVE-2026-109618 corretto in 6.4.2; CVE-2026-109619 in esame". Quando ogni asserzione è "Affected"
    /// senza versione corretta (il caso normale delle applicazioni PHP: la correzione è l'aggiornamento di PHP) la frase lo dice in chiaro.
    /// </summary>
    public string Summary(NcscPackage p)
    {
        if (p.Vex.Count == 0) return L.F("NCSC-NL: {0} in inventario, nessuna asserzione VEX", p.Name);
        if (AllAffectedNoFix(p)) return L.T("NCSC-NL: prodotto affetto in quanto dipende dalla versione di PHP (nessuna versione del prodotto corregge da sola)");
        return L.F("NCSC-NL: {0}", string.Join("; ", Parts(p)));
    }

    /// <summary>
    /// Stato in forma breve per l'elenco "Nome: stato" delle tecnologie: quando le asserzioni coincidono una sola parola ("affetto",
    /// "corretto in 8.3.36", "non affetto", "in esame"), altrimenti il dettaglio per CVE.
    /// </summary>
    public string ShortStatus(NcscPackage p)
    {
        if (p.Vex.Count == 0) return L.T("in inventario, nessuna asserzione VEX");
        var statuses = p.Vex.Values.Select(v => v.Status).Distinct(StringComparer.Ordinal).ToList();
        if (statuses.Count == 1)
        {
            var fixedVersions = p.Vex.Values.Select(v => v.FixedVersion).Where(f => f.Length > 0).Distinct(StringComparer.Ordinal).ToList();
            switch (statuses[0])
            {
                case "Affected": return L.T("affetto (dipende dalla versione di PHP)");
                case "Fixed": return fixedVersions.Count > 0 ? L.F("corretto in {0}", string.Join(" / ", fixedVersions)) : L.T("corretto");
                case "NotAffected": return L.T("non affetto");
                case "UnderInvestigation": return L.T("in esame");
            }
        }
        return string.Join("; ", Parts(p));
    }

    /// <summary>Vero quando tutte le asserzioni sono "Affected" e nessuna indica una versione corretta.</summary>
    public static bool AllAffectedNoFix(NcscPackage p) =>
        p.Vex.Count > 0 && p.Vex.Values.All(v => v.Status == "Affected" && v.FixedVersion.Length == 0);

    private static IEnumerable<string> Parts(NcscPackage p)
    {
        foreach (var kv in p.Vex.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            string cve = kv.Key;
            var v = kv.Value;
            yield return v.Status switch
            {
                "Affected" => L.F("{0} affetto", cve),
                "Fixed" when v.FixedVersion.Length > 0 => L.F("{0} corretto in {1}", cve, v.FixedVersion),
                "Fixed" => L.F("{0} corretto", cve),
                "NotAffected" => L.F("{0} non affetto", cve),
                "UnderInvestigation" => L.F("{0} in esame", cve),
                _ => cve + " " + v.Status,
            };
        }
    }

    // ---- confronto di versione tollerante ----------------------------------------------------------------------------

    /// <summary>
    /// Confronta la versione osservata dell'applicazione con le versioni corrette dichiarate nel VEX del pacchetto (campo "fixedVersion",
    /// anche più valori separati da virgola, uno per ramo): restituisce "x &lt; corretto in y" oppure "x ≥ corretto in y", "" se non confrontabile.
    /// Tra più versioni corrette si sceglie quella dello stesso ramo (prefisso numerico comune più lungo), altrimenti la più bassa.
    /// </summary>
    public static string VersionCheck(string observedVersion, NcscPackage p)
    {
        if (string.IsNullOrWhiteSpace(observedVersion)) return "";
        var observed = VersionSegments(observedVersion);
        if (observed.Length == 0) return "";
        var candidates = p.Vex.Values
            .Where(v => v.Status == "Fixed" && v.FixedVersion.Length > 0)
            .SelectMany(v => v.FixedVersion.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            .Distinct(StringComparer.Ordinal)
            .Select(s => (Text: s, Segs: VersionSegments(s)))
            .Where(c => c.Segs.Length > 0)
            .ToList();
        if (candidates.Count == 0) return "";
        var best = candidates
            .OrderByDescending(c => CommonPrefix(observed, c.Segs))
            .ThenBy(c => c.Segs, SegmentComparer.Instance)
            .First();
        int cmp = CompareSegments(observed, best.Segs);
        return cmp < 0 ? L.F("{0} < corretto in {1}", observedVersion.Trim(), best.Text) : L.F("{0} ≥ corretto in {1}", observedVersion.Trim(), best.Text);
    }

    /// <summary>Confronto tollerante: segmenti numerici iniziali ("6.4.2-1ubuntu" → 6.4.2), suffissi ignorati, segmenti mancanti = 0.</summary>
    public static int CompareVersions(string a, string b) => CompareSegments(VersionSegments(a), VersionSegments(b));

    internal static long[] VersionSegments(string s)
    {
        var segs = new List<long>();
        int i = 0;
        s = s.Trim();
        if (s.StartsWith('v') || s.StartsWith('V')) i = 1;
        while (i < s.Length)
        {
            int start = i;
            while (i < s.Length && char.IsAsciiDigit(s[i])) i++;
            if (i == start) break;
            if (!long.TryParse(s.AsSpan(start, i - start), out long n)) break;
            segs.Add(n);
            if (i < s.Length && s[i] == '.' && i + 1 < s.Length && char.IsAsciiDigit(s[i + 1])) { i++; continue; }
            break;
        }
        return segs.ToArray();
    }

    private static int CompareSegments(long[] a, long[] b)
    {
        int n = Math.Max(a.Length, b.Length);
        for (int i = 0; i < n; i++)
        {
            long x = i < a.Length ? a[i] : 0, y = i < b.Length ? b[i] : 0;
            if (x != y) return x < y ? -1 : 1;
        }
        return 0;
    }

    private static int CommonPrefix(long[] a, long[] b)
    {
        int n = 0;
        while (n < a.Length && n < b.Length && a[n] == b[n]) n++;
        return n;
    }

    private sealed class SegmentComparer : IComparer<long[]>
    {
        public static readonly SegmentComparer Instance = new();
        public int Compare(long[]? x, long[]? y) => CompareSegments(x ?? [], y ?? []);
    }

    /// <summary>Solo lettere e cifre ASCII minuscole: "Craft CMS" e "CraftCMS" diventano la stessa chiave.</summary>
    internal static string Normalize(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (char c in s)
        {
            if (c is >= 'a' and <= 'z' or >= '0' and <= '9') sb.Append(c);
            else if (c is >= 'A' and <= 'Z') sb.Append((char)(c + 32));
        }
        return sb.ToString();
    }

    private static string[] Words(string s)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        foreach (char c in s)
        {
            bool ok = c is >= 'a' and <= 'z' or >= '0' and <= '9' or >= 'A' and <= 'Z' or '.';
            if (ok) sb.Append(char.ToLowerInvariant(c));
            else if (sb.Length > 0) { list.Add(sb.ToString().Trim('.')); sb.Clear(); }
        }
        if (sb.Length > 0) list.Add(sb.ToString().Trim('.'));
        return list.Where(w => w.Length > 0).ToArray();
    }

    private static bool IsVersionWord(string w) => w.Length > 0 && char.IsDigit(w[0]);
    private static bool IsSpecific(string w) => !GenericWords.Contains(w) && !IsVersionWord(w);
}
