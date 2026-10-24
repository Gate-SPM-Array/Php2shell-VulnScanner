using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Apps;

/// <summary>Tecnologia riconosciuta dal database firme, con la confidenza (0–100), l'evidenza che la sostiene e il sito del produttore.</summary>
public sealed record TechMatch(string Name, string Version, int Confidence, IReadOnlyList<string> Categories, bool ImpliesPhp, string Evidence, string Website)
{
    /// <summary>Vero quando la tecnologia non è stata osservata ma dedotta per implicazione da un'altra (es. WordPress → PHP).</summary>
    public bool Implied { get; init; }
}

/// <summary>
/// Database espandibile di firme applicative in formato Wappalyzer (enthec/webappanalyzer, GPL-3.0) più l'inventario PHP2Shell di NCSC-NL,
/// caricato dai file di <c>data/</c> prodotti da <c>tools/build_appdb.py</c>. Riconoscimento solo passivo: intestazioni, cookie, meta, HTML,
/// script, URL ed emittente del certificato delle risposte già scaricate; nessuna richiesta aggiuntiva.
/// Le espressioni regolari sono compilate alla prima occorrenza e messe in cache; quelle non valide in .NET vengono saltate e contate.
/// </summary>
public sealed class TechnologyDatabase
{
    /// <summary>Istanza condivisa caricata all'avvio (null = funzionalità assente: le firme manuali di StackFingerprint restano attive).</summary>
    public static TechnologyDatabase? Default { get; set; }

    /// <summary>Categorie Wappalyzer che descrivono un'applicazione completa (CMS, forum, e-commerce, wiki, pannelli, blog, framework, LMS, webmail…).</summary>
    private static readonly HashSet<int> ApplicationCategories = [1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 13, 18, 21, 30, 47, 50, 51, 53, 95];

    private readonly Dictionary<string, Tech> _techs;
    private readonly Dictionary<int, string> _categories;
    private int _invalidPatterns;

    private TechnologyDatabase(Dictionary<string, Tech> techs, Dictionary<int, string> categories, NcscInventory inventory, string dataVersion)
    {
        _techs = techs;
        _categories = categories;
        Inventory = inventory;
        DataVersion = dataVersion;
        foreach (var t in techs.Values) t.ImpliesPhp = ComputeImpliesPhp(t, []);
    }

    public int Count => _techs.Count;
    public NcscInventory Inventory { get; }
    /// <summary>Contenuto di DATA-VERSION.txt (commit e data delle due sorgenti), "" se il file manca.</summary>
    public string DataVersion { get; }
    /// <summary>Espressioni regolari rifiutate dal motore .NET e quindi ignorate (contate alla prima compilazione).</summary>
    public int InvalidPatterns => _invalidPatterns;
    public string CategoryName(int id) => _categories.TryGetValue(id, out var n) ? n : id.ToString();
    public bool Contains(string name) => _techs.ContainsKey(name);
    /// <summary>Vero se la tecnologia è PHP o implica PHP (transitivamente).</summary>
    public bool ImpliesPhp(string name) => _techs.TryGetValue(name, out var t) && t.ImpliesPhp;

    // ---- caricamento -------------------------------------------------------------------------------------------

    /// <summary>Carica <c>technologies.json</c>, <c>categories.json</c>, <c>ncsc_inventory.json</c> e <c>DATA-VERSION.txt</c> dalla cartella indicata.</summary>
    public static TechnologyDatabase Load(string dataFolder)
    {
        if (!Directory.Exists(dataFolder)) throw new DirectoryNotFoundException(L.F("cartella del database applicazioni non trovata: {0}", dataFolder));
        string techPath = Path.Combine(dataFolder, "technologies.json");
        string catPath = Path.Combine(dataFolder, "categories.json");
        string ncscPath = Path.Combine(dataFolder, "ncsc_inventory.json");
        foreach (var p in new[] { techPath, catPath, ncscPath })
            if (!File.Exists(p)) throw new FileNotFoundException(L.F("file del database applicazioni mancante: {0}", p), p);

        var categories = new Dictionary<int, string>();
        using (var doc = JsonDocument.Parse(File.ReadAllText(catPath)))
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException(L.F("{0}: atteso un oggetto JSON id → nome", "categories.json"));
            foreach (var p in doc.RootElement.EnumerateObject())
                if (int.TryParse(p.Name, out int id) && p.Value.ValueKind == JsonValueKind.String) categories[id] = p.Value.GetString() ?? "";
        }

        var techs = new Dictionary<string, Tech>(StringComparer.Ordinal);
        using (var doc = JsonDocument.Parse(File.ReadAllText(techPath)))
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException(L.F("{0}: atteso un oggetto JSON nome → tecnologia", "technologies.json"));
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (p.Value.ValueKind != JsonValueKind.Object) continue;
                var t = Tech.Read(p.Name, p.Value);
                techs.TryAdd(t.Name, t);
            }
        }
        if (techs.Count == 0) throw new InvalidDataException(L.F("{0}: nessuna tecnologia caricata", "technologies.json"));

        var inventory = NcscInventory.LoadFile(ncscPath);
        string versionPath = Path.Combine(dataFolder, "DATA-VERSION.txt");
        string version = File.Exists(versionPath)
            ? string.Join("; ", File.ReadAllLines(versionPath).Select(l => l.Trim()).Where(l => l.Length > 0))
            : "";
        return new TechnologyDatabase(techs, categories, inventory, version);
    }

    /// <summary>Come <see cref="Load"/>, ma restituisce null se la cartella o i file mancano o non sono leggibili.</summary>
    public static TechnologyDatabase? TryLoad(string dataFolder)
    {
        try { return Load(dataFolder); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidDataException) { return null; }
    }

    /// <summary>Compila subito tutte le espressioni (normalmente avviene alla prima occorrenza); restituisce quante sono state scartate.</summary>
    public int CompileAll()
    {
        foreach (var t in _techs.Values)
            foreach (var p in t.AllPatterns()) p.EnsureCompiled(this);
        return _invalidPatterns;
    }

    /// <summary>Numero totale di pattern (campi passivi) nel database.</summary>
    public int PatternCount => _techs.Values.Sum(t => t.AllPatterns().Count());

    /// <summary>Pattern del campo indicato ("html" o "scriptSrc") privi di prefiltro: ognuno costa un'esecuzione completa sul corpo (diagnostica).</summary>
    public int PatternsWithoutPrefilter(string field) =>
        _techs.Values.Sum(t => (field == "html" ? t.Html : field == "scriptSrc" ? t.ScriptSrc : []).Count(p => !p.Presence && p.Prefilters.Length == 0));

    internal void CountInvalid() => Interlocked.Increment(ref _invalidPatterns);

    /// <summary>Chiusura transitiva di implies e requires fino a "PHP" (memorizzata per tecnologia).</summary>
    private bool ComputeImpliesPhp(Tech t, HashSet<string> visiting)
    {
        if (t.Name == "PHP") return true;
        if (t.ImpliesPhpComputed) return t.ImpliesPhp;
        if (!visiting.Add(t.Name)) return false;
        bool result = false;
        var linked = t.Implies.Select(i => i.Name).Concat(t.Requires).ToList();
        if (linked.Contains("PHP")) result = true;
        else
            foreach (var name in linked)
                if (_techs.TryGetValue(name, out var other) && ComputeImpliesPhp(other, visiting)) { result = true; break; }
        visiting.Remove(t.Name);
        t.ImpliesPhp = result; t.ImpliesPhpComputed = true;
        return result;
    }

    // ---- riconoscimento ----------------------------------------------------------------------------------------

    /// <summary>Riconosce le tecnologie dalle risposte già scaricate; <paramref name="certIssuer"/> è l'emittente del certificato TLS, se noto.</summary>
    public IReadOnlyList<TechMatch> Match(IReadOnlyList<HttpSnapshot> responses, string? certIssuer)
    {
        var ctx = new Context(responses.Where(s => s.HasResponse).ToList(), certIssuer ?? "");
        var found = new Dictionary<string, Hit>(StringComparer.Ordinal);

        foreach (var t in _techs.Values)
        {
            Hit? hit = null;
            MatchTech(t, ctx, ref hit);
            if (hit != null) found[t.Name] = hit;
        }

        // implicazioni transitive: la confidenza dell'implicata è il minimo tra chi implica e il suffisso \;confidence del legame.
        // Anche "requires" vale come implicazione: un componente (WooCommerce) esiste solo sulla sua piattaforma (WordPress).
        var queue = new Queue<string>(found.Keys);
        while (queue.Count > 0)
        {
            string name = queue.Dequeue();
            if (!found.TryGetValue(name, out var from) || !_techs.TryGetValue(name, out var t)) continue;
            foreach (var (implied, conf, required) in t.Implies.Select(i => (i.Name, i.Confidence, false)).Concat(t.Requires.Select(r => (r, 100, true))))
            {
                if (!_techs.TryGetValue(implied, out var it)) continue;
                int c = Math.Min(from.Confidence, conf);
                if (found.TryGetValue(implied, out var existing))
                {
                    if (existing.Implied && c > existing.Confidence) { existing.Confidence = c; queue.Enqueue(implied); }
                    continue;
                }
                found[implied] = new Hit(it) { Confidence = c, Evidence = required ? L.F("richiesto da {0}", t.Name) : L.F("implicato da {0}", t.Name), Implied = true };
                queue.Enqueue(implied);
            }
        }

        // excludes
        foreach (var name in found.Keys.ToList())
            if (found.ContainsKey(name) && _techs.TryGetValue(name, out var t))
                foreach (var ex in t.Excludes) found.Remove(ex);

        return found.Values
            .OrderByDescending(h => h.Confidence).ThenBy(h => h.Implied).ThenBy(h => h.Tech.Name, StringComparer.OrdinalIgnoreCase)
            .Select(h => new TechMatch(h.Tech.Name, h.Version, h.Confidence, h.Tech.Cats.Select(CategoryName).ToList(), h.Tech.ImpliesPhp, h.Evidence, h.Tech.Website) { Implied = h.Implied })
            .ToList();
    }

    private void MatchTech(Tech t, Context ctx, ref Hit? hit)
    {
        foreach (var (name, patterns) in t.Headers)
        {
            if (!ctx.Headers.TryGetValue(name, out var values)) continue;
            foreach (var v in values)
                foreach (var p in patterns)
                    if (p.TryMatch(this, v, null, out var ver, out _)) Add(t, ref hit, p, ver, L.F("intestazione {0}: {1}", name, Short(v)));
        }
        foreach (var (name, patterns) in t.Cookies)
        {
            foreach (var (cookieName, cookieValue) in ctx.Cookies)
            {
                if (!CookieNameMatches(name, cookieName)) continue;
                foreach (var p in patterns)
                    if (p.TryMatch(this, cookieValue, null, out var ver, out _)) Add(t, ref hit, p, ver, L.F("cookie {0}", cookieName));
            }
        }
        foreach (var (name, patterns) in t.Meta)
        {
            if (!ctx.Meta.TryGetValue(name, out var contents)) continue;
            foreach (var c in contents)
                foreach (var p in patterns)
                    if (p.TryMatch(this, c, null, out var ver, out _)) Add(t, ref hit, p, ver, L.F("meta {0}: \"{1}\"", name, Short(c)));
        }
        if (t.Html.Length > 0)
            foreach (var body in ctx.Bodies)
                foreach (var p in t.Html)
                    if (p.TryMatch(this, body.Text, body.Lower, out var ver, out var m)) Add(t, ref hit, p, ver, L.F("corpo di {0}: \"{1}\"", body.Path, Short(m)));
        if (t.ScriptSrc.Length > 0 && ctx.ScriptSrcs.Count > 0)
            foreach (var p in t.ScriptSrc)
            {
                if (!p.Prefilter(ctx.ScriptJoinedLower)) continue;
                foreach (var src in ctx.ScriptSrcs)
                    if (p.TryMatch(this, src, null, out var ver, out _)) { Add(t, ref hit, p, ver, L.F("script {0}", Short(src))); break; }
            }
        if (t.Url.Length > 0 && ctx.BaseUrl.Length > 0)
            foreach (var p in t.Url)
                if (p.TryMatch(this, ctx.BaseUrl, null, out var ver, out _)) Add(t, ref hit, p, ver, L.F("URL {0}", Short(ctx.BaseUrl)));
        if (t.CertIssuer.Length > 0 && ctx.CertIssuer.Length > 0)
            foreach (var p in t.CertIssuer)
                if (p.TryMatch(this, ctx.CertIssuer, null, out var ver, out _)) Add(t, ref hit, p, ver, L.F("emittente del certificato: {0}", Short(ctx.CertIssuer)));
    }

    private static void Add(Tech t, ref Hit? hit, SigPattern p, string version, string evidence)
    {
        hit ??= new Hit(t);
        hit.Confidence = Math.Min(100, hit.Confidence + p.Confidence);
        if (hit.Evidence.Length == 0) hit.Evidence = evidence;
        if (hit.Version.Length == 0 && version.Length > 0) hit.Version = version;
    }

    private static readonly Dictionary<string, Regex?> CookieNameRegexes = new(StringComparer.Ordinal);

    /// <summary>Nome del cookie: confronto senza maiuscole; se la chiave Wappalyzer contiene metacaratteri ("joomla_[a-z0-9]+", "SESS[a-f0-9]{32}") è un'espressione.</summary>
    private static bool CookieNameMatches(string key, string cookieName)
    {
        if (key.Equals(cookieName, StringComparison.OrdinalIgnoreCase)) return true;
        if (key.AsSpan().IndexOfAny(@"[(\+*?^$|") < 0) return false;
        Regex? rx;
        lock (CookieNameRegexes)
        {
            if (!CookieNameRegexes.TryGetValue(key, out rx))
            {
                try { rx = new Regex("^(?:" + key + ")$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)); }
                catch (ArgumentException) { rx = null; }
                CookieNameRegexes[key] = rx;
            }
        }
        try { return rx != null && rx.IsMatch(cookieName); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static string Short(string s)
    {
        s = s.Replace('\r', ' ').Replace('\n', ' ');
        return s.Length <= 60 ? s : s[..57] + "...";
    }

    // ---- integrazione nel risultato -------------------------------------------------------------------------------

    /// <summary>Applica il database condiviso (<see cref="Default"/>) al risultato; non fa nulla se il database non è caricato.</summary>
    public static void ApplyTo(ScanResult r, IReadOnlyList<HttpSnapshot> responses)
    {
        var db = Default;
        if (db == null) return;
        db.Apply(r, responses);
    }

    /// <summary>
    /// Compila <see cref="ScanResult.Technologies"/>, completa <see cref="ScanResult.Application"/> quando le firme manuali non hanno riconosciuto
    /// nulla, segnala PHP se una tecnologia lo implica e aggiunge lo stato NCSC-NL dell'applicazione. Non tocca verdetto e priorità.
    /// </summary>
    public void Apply(ScanResult r, IReadOnlyList<HttpSnapshot> responses)
    {
        var ok = responses.Where(s => s.HasResponse).ToList();
        if (ok.Count == 0) return;
        var matches = Match(ok, r.Tls?.Issuer);

        var ordered = matches
            .OrderByDescending(m => m.ImpliesPhp).ThenByDescending(m => m.Confidence).ThenBy(m => m.Implied)
            .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase).ToList();
        r.Technologies = ordered.Take(12).Select(m => m.Version.Length > 0 ? m.Name + " " + m.Version : m.Name).ToList();

        // applicazione: tecnologia che implica PHP, diversa da PHP stesso; osservata direttamente prima che dedotta,
        // piattaforma (senza requires) prima dei suoi componenti (WooCommerce richiede WordPress), poi confidenza e categoria applicativa
        var app = ordered
            .Where(m => m.ImpliesPhp && m.Name != "PHP" && m.Confidence >= 50)
            .OrderBy(m => m.Implied)
            .ThenBy(m => _techs.TryGetValue(m.Name, out var t) && t.Requires.Length > 0)
            .ThenByDescending(m => m.Confidence)
            .ThenByDescending(m => _techs.TryGetValue(m.Name, out var t) && t.Cats.Any(ApplicationCategories.Contains))
            .ThenBy(m => m.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();

        if (app != null && r.Application.Length == 0)
        {
            r.Application = app.Name;
            r.ApplicationEvidence = L.F("database firme: {0} ({1})", app.Name, app.Evidence);
            r.ApplicationReference = Inventory.Find(app.Name)?.Reference ?? app.Website;
            if (app.Version.Length > 0) r.ApplicationVersion = app.Version;
        }
        else if (r.Application.Length > 0 && r.ApplicationVersion.Length == 0)
        {
            string key = NcscInventory.Normalize(r.Application);
            var same = matches.FirstOrDefault(m => m.Version.Length > 0 && NcscInventory.Normalize(m.Name).StartsWith(key, StringComparison.Ordinal));
            if (same != null) r.ApplicationVersion = same.Version;
        }

        var php = ordered.FirstOrDefault(m => m.ImpliesPhp && m.Confidence >= 50);
        if (php != null && !r.PhpDetected)
        {
            r.PhpDetected = true;
            string ev = L.F("tecnologia PHP riconosciuta: {0}", php.Name);
            var parts = r.PhpEvidence.Split("; ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            if (!parts.Contains(ev)) parts.Add(ev);
            r.PhpEvidence = string.Join("; ", parts);
        }

        if (r.Application.Length > 0 && Inventory.Find(r.Application) is { } pkg)
        {
            r.NcscStatus = Inventory.Summary(pkg);
            r.NcscReference = pkg.Reference;
            // versione osservata contro la versione corretta dichiarata (solo quando il VEX ne indica una: per le applicazioni che dipendono
            // dalla versione di PHP non esiste una versione del prodotto da confrontare)
            if (r.ApplicationVersion.Length > 0) r.AppVersionCheck = NcscInventory.VersionCheck(r.ApplicationVersion, pkg);
        }

        // stato VEX di ogni tecnologia riconosciuta presente nell'inventario (un pacchetto una volta sola, nell'ordine dell'elenco)
        var statuses = new List<string>();
        var seenPkgs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var m in ordered.Take(12))
        {
            var p = Inventory.Find(m.Name);
            if (p == null || !seenPkgs.Add(p.Name)) continue;
            statuses.Add(m.Name + ": " + Inventory.ShortStatus(p));
            if (statuses.Count >= 12) break;
        }
        r.TechnologyStatuses = statuses;
    }

    // ---- strutture interne ----------------------------------------------------------------------------------------

    private sealed class Hit(Tech tech)
    {
        public Tech Tech = tech;
        public int Confidence;
        public string Version = "";
        public string Evidence = "";
        public bool Implied;
    }

    /// <summary>Dati estratti una volta sola dalle risposte: intestazioni e meta per nome (minuscolo), cookie, corpi con copia minuscola, script src.</summary>
    private sealed class Context
    {
        public readonly Dictionary<string, List<string>> Headers = new(StringComparer.Ordinal);
        public readonly List<(string Name, string Value)> Cookies = [];
        public readonly Dictionary<string, List<string>> Meta = new(StringComparer.Ordinal);
        public readonly List<(string Path, string Text, string Lower)> Bodies = [];
        public readonly List<string> ScriptSrcs = [];
        public readonly string ScriptJoinedLower;
        /// <summary>URL della prima risposta (la richiesta base scelta dall'utente): i percorsi .php sondati dallo scanner non devono "dimostrare" PHP.</summary>
        public readonly string BaseUrl;
        public readonly string CertIssuer;

        private static readonly Regex MetaTag = new(@"<meta\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex Attr = new(@"([a-zA-Z_:][\w:.-]*)\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s""'>]+))", RegexOptions.CultureInvariant);
        private static readonly Regex ScriptSrc = new(@"<script\b[^>]*?\bsrc\s*=\s*(?:""([^""]*)""|'([^']*)'|([^\s""'>]+))", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public Context(List<HttpSnapshot> responses, string certIssuer)
        {
            CertIssuer = certIssuer;
            BaseUrl = responses.Count > 0 ? responses[0].Url : "";
            var seenCookies = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenBodies = new HashSet<string>(StringComparer.Ordinal);
            var seenSrc = new HashSet<string>(StringComparer.Ordinal);
            foreach (var s in responses)
            {
                foreach (var h in s.Headers)
                {
                    string key = h.Key.ToLowerInvariant();
                    if (!Headers.TryGetValue(key, out var list)) Headers[key] = list = [];
                    if (!list.Contains(h.Value)) list.Add(h.Value);
                    if (key == "set-cookie")
                    {
                        string first = h.Value.Split(';', 2)[0];
                        int eq = first.IndexOf('=');
                        string name = (eq < 0 ? first : first[..eq]).Trim();
                        string value = eq < 0 ? "" : first[(eq + 1)..].Trim();
                        if (name.Length > 0 && seenCookies.Add(name)) Cookies.Add((name, value));
                    }
                }
                if (s.Body.Length == 0 || !seenBodies.Add(s.Body)) continue;
                Bodies.Add((PathOf(s.Url), s.Body, s.Body.ToLowerInvariant()));
                foreach (Match m in MetaTag.Matches(s.Body))
                {
                    string? name = null, content = null;
                    foreach (Match a in Attr.Matches(m.Value))
                    {
                        string an = a.Groups[1].Value.ToLowerInvariant();
                        string av = a.Groups[2].Success ? a.Groups[2].Value : a.Groups[3].Success ? a.Groups[3].Value : a.Groups[4].Value;
                        if (an is "name" or "property" or "http-equiv" or "itemprop") name ??= av.ToLowerInvariant();
                        else if (an == "content") content = av;
                    }
                    if (name == null || content == null) continue;
                    if (!Meta.TryGetValue(name, out var list)) Meta[name] = list = [];
                    if (!list.Contains(content)) list.Add(content);
                }
                foreach (Match m in ScriptSrc.Matches(s.Body))
                {
                    string src = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value;
                    if (src.Length > 0 && seenSrc.Add(src)) ScriptSrcs.Add(src);
                }
            }
            ScriptJoinedLower = string.Join('\n', ScriptSrcs).ToLowerInvariant();
        }

        private static string PathOf(string url)
        {
            int i = url.IndexOf("://", StringComparison.Ordinal);
            int s = i < 0 ? -1 : url.IndexOf('/', i + 3);
            return s < 0 ? "/" : url[s..];
        }
    }

    /// <summary>Una tecnologia del database con i soli campi passivi.</summary>
    internal sealed class Tech
    {
        public string Name = "";
        public int[] Cats = [];
        public string Website = "";
        public string Cpe = "";
        public (string Name, SigPattern[] Patterns)[] Headers = [];
        public (string Name, SigPattern[] Patterns)[] Cookies = [];
        public (string Name, SigPattern[] Patterns)[] Meta = [];
        public SigPattern[] Html = [];
        public SigPattern[] ScriptSrc = [];
        public SigPattern[] Url = [];
        public SigPattern[] CertIssuer = [];
        public (string Name, int Confidence)[] Implies = [];
        public string[] Requires = [];
        public string[] Excludes = [];
        public bool ImpliesPhp;
        public bool ImpliesPhpComputed;

        public IEnumerable<SigPattern> AllPatterns() =>
            Headers.SelectMany(h => h.Patterns).Concat(Cookies.SelectMany(c => c.Patterns)).Concat(Meta.SelectMany(m => m.Patterns))
                   .Concat(Html).Concat(ScriptSrc).Concat(Url).Concat(CertIssuer);

        public static Tech Read(string name, JsonElement e)
        {
            var t = new Tech { Name = name };
            if (e.TryGetProperty("cats", out var cats) && cats.ValueKind == JsonValueKind.Array)
                t.Cats = cats.EnumerateArray().Where(c => c.ValueKind == JsonValueKind.Number).Select(c => c.GetInt32()).ToArray();
            t.Website = Str(e, "website");
            t.Cpe = Str(e, "cpe");
            t.Headers = ReadMap(e, "headers", lowerKeys: true);
            t.Cookies = ReadMap(e, "cookies", lowerKeys: false);
            t.Meta = ReadMap(e, "meta", lowerKeys: true);
            t.Html = ReadList(e, "html");
            t.ScriptSrc = ReadList(e, "scriptSrc");
            t.Url = ReadList(e, "url");
            t.CertIssuer = ReadList(e, "certIssuer");
            t.Implies = Strings(e, "implies").Select(SplitSuffix).ToArray();
            t.Requires = Strings(e, "requires").Select(s => SplitSuffix(s).Name).ToArray();
            t.Excludes = Strings(e, "excludes").Select(s => SplitSuffix(s).Name).ToArray();
            return t;
        }

        /// <summary>"PHP\;confidence:50" → ("PHP", 50); senza suffisso la confidenza è 100.</summary>
        private static (string Name, int Confidence) SplitSuffix(string s)
        {
            var parts = s.Split("\\;");
            int conf = 100;
            foreach (var p in parts.Skip(1))
                if (p.StartsWith("confidence:", StringComparison.OrdinalIgnoreCase) && int.TryParse(p.AsSpan(11), out int c)) conf = Math.Clamp(c, 0, 100);
            return (parts[0].Trim(), conf);
        }

        private static string Str(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

        private static IEnumerable<string> Strings(JsonElement e, string name)
        {
            if (!e.TryGetProperty(name, out var v)) yield break;
            if (v.ValueKind == JsonValueKind.String) { yield return v.GetString() ?? ""; yield break; }
            if (v.ValueKind != JsonValueKind.Array) yield break;
            foreach (var x in v.EnumerateArray()) if (x.ValueKind == JsonValueKind.String) yield return x.GetString() ?? "";
        }

        private static SigPattern[] ReadList(JsonElement e, string name) => Strings(e, name).Select(SigPattern.Parse).ToArray();

        private static (string, SigPattern[])[] ReadMap(JsonElement e, string name, bool lowerKeys)
        {
            if (!e.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.Object) return [];
            var list = new List<(string, SigPattern[])>();
            foreach (var p in v.EnumerateObject())
            {
                var pats = p.Value.ValueKind == JsonValueKind.String ? [SigPattern.Parse(p.Value.GetString() ?? "")]
                         : p.Value.ValueKind == JsonValueKind.Array ? p.Value.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => SigPattern.Parse(x.GetString() ?? "")).ToArray()
                         : [];
                if (pats.Length == 0) continue;
                string key = p.Name.Trim();
                list.Add((lowerKeys ? key.ToLowerInvariant() : key, pats));
            }
            return list.ToArray();
        }
    }

    /// <summary>
    /// Pattern Wappalyzer: espressione regolare JavaScript (senza maiuscole/minuscole) più i suffissi <c>\;version:…</c> e <c>\;confidence:N</c>.
    /// La compilazione avviene alla prima occorrenza; un pattern non valido in .NET è ignorato. Il prefiltro è la sottostringa letterale più lunga
    /// obbligatoria del pattern (o un letterale per ramo di un'alternativa obbligatoria): se non compare nel testo, in minuscolo, l'espressione non viene nemmeno eseguita.
    /// </summary>
    internal sealed class SigPattern
    {
        public string Source { get; private init; } = "";
        public string VersionExpr { get; private init; } = "";
        public int Confidence { get; private init; } = 100;
        /// <summary>Pattern vuoto: basta la presenza dell'elemento (intestazione, cookie, meta).</summary>
        public bool Presence { get; private init; }
        /// <summary>Letterale singolo più lungo del prefiltro (solo diagnostica e test).</summary>
        public string? Literal { get; private init; }
        /// <summary>Prefiltro: per ogni insieme almeno un letterale deve comparire nel testo in minuscolo.</summary>
        public string[][] Prefilters { get; private init; } = [];

        private Regex? _regex;
        private volatile int _state;   // 0 = da compilare, 1 = valida, 2 = non valida

        private static readonly Regex Ternary = new(@"\\(\d+)\?([^:]*):(.*)$", RegexOptions.CultureInvariant);

        public static SigPattern Parse(string raw)
        {
            var parts = raw.Split("\\;");
            string version = "";
            int conf = 100;
            foreach (var p in parts.Skip(1))
            {
                if (p.StartsWith("version:", StringComparison.OrdinalIgnoreCase)) version = p[8..];
                else if (p.StartsWith("confidence:", StringComparison.OrdinalIgnoreCase) && int.TryParse(p.AsSpan(11), out int c)) conf = Math.Clamp(c, 0, 100);
            }
            string source = parts[0].Replace("[^]", @"[\s\S]");
            var pre = source.Length == 0 ? [] : BuildPrefilter(source);
            string? lit = null;
            foreach (var set in pre) if (set.Length == 1 && (lit == null || set[0].Length > lit.Length)) lit = set[0];
            return new SigPattern
            {
                Source = source, VersionExpr = version, Confidence = conf,
                Presence = source.Length == 0,
                Prefilters = pre, Literal = lit,
            };
        }

        public void EnsureCompiled(TechnologyDatabase db)
        {
            if (_state != 0 || Presence) return;
            try
            {
                _regex = new Regex(Source, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
                _state = 1;
            }
            catch (ArgumentException)
            {
                _state = 2;
                db.CountInvalid();
            }
        }

        /// <summary>Vero se il prefiltro consente l'esecuzione sul testo (già in minuscolo).</summary>
        public bool Prefilter(string lower)
        {
            foreach (var set in Prefilters)
            {
                bool any = false;
                foreach (var lit in set) if (lower.Contains(lit, StringComparison.Ordinal)) { any = true; break; }
                if (!any) return false;
            }
            return true;
        }

        private bool PrefilterIgnoreCase(string input)
        {
            foreach (var set in Prefilters)
            {
                bool any = false;
                foreach (var lit in set) if (input.Contains(lit, StringComparison.OrdinalIgnoreCase)) { any = true; break; }
                if (!any) return false;
            }
            return true;
        }

        public bool TryMatch(TechnologyDatabase db, string input, string? inputLower, out string version, out string matched)
        {
            version = ""; matched = "";
            if (Presence) { matched = input; return true; }
            if (Prefilters.Length > 0 && !(inputLower != null ? Prefilter(inputLower) : PrefilterIgnoreCase(input))) return false;
            EnsureCompiled(db);
            if (_state != 1 || _regex == null) return false;
            Match m;
            try { m = _regex.Match(input); }
            catch (RegexMatchTimeoutException) { return false; }
            if (!m.Success) return false;
            matched = m.Value;
            if (VersionExpr.Length > 0) version = ResolveVersion(VersionExpr, m);
            return true;
        }

        /// <summary>Sintassi Wappalyzer: <c>\1</c> inserisce il gruppo; <c>\1?a:b</c> vale a se il gruppo è presente, altrimenti b (a e b possono contenere <c>\1</c>).</summary>
        internal static string ResolveVersion(string expr, Match m)
        {
            string resolved = expr;
            for (int i = 0; i < m.Groups.Count; i++)
            {
                string value = m.Groups[i].Success ? m.Groups[i].Value : "";
                var t = Ternary.Match(resolved);
                if (t.Success && t.Groups[1].Value == i.ToString())
                    resolved = resolved.Replace(t.Value, value.Length > 0 ? t.Groups[2].Value : t.Groups[3].Value);
                resolved = resolved.Trim().Replace("\\" + i, value);
            }
            return resolved.Trim();
        }

        /// <summary>Sottostringa letterale più lunga che ogni testo corrispondente deve contenere (null se non determinabile o troppo corta).</summary>
        internal static string? LiteralHint(string rx)
        {
            var sets = BuildPrefilter(rx);
            string? best = null;
            foreach (var set in sets)
                if (set.Length == 1 && (best == null || set[0].Length > best.Length)) best = set[0];
            return best;
        }

        /// <summary>
        /// Prefiltro: insiemi di letterali (in minuscolo) di cui almeno uno per insieme deve comparire nel testo perché l'espressione possa
        /// corrispondere. Un run letterale obbligatorio al livello superiore dà un insieme di un elemento; un gruppo obbligatorio con alternative
        /// (<c>(?:a|b)</c>) dà un insieme con un letterale per ramo, se ogni ramo ne ha uno. Vuoto = nessun prefiltro possibile.
        /// </summary>
        internal static string[][] BuildPrefilter(string rx)
        {
            var sets = new List<string[]>();
            Collect(rx, 0, rx.Length, sets);
            return sets.ToArray();
        }

        private const int MinLiteral = 3;

        /// <summary>Analizza rx[from..to) come concatenazione di atomi al livello superiore; aggiunge gli insiemi trovati.</summary>
        private static void Collect(string rx, int from, int to, List<string[]> sets)
        {
            // un'alternativa al livello di questa sequenza: ogni ramo deve fornire un letterale
            var branches = SplitAlternatives(rx, from, to);
            if (branches.Count > 1)
            {
                var alt = new List<string>();
                foreach (var (bs, be) in branches)
                {
                    var inner = new List<string[]>();
                    Collect(rx, bs, be, inner);
                    string? pick = null;
                    foreach (var set in inner) if (set.Length == 1 && (pick == null || set[0].Length > pick.Length)) pick = set[0];
                    if (pick == null) { var multi = inner.FirstOrDefault(x => x.Length > 1); if (multi != null) { alt.AddRange(multi); continue; } return; }
                    alt.Add(pick);
                }
                sets.Add(alt.Distinct(StringComparer.Ordinal).ToArray());
                return;
            }

            var cur = new StringBuilder();
            void Flush() { if (cur.Length >= MinLiteral) sets.Add([cur.ToString().ToLowerInvariant()]); cur.Clear(); }
            for (int i = from; i < to; i++)
            {
                char c = rx[i];
                if (c == '\\')
                {
                    if (i + 1 >= to) break;
                    char n = rx[++i];
                    if (char.IsLetterOrDigit(n)) Flush();   // \d \w \s \b \1 \n …: classe o riferimento, non un letterale
                    else cur.Append(n);                      // punteggiatura protetta: letterale
                    continue;
                }
                if (c == '[') { Flush(); i = SkipClass(rx, i); continue; }
                if (c == '(')
                {
                    Flush();
                    int close = FindGroupEnd(rx, i, to);
                    int contentStart = i + 1;
                    bool lookaround = rx.AsSpan(contentStart, Math.Max(0, close - contentStart)).StartsWith("?=") || rx.AsSpan(contentStart, Math.Max(0, close - contentStart)).StartsWith("?!")
                                   || rx.AsSpan(contentStart, Math.Max(0, close - contentStart)).StartsWith("?<=") || rx.AsSpan(contentStart, Math.Max(0, close - contentStart)).StartsWith("?<!");
                    if (rx.AsSpan(contentStart, Math.Max(0, close - contentStart)).StartsWith("?:")) contentStart += 2;
                    else if (close > contentStart + 1 && rx[contentStart] == '?' && rx[contentStart + 1] == '<') { int gt = rx.IndexOf('>', contentStart); if (gt > 0 && gt < close) contentStart = gt + 1; }
                    else if (close > contentStart && rx[contentStart] == '?') lookaround = true;   // (?i) e simili: nessun contenuto utile
                    bool optional = close + 1 < to && (rx[close + 1] == '?' || rx[close + 1] == '*' || (rx[close + 1] == '{' && close + 2 < to && rx[close + 2] == '0'));
                    if (!lookaround && !optional && close > contentStart) Collect(rx, contentStart, close, sets);
                    i = close;
                    if (close + 1 < to && rx[close + 1] == '{') { int e = rx.IndexOf('}', close + 1); if (e > 0 && e < to) i = e; }
                    continue;
                }
                switch (c)
                {
                    case '?': case '*': if (cur.Length > 0) cur.Length--; Flush(); break;
                    case '{':
                        if (cur.Length > 0) cur.Length--;
                        Flush();
                        int e = rx.IndexOf('}', i);
                        if (e > i && e < to) i = e;
                        break;
                    case '+': case '.': case '^': case '$': case ')': Flush(); break;
                    default: cur.Append(c); break;
                }
            }
            Flush();
        }

        /// <summary>Divide rx[from..to) sui '|' al livello superiore (fuori da gruppi e classi).</summary>
        private static List<(int, int)> SplitAlternatives(string rx, int from, int to)
        {
            var parts = new List<(int, int)>();
            int depth = 0, start = from;
            for (int i = from; i < to; i++)
            {
                char c = rx[i];
                if (c == '\\') { i++; continue; }
                if (c == '[') { i = SkipClass(rx, i); continue; }
                if (c == '(') depth++;
                else if (c == ')') { if (depth > 0) depth--; }
                else if (c == '|' && depth == 0) { parts.Add((start, i)); start = i + 1; }
            }
            parts.Add((start, to));
            return parts;
        }

        /// <summary>i punta a '('; restituisce l'indice della ')' corrispondente (o to-1).</summary>
        private static int FindGroupEnd(string rx, int i, int to)
        {
            int depth = 0;
            for (int j = i; j < to; j++)
            {
                char c = rx[j];
                if (c == '\\') { j++; continue; }
                if (c == '[') { j = SkipClass(rx, j); continue; }
                if (c == '(') depth++;
                else if (c == ')') { depth--; if (depth == 0) return j; }
            }
            return to - 1;
        }

        private static int SkipClass(string rx, int i)
        {
            // i punta a '['; restituisce l'indice di ']' corrispondente (o la fine)
            int j = i + 1;
            if (j < rx.Length && rx[j] == '^') j++;
            if (j < rx.Length && rx[j] == ']') j++;
            while (j < rx.Length)
            {
                if (rx[j] == '\\') { j += 2; continue; }
                if (rx[j] == ']') return j;
                j++;
            }
            return rx.Length - 1;
        }
    }
}
