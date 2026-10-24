using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Apps;

/// <summary>Esito di un aggiornamento del database applicazioni: conteggi dei file prodotti e nuovo contenuto di DATA-VERSION.txt.</summary>
public sealed record UpdateResult(int Technologies, int Categories, int Packages, int Vex, string DataVersion, AppDbUpdater.ConvertStats Stats);

/// <summary>
/// Aggiornamento del database applicazioni (cartella <c>data/</c>) direttamente da GitHub: scarica enthec/webappanalyzer
/// (<c>src/categories.json</c>, <c>src/technologies/*.json</c>) e l'inventario PHP2Shell di NCSC-NL
/// (<c>software/spdx/PHP_Downstream_Inventory.spdx3.json</c>), li converte esattamente come <c>tools/build_appdb.py</c>
/// (stesso schema, stesso filtro dei campi, stessa approssimazione dei selettori DOM, stesse correzioni implies PHP, stessa
/// estrazione di alias e VEX; serializzazione compatta identica a <c>json.dump(separators=(",",":"), ensure_ascii=False)</c>)
/// e sostituisce in modo atomico <c>technologies.json</c>, <c>categories.json</c>, <c>ncsc_inventory.json</c> e <c>DATA-VERSION.txt</c>.
/// In caso di qualsiasi errore la cartella resta com'era. I file scaricati sono dati non fidati: vengono solo letti e trasformati.
/// </summary>
public static class AppDbUpdater
{
    public const string WappalyzerRawBase = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/";
    public const string WappalyzerContentsApi = "https://api.github.com/repos/enthec/webappanalyzer/contents/src/technologies";
    public const string WappalyzerCommitsApi = "https://api.github.com/repos/enthec/webappanalyzer/commits?path=src&per_page=1";
    public const string NcscRawUrl = "https://raw.githubusercontent.com/NCSC-NL/php2shell/main/software/spdx/PHP_Downstream_Inventory.spdx3.json";
    public const string NcscCommitsApi = "https://api.github.com/repos/NCSC-NL/php2shell/commits?path=software/spdx/PHP_Downstream_Inventory.spdx3.json&per_page=1";

    /// <summary>Limite di dimensione di un singolo file scaricato (il più grande, technologies/w.json, è sotto il MiB).</summary>
    public const long MaxDownload = 64L * 1024 * 1024;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    /// <summary>User-Agent dichiarato anche verso GitHub (che lo richiede): lo strumento non si nasconde.</summary>
    public static string UserAgent => "PhpVulnScanner/" + HttpProbe.AppVersion;

    /// <summary>Nomi dei file di firme quando l'API contents di GitHub non è raggiungibile: <c>_.json</c> più una lettera per file.</summary>
    public static IReadOnlyList<string> FallbackTechnologyFiles { get; } =
        new[] { "_.json" }.Concat(Enumerable.Range('a', 26).Select(c => ((char)c).ToString() + ".json")).ToList();

    // ---- scaricamento e sostituzione ------------------------------------------------------------------------------

    /// <summary>
    /// Scarica le sorgenti, le converte e sostituisce i file in <paramref name="dataFolder"/>. I messaggi di avanzamento (già tradotti)
    /// passano da <paramref name="progress"/>. Lancia <see cref="HttpRequestException"/>, <see cref="OperationCanceledException"/>,
    /// <see cref="JsonException"/>, <see cref="InvalidDataException"/> o <see cref="IOException"/>: in ogni caso nulla viene sostituito.
    /// </summary>
    public static async Task<UpdateResult> UpdateAsync(string dataFolder, IProgress<string>? progress, CancellationToken ct)
    {
        using var client = CreateClient();
        return await UpdateAsync(client, dataFolder, progress, ct).ConfigureAwait(false);
    }

    /// <summary>Variante con un <see cref="HttpClient"/> fornito dal chiamante (test con handler finto, proxy).</summary>
    public static async Task<UpdateResult> UpdateAsync(HttpClient client, string dataFolder, IProgress<string>? progress, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(dataFolder)) throw new ArgumentException(L.T("cartella del database applicazioni non indicata"), nameof(dataFolder));
        ct.ThrowIfCancellationRequested();

        // 1. elenco dei file di firme
        progress?.Report(L.T("Elenco dei file di firme da GitHub…"));
        var fileNames = await ListTechnologyFilesAsync(client, progress, ct).ConfigureAwait(false);

        // 2. download (al massimo 4 in parallelo)
        progress?.Report(L.F("Scaricamento di {0} file di firme…", fileNames.Count));
        var techJson = new string[fileNames.Count];
        using (var gate = new SemaphoreSlim(4))
        {
            int done = 0;
            var tasks = fileNames.Select(async (name, i) =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    techJson[i] = await GetStringAsync(client, WappalyzerRawBase + "technologies/" + name, ct).ConfigureAwait(false);
                    int n = Interlocked.Increment(ref done);
                    progress?.Report(L.F("Firme: {0}/{1} ({2})", n, fileNames.Count, name));
                }
                finally { gate.Release(); }
            }).ToArray();
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        progress?.Report(L.T("Scaricamento di categories.json…"));
        string catJson = await GetStringAsync(client, WappalyzerRawBase + "categories.json", ct).ConfigureAwait(false);
        progress?.Report(L.T("Scaricamento dell'inventario NCSC-NL…"));
        string spdxJson = await GetStringAsync(client, NcscRawUrl, ct).ConfigureAwait(false);

        // 3. conversione
        progress?.Report(L.T("Conversione delle firme…"));
        var files = fileNames.Select((n, i) => (n, techJson[i])).ToList();
        var converted = Convert(catJson, files, spdxJson);

        // 4. commit e data delle sorgenti (facoltativi: senza API resta "unknown <data>")
        progress?.Report(L.T("Lettura dei commit delle sorgenti…"));
        var (wCommit, wDate) = await CommitInfoAsync(client, WappalyzerCommitsApi, ct).ConfigureAwait(false);
        var (nCommit, nDate) = await CommitInfoAsync(client, NcscCommitsApi, ct).ConfigureAwait(false);
        string version = DataVersionText(converted, wCommit, wDate, nCommit, nDate);

        // 5. scrittura atomica
        progress?.Report(L.F("Scrittura in {0}…", dataFolder));
        WriteAtomic(dataFolder, converted, version);
        progress?.Report(L.F("Database aggiornato: {0} tecnologie, {1} pacchetti NCSC-NL", converted.Technologies.Count, converted.Packages.Count));
        return new UpdateResult(converted.Technologies.Count, converted.Categories.Count, converted.Packages.Count, converted.Stats.Vex,
            version.TrimEnd('\n'), converted.Stats);
    }

    public static HttpClient CreateClient()
    {
        var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 5 }) { Timeout = Timeout };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }

    /// <summary>Elenco dei file <c>src/technologies/*.json</c> dall'API contents; in caso di errore l'insieme fisso <c>_.json</c>, <c>a.json</c>…<c>z.json</c>.</summary>
    public static async Task<IReadOnlyList<string>> ListTechnologyFilesAsync(HttpClient client, IProgress<string>? progress, CancellationToken ct)
    {
        try
        {
            string json = await GetStringAsync(client, WappalyzerContentsApi, ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array) throw new InvalidDataException("contents: array expected");
            var names = new List<string>();
            foreach (var e in doc.RootElement.EnumerateArray())
            {
                if (e.ValueKind != JsonValueKind.Object) continue;
                string type = Str(e, "type"), name = Str(e, "name");
                if (type == "file" && name.EndsWith(".json", StringComparison.Ordinal) && name.IndexOfAny(['/', '\\']) < 0) names.Add(name);
            }
            if (names.Count == 0) throw new InvalidDataException("contents: no json files");
            names.Sort(StringComparer.Ordinal);   // come sorted(os.listdir(...)) in Python: ordine per codice carattere
            return names;
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or InvalidDataException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            progress?.Report(L.F("API GitHub non disponibile ({0}): uso l'elenco fisso di {1} file", e.Message, FallbackTechnologyFiles.Count));
            return FallbackTechnologyFiles;
        }
    }

    /// <summary>Commit e data (ISO 8601) dell'ultima modifica, dall'API commits; ("unknown", data odierna) se non raggiungibile.</summary>
    public static async Task<(string Commit, string Date)> CommitInfoAsync(HttpClient client, string commitsApiUrl, CancellationToken ct)
    {
        try
        {
            string json = await GetStringAsync(client, commitsApiUrl, ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
            {
                var c = doc.RootElement[0];
                string sha = Str(c, "sha");
                string date = "";
                if (c.TryGetProperty("commit", out var commit) && commit.ValueKind == JsonValueKind.Object)
                {
                    if (commit.TryGetProperty("committer", out var cm) && cm.ValueKind == JsonValueKind.Object) date = Str(cm, "date");
                    if (date.Length == 0 && commit.TryGetProperty("author", out var au) && au.ValueKind == JsonValueKind.Object) date = Str(au, "date");
                }
                if (Regex.IsMatch(sha, "^[0-9a-f]{7,64}$") && date.Length > 0 && date.Length < 40 && !date.Any(char.IsWhiteSpace))
                    return (sha, date);
            }
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or TaskCanceledException && !ct.IsCancellationRequested) { }
        return ("unknown", DateTimeOffset.Now.ToString("yyyy-MM-dd'T'HH:mm:ssK", CultureInfo.InvariantCulture));
    }

    private static async Task<string> GetStringAsync(HttpClient client, string url, CancellationToken ct)
    {
        using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException(L.F("{0}: HTTP {1}", url, (int)resp.StatusCode), null, resp.StatusCode);
        if (resp.Content.Headers.ContentLength is long len && len > MaxDownload)
            throw new InvalidDataException(L.F("{0}: file troppo grande ({1} byte)", url, len));
        await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buffer = new byte[64 * 1024];
        long total = 0;
        int read;
        while ((read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            total += read;
            if (total > MaxDownload) throw new InvalidDataException(L.F("{0}: file troppo grande ({1} byte)", url, total));
            ms.Write(buffer, 0, read);
        }
        var bytes = ms.ToArray();
        int bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? 3 : 0;
        return Encoding.UTF8.GetString(bytes, bom, bytes.Length - bom);
    }

    /// <summary>Le due righe di DATA-VERSION.txt, nello stesso formato di build_appdb.py.</summary>
    public static string DataVersionText(ConvertedData d, string wCommit, string wDate, string nCommit, string nDate) =>
        $"webappanalyzer {wCommit} {wDate} {d.Technologies.Count} technologies\n" +
        $"ncsc-nl/php2shell {nCommit} {nDate} {d.Packages.Count} packages {d.Stats.Vex} vex\n";

    /// <summary>
    /// Scrive i quattro file in una sottocartella temporanea, li ricarica con <see cref="TechnologyDatabase.Load"/> per convalidarli e
    /// solo allora li sposta al posto di quelli esistenti (<see cref="File.Move(string,string,bool)"/>, sostituzione atomica per file).
    /// </summary>
    public static void WriteAtomic(string dataFolder, ConvertedData d, string dataVersionText)
    {
        Directory.CreateDirectory(dataFolder);
        string tmp = Path.Combine(dataFolder, ".update-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tmp);
        try
        {
            var utf8 = new UTF8Encoding(false);
            File.WriteAllText(Path.Combine(tmp, "technologies.json"), PyJson.Serialize(d.Technologies) + "\n", utf8);
            File.WriteAllText(Path.Combine(tmp, "categories.json"), PyJson.Serialize(d.Categories) + "\n", utf8);
            File.WriteAllText(Path.Combine(tmp, "ncsc_inventory.json"), PyJson.Serialize(d.Packages) + "\n", utf8);
            File.WriteAllText(Path.Combine(tmp, "DATA-VERSION.txt"), dataVersionText, utf8);

            var check = TechnologyDatabase.Load(tmp);   // lancia se i file prodotti non sono leggibili
            if (check.Count != d.Technologies.Count) throw new InvalidDataException(L.F("convalida fallita: {0} tecnologie scritte, {1} rilette", d.Technologies.Count, check.Count));

            foreach (var name in new[] { "technologies.json", "categories.json", "ncsc_inventory.json", "DATA-VERSION.txt" })
                File.Move(Path.Combine(tmp, name), Path.Combine(dataFolder, name), overwrite: true);
        }
        finally
        {
            try { Directory.Delete(tmp, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
    }

    // ---- conversione (porting di build_appdb.py) --------------------------------------------------------------------

    /// <summary>Contatori della conversione (stessi nomi di build_appdb.py).</summary>
    public sealed class ConvertStats
    {
        public int Patterns, Duplicates, DomConverted, DomSkipped, Vex, PhpFixups;
        public override string ToString() => $"patterns {Patterns}, duplicates {Duplicates}, dom converted {DomConverted}, dom skipped {DomSkipped}, vex {Vex}, php fixups {PhpFixups}";
    }

    /// <summary>Risultato della conversione: oggetti JSON ordinati come li produce lo script Python.</summary>
    public sealed class ConvertedData
    {
        public JsonObject Technologies { get; init; } = new();
        public JsonObject Categories { get; init; } = new();
        public JsonArray Packages { get; init; } = new();
        public ConvertStats Stats { get; init; } = new();
    }

    private static readonly string[] PassiveListFields = ["html", "scriptSrc", "url", "certIssuer"];
    private static readonly string[] PassiveDictFields = ["headers", "cookies", "meta"];
    public const string NcscBase = "https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_";
    private static readonly string[] CveIds = ["CVE-2026-109618", "CVE-2026-109619"];

    /// <summary>Applicazioni PHP senza implies PHP nelle firme Wappalyzer (stesso elenco di build_appdb.py).</summary>
    public static readonly HashSet<string> PhpImpliesFixups = new(StringComparer.Ordinal)
    {
        "Matomo Analytics", "SuiteCRM", "Piwigo", "Invision Community", "Zen Cart", "WHMCS", "Elgg", "Tiki Wiki CMS Groupware",
        "Zend", "Pagekit", "Mahara", "Omeka", "Mautic", "Vtiger", "EspoCRM", "Bagisto", "HumHub", "Lychee", "Gallery", "Plesk",
    };

    private static readonly Dictionary<string, string> VexStatus = new(StringComparer.Ordinal)
    {
        ["security_VexAffectedVulnAssessmentRelationship"] = "Affected",
        ["security_VexFixedVulnAssessmentRelationship"] = "Fixed",
        ["security_VexNotAffectedVulnAssessmentRelationship"] = "NotAffected",
        ["security_VexUnderInvestigationVulnAssessmentRelationship"] = "UnderInvestigation",
    };

    /// <summary>Converte le sorgenti già scaricate: <paramref name="technologyFiles"/> sono (nome file, contenuto) e vengono elaborati in ordine di nome.</summary>
    public static ConvertedData Convert(string categoriesJson, IEnumerable<(string FileName, string Json)> technologyFiles, string spdxJson)
    {
        var stats = new ConvertStats();
        var categories = BuildCategories(categoriesJson);
        var techs = BuildTechnologies(technologyFiles, stats);
        var packages = BuildNcsc(spdxJson, stats);
        return new ConvertedData { Technologies = techs, Categories = categories, Packages = packages, Stats = stats };
    }

    internal static JsonObject BuildCategories(string json)
    {
        var categories = new JsonObject();
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException(L.F("{0}: atteso un oggetto JSON id → nome", "categories.json"));
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (p.Value.ValueKind != JsonValueKind.Object || !p.Value.TryGetProperty("name", out var n) || n.ValueKind != JsonValueKind.String) continue;
            if (!long.TryParse(p.Name.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out long id)) continue;   // str(int(cid))
            categories[id.ToString(CultureInfo.InvariantCulture)] = n.GetString() ?? "";
        }
        return categories;
    }

    internal static JsonObject BuildTechnologies(IEnumerable<(string FileName, string Json)> files, ConvertStats stats)
    {
        var techs = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        var order = new List<string>();
        foreach (var (fileName, json) in files.OrderBy(f => f.FileName, StringComparer.Ordinal))
        {
            if (!fileName.EndsWith(".json", StringComparison.Ordinal)) continue;
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) continue;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                string name = p.Name;
                var t = p.Value;
                if (t.ValueKind != JsonValueKind.Object) continue;
                if (techs.ContainsKey(name)) { stats.Duplicates++; continue; }

                var entry = new JsonObject();
                var cats = new JsonArray();
                if (t.TryGetProperty("cats", out var rawCats) && rawCats.ValueKind == JsonValueKind.Array)
                    foreach (var c in rawCats.EnumerateArray())
                    {
                        if (c.ValueKind == JsonValueKind.Number && c.TryGetInt64(out long ci)) cats.Add(ci);
                        else if (c.ValueKind == JsonValueKind.String && c.GetString() is { Length: > 0 } cs && cs.All(char.IsAsciiDigit) && long.TryParse(cs, out long cv)) cats.Add(cv);
                        else if (c.ValueKind is JsonValueKind.True or JsonValueKind.False) cats.Add(c.ValueKind == JsonValueKind.True ? 1 : 0);   // isinstance(True, int) in Python
                    }
                entry["cats"] = cats;
                entry["website"] = t.TryGetProperty("website", out var w) && w.ValueKind == JsonValueKind.String ? w.GetString() ?? "" : "";
                if (t.TryGetProperty("cpe", out var cpe) && cpe.ValueKind == JsonValueKind.String && cpe.GetString() is { Length: > 0 } cpeS) entry["cpe"] = cpeS;

                foreach (var fld in PassiveDictFields)
                {
                    var d = AsDictOfLists(t, fld);
                    if (d.Count == 0) continue;
                    var obj = new JsonObject();
                    foreach (var (k, v) in d) { obj[k] = ToArray(v); stats.Patterns += v.Count; }
                    entry[fld] = obj;
                }
                foreach (var fld in PassiveListFields)
                {
                    var lst = AsList(t, fld);
                    if (fld == "scriptSrc")
                    {
                        var orig = lst.ToList();
                        foreach (var s in AsList(t, "scripts")) if (!orig.Contains(s)) lst.Add(s);
                    }
                    if (fld == "html" && t.TryGetProperty("dom", out var dom)) lst.AddRange(DomToHtmlPatterns(dom, stats));
                    if (lst.Count == 0) continue;
                    entry[fld] = ToArray(lst);
                    stats.Patterns += lst.Count;
                }
                foreach (var fld in new[] { "implies", "requires", "excludes" })
                {
                    var lst = AsList(t, fld);
                    if (fld == "implies" && PhpImpliesFixups.Contains(name) && !lst.Any(x => x.Split("\\;")[0] == "PHP"))
                    {
                        lst.Add("PHP");
                        stats.PhpFixups++;
                    }
                    if (lst.Count > 0) entry[fld] = ToArray(lst);
                }
                techs[name] = entry;
                order.Add(name);
            }
        }
        // dict(sorted(techs.items(), key=lambda kv: kv[0].lower())): ordinamento stabile per nome minuscolo
        var result = new JsonObject();
        foreach (var name in order.OrderBy(n => n.ToLowerInvariant(), StringComparer.Ordinal)) result[name] = techs[name];
        return result;
    }

    private static JsonArray ToArray(IEnumerable<string> items)
    {
        var a = new JsonArray();
        foreach (var s in items) a.Add(s);
        return a;
    }

    /// <summary>as_list: stringa → [s]; array → solo le stringhe; altro → [].</summary>
    private static List<string> AsList(JsonElement parent, string field)
    {
        var out_ = new List<string>();
        if (!parent.TryGetProperty(field, out var v)) return out_;
        if (v.ValueKind == JsonValueKind.String) out_.Add(v.GetString() ?? "");
        else if (v.ValueKind == JsonValueKind.Array)
            foreach (var x in v.EnumerateArray()) if (x.ValueKind == JsonValueKind.String) out_.Add(x.GetString() ?? "");
        return out_;
    }

    /// <summary>as_dict_of_lists: valore "" → [""] (sola presenza); liste vuote o valori non testuali vengono saltati.</summary>
    private static List<(string Key, List<string> Values)> AsDictOfLists(JsonElement parent, string field)
    {
        var out_ = new List<(string, List<string>)>();
        if (!parent.TryGetProperty(field, out var v) || v.ValueKind != JsonValueKind.Object) return out_;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in v.EnumerateObject())
        {
            var lst = new List<string>();
            if (p.Value.ValueKind == JsonValueKind.String) lst.Add(p.Value.GetString() ?? "");
            else if (p.Value.ValueKind == JsonValueKind.Array)
                foreach (var x in p.Value.EnumerateArray()) if (x.ValueKind == JsonValueKind.String) lst.Add(x.GetString() ?? "");
            bool isEmptyString = p.Value.ValueKind == JsonValueKind.String && (p.Value.GetString() ?? "").Length == 0;
            if (lst.Count == 0 && !isEmptyString) continue;
            if (isEmptyString) lst = [""];
            if (!seen.Add(p.Name))   // chiave duplicata nel JSON: in Python vince l'ultimo valore, nella posizione della prima occorrenza
            {
                int idx = out_.FindIndex(e => e.Item1 == p.Name);
                if (idx >= 0) out_[idx] = (p.Name, lst); else out_.Add((p.Name, lst));
                continue;
            }
            out_.Add((p.Name, lst));
        }
        return out_;
    }

    // ---- selettori DOM semplici → regex HTML ----

    private static readonly Regex SimpleSelector = new(
        @"^\s*([a-zA-Z][a-zA-Z0-9-]*)?\s*\[\s*([a-zA-Z_:][\w:.-]*)\s*(\*=|\^=|\$=|=)?\s*(?:'([^']*)'|""([^""]*)""|([^\]\s'""]+))?\s*\]\s*$",
        RegexOptions.CultureInvariant);

    internal static List<string> SplitTopLevelCommas(string s)
    {
        var parts = new List<string>();
        var cur = new StringBuilder();
        int depth = 0;
        char quote = '\0';
        foreach (char ch in s)
        {
            if (quote != '\0')
            {
                cur.Append(ch);
                if (ch == quote) quote = '\0';
                continue;
            }
            if (ch is '\'' or '"') { quote = ch; cur.Append(ch); }
            else if (ch is '(' or '[') { depth++; cur.Append(ch); }
            else if (ch is ')' or ']') { depth--; cur.Append(ch); }
            else if (ch == ',' && depth == 0) { parts.Add(cur.ToString()); cur.Clear(); }
            else cur.Append(ch);
        }
        parts.Add(cur.ToString());
        return parts.Where(p => p.Trim().Length > 0).ToList();
    }

    /// <summary>Python 3.7+ <c>re.escape</c>: protegge solo i caratteri speciali <c>()[]{}?*+-|^$\.&amp;~# \t\n\r\v\f</c>.</summary>
    internal static string PyReEscape(string s)
    {
        var sb = new StringBuilder(s.Length + 8);
        foreach (char c in s)
        {
            if ("()[]{}?*+-|^$\\.&~# \t\n\r\v\f".Contains(c)) sb.Append('\\');
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary><c>link[href*='/wp-content/']</c> → regex sul sorgente HTML; null se il selettore non è di questa forma semplice.</summary>
    internal static string? SelectorToRegex(string sel)
    {
        var m = SimpleSelector.Match(sel);
        if (!m.Success) return null;
        string tag = m.Groups[1].Success ? m.Groups[1].Value : "";
        string attr = m.Groups[2].Value;
        string op = m.Groups[3].Success ? m.Groups[3].Value : "";
        string? value = m.Groups[4].Success ? m.Groups[4].Value : m.Groups[5].Success ? m.Groups[5].Value : m.Groups[6].Success ? m.Groups[6].Value : null;
        string tagRx = tag.Length > 0 ? PyReEscape(tag) : "[a-zA-Z][a-zA-Z0-9-]*";
        string attrRx = PyReEscape(attr);
        if (value == null) return $@"<{tagRx}\b[^>]*\s{attrRx}(?:[\s=>/]|$)";
        string valRx = PyReEscape(value);
        // come nello script Python (rf-string): la virgoletta doppia resta preceduta dal backslash, \" nella regex
        return op switch
        {
            "*=" => $@"<{tagRx}\b[^>]*\s{attrRx}=[\""']?[^\""'>]*{valRx}",
            "^=" => $@"<{tagRx}\b[^>]*\s{attrRx}=[\""']?{valRx}",
            "$=" => $@"<{tagRx}\b[^>]*\s{attrRx}=[\""']?[^\""'>]*{valRx}[\""'\s>/]",
            "=" => $@"<{tagRx}\b[^>]*\s{attrRx}=[\""']?{valRx}[\""'\s>/]",
            _ => null,
        };
    }

    internal static List<string> DomToHtmlPatterns(JsonElement dom, ConvertStats stats)
    {
        var selectors = new List<string>();
        if (dom.ValueKind == JsonValueKind.String) selectors.Add(dom.GetString() ?? "");
        else if (dom.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in dom.EnumerateArray()) if (s.ValueKind == JsonValueKind.String) selectors.Add(s.GetString() ?? "");
        }
        else if (dom.ValueKind == JsonValueKind.Object)
        {
            foreach (var p in dom.EnumerateObject())
            {
                var cond = p.Value;
                // solo "esiste": le condizioni su attributi, testo o proprietà richiedono un DOM reale
                bool existsOnly = cond.ValueKind == JsonValueKind.Null
                    || (cond.ValueKind == JsonValueKind.String && (cond.GetString() ?? "").Length == 0)
                    || (cond.ValueKind == JsonValueKind.Object && cond.EnumerateObject().All(c => c.Name == "exists"));
                if (existsOnly) selectors.Add(p.Name);
                else stats.DomSkipped++;
            }
        }
        var out_ = new List<string>();
        foreach (var sel in selectors)
            foreach (var part in SplitTopLevelCommas(sel))
            {
                var rx = SelectorToRegex(part);
                if (rx == null) stats.DomSkipped++;
                else { stats.DomConverted++; out_.Add(rx); }
            }
        return out_;
    }

    // ---- NCSC-NL ----

    private static readonly Regex FixedClauseRx = new(@"\b[Ff]ixed\b[^;:.]{0,40}?\bin\b([^;]{1,160})", RegexOptions.CultureInvariant);
    private static readonly Regex VersionTokenRx = new(@"(?<![\w.])\d+\.\d+(?:\.\d+)*(?:[-+][\w.]+)?(?![\w.]*\.\w)", RegexOptions.CultureInvariant);
    private static readonly Regex UrlRx = new(@"https?://[^\s)\]]+", RegexOptions.CultureInvariant);
    private static readonly Regex SentenceEnd = new(@"\.\s", RegexOptions.CultureInvariant);

    /// <summary>Numeri di versione citati nella frase "Fixed in …" (es. "8.5.12, 8.4.27, 8.3.36, 8.2.35" oppure "8.5.12-1").</summary>
    internal static string FixedVersion(string notes)
    {
        var m = FixedClauseRx.Match(notes);
        if (!m.Success) return "";
        string clause = m.Groups[1].Value;
        var end = SentenceEnd.Match(clause);   // la frase si ferma al primo punto seguito da spazio, non ai punti dei numeri
        if (end.Success) clause = clause[..end.Index];
        var found = new List<string>();
        foreach (Match v in VersionTokenRx.Matches(clause)) if (!found.Contains(v.Value)) found.Add(v.Value);
        return string.Join(", ", found.Take(4));
    }

    internal static string CommentField(string comment, string key)
    {
        var m = Regex.Match(comment ?? "", "^" + Regex.Escape(key) + @":\s*(.*)$", RegexOptions.Multiline | RegexOptions.CultureInvariant);
        return m.Success ? PyStrip(m.Groups[1].Value) : "";
    }

    internal static string NcscLetter(string name)
    {
        string s = PyStrip(name);
        if (s.Length == 0) return "";
        string first;
        try { first = Rune.GetRuneAt(s, 0).ToString().ToLowerInvariant(); }
        catch (ArgumentException) { return ""; }
        if (first.Length == 1 && char.IsDigit(first[0])) return "0-9";
        if (first.Length == 1 && first[0] is >= 'a' and <= 'z') return first;
        return "";
    }

    internal static JsonArray BuildNcsc(string spdxJson, ConvertStats stats)
    {
        using var doc = JsonDocument.Parse(spdxJson);
        var root = doc.RootElement;
        var graph = new List<JsonElement>();
        if (root.ValueKind == JsonValueKind.Object && root.TryGetProperty("@graph", out var g) && g.ValueKind == JsonValueKind.Array) graph.AddRange(g.EnumerateArray());
        else if (root.ValueKind == JsonValueKind.Array) graph.AddRange(root.EnumerateArray());
        graph = graph.Where(e => e.ValueKind == JsonValueKind.Object).ToList();

        var byId = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var e in graph)
        {
            string id = Str(e, "spdxId");
            if (id.Length == 0) id = Str(e, "@id");
            byId[id] = e;   // come la dict comprehension Python: l'ultimo vince
        }

        var vexByPkg = new Dictionary<string, List<(string Cve, JsonObject Item)>>(StringComparer.Ordinal);
        foreach (var e in graph)
        {
            if (!VexStatus.TryGetValue(Str(e, "type"), out var status)) continue;
            string cve = byId.TryGetValue(Str(e, "from"), out var vuln) ? Str(vuln, "name") : "";
            if (!CveIds.Contains(cve)) continue;
            string notes = Str(e, "security_statusNotes");
            if (notes.Length == 0) notes = Str(e, "security_impactStatement");
            if (notes.Length == 0) notes = Str(e, "summary");
            notes = PyStrip(notes);
            string fixedV = status == "Fixed" ? FixedVersion(notes) : "";
            string reference = FirstLocator(e, requireString: false);
            if (reference.Length == 0)
            {
                var m = UrlRx.Match(Str(e, "comment"));
                if (m.Success) reference = m.Value.TrimEnd('.', ',');
            }
            var item = new JsonObject { ["status"] = status };
            if (fixedV.Length > 0) item["fixedVersion"] = fixedV;
            if (notes.Length > 0) item["note"] = PySlice(notes, 300);
            if (reference.Length > 0) item["reference"] = reference;
            if (!e.TryGetProperty("to", out var to)) continue;
            var targets = to.ValueKind == JsonValueKind.Array ? to.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").ToList()
                        : to.ValueKind == JsonValueKind.String ? [to.GetString() ?? ""] : [];
            foreach (var pkgId in targets)
            {
                if (!vexByPkg.TryGetValue(pkgId, out var list)) vexByPkg[pkgId] = list = [];
                int idx = list.FindIndex(x => x.Cve == cve);
                if (idx >= 0) list[idx] = (cve, item); else list.Add((cve, item));
                stats.Vex++;
            }
        }

        var packages = new List<(string Name, JsonObject Pkg)>();
        foreach (var e in graph)
        {
            if (Str(e, "type") != "software_Package" || !e.TryGetProperty("name", out var n) || n.ValueKind != JsonValueKind.String) continue;
            string rawName = n.GetString() ?? "";
            string comment = Str(e, "comment");
            var aliases = new JsonArray();
            foreach (var a in CommentField(comment, "Aliases").Split(',')) { string s = PyStrip(a); if (s.Length > 0) aliases.Add(s); }
            string url = FirstLocator(e, requireString: true);
            string letter = NcscLetter(rawName);
            var vex = new JsonObject();
            if (vexByPkg.TryGetValue(Str(e, "spdxId"), out var vl))
                foreach (var (cve, item) in vl) vex[cve] = item.DeepClone();
            var pkg = new JsonObject
            {
                ["name"] = PyStrip(rawName),
                ["aliases"] = aliases,
                ["category"] = CommentField(comment, "Category"),
                ["url"] = url,
                ["vex"] = vex,
                ["reference"] = letter.Length > 0 ? NcscBase + letter + ".md" : NcscBase[..NcscBase.LastIndexOf('_')] + ".md",
            };
            packages.Add((rawName, pkg));
        }
        var arr = new JsonArray();
        foreach (var (_, pkg) in packages.OrderBy(p => (p.Pkg["name"]?.GetValue<string>() ?? "").ToLowerInvariant(), StringComparer.Ordinal)) arr.Add(pkg);
        return arr;
    }

    /// <summary>Primo externalRef con locator non vuoto (per i VEX anche non testuale, come nello script; per i pacchetti solo stringhe).</summary>
    private static string FirstLocator(JsonElement e, bool requireString)
    {
        if (!e.TryGetProperty("externalRef", out var refs) || refs.ValueKind != JsonValueKind.Array) return "";
        foreach (var er in refs.EnumerateArray())
        {
            if (er.ValueKind != JsonValueKind.Object || !er.TryGetProperty("locator", out var locs) || locs.ValueKind != JsonValueKind.Array || locs.GetArrayLength() == 0) continue;
            var first = locs[0];
            if (first.ValueKind == JsonValueKind.String) return first.GetString() ?? "";
            if (requireString) continue;
            return first.ToString();
        }
        return "";
    }

    private static string Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    /// <summary>Python <c>str.strip()</c>: spazi Unicode a entrambi i capi.</summary>
    internal static string PyStrip(string s) => s.Trim();

    /// <summary>Python <c>s[:n]</c>: taglio per punti di codice, non per unità UTF-16.</summary>
    internal static string PySlice(string s, int n)
    {
        int count = 0, i = 0;
        while (i < s.Length && count < n)
        {
            i += char.IsHighSurrogate(s[i]) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]) ? 2 : 1;
            count++;
        }
        return s[..i];
    }

    // ---- serializzazione identica a json.dump(separators=(",",":"), ensure_ascii=False) ----

    /// <summary>Scrive un albero <see cref="JsonNode"/> in forma compatta con le regole di escape di Python (<c>"</c>, <c>\</c>, controlli; tutto il resto letterale).</summary>
    public static class PyJson
    {
        public static string Serialize(JsonNode? node)
        {
            var sb = new StringBuilder();
            Write(node, sb);
            return sb.ToString();
        }

        private static void Write(JsonNode? node, StringBuilder sb)
        {
            switch (node)
            {
                case null: sb.Append("null"); break;
                case JsonObject o:
                    sb.Append('{');
                    bool first = true;
                    foreach (var kv in o)
                    {
                        if (!first) sb.Append(',');
                        first = false;
                        WriteString(kv.Key, sb);
                        sb.Append(':');
                        Write(kv.Value, sb);
                    }
                    sb.Append('}');
                    break;
                case JsonArray a:
                    sb.Append('[');
                    for (int i = 0; i < a.Count; i++) { if (i > 0) sb.Append(','); Write(a[i], sb); }
                    sb.Append(']');
                    break;
                case JsonValue v:
                    if (v.TryGetValue<string>(out var s)) WriteString(s, sb);
                    else if (v.TryGetValue<bool>(out var b)) sb.Append(b ? "true" : "false");
                    else if (v.TryGetValue<long>(out var l)) sb.Append(l.ToString(CultureInfo.InvariantCulture));
                    else if (v.TryGetValue<int>(out var n)) sb.Append(n.ToString(CultureInfo.InvariantCulture));
                    else if (v.TryGetValue<double>(out var d)) sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                    else sb.Append(v.ToJsonString());
                    break;
                default: sb.Append(node.ToJsonString()); break;
            }
        }

        private static void WriteString(string s, StringBuilder sb)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }
}
