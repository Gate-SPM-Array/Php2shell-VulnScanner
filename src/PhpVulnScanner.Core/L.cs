using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PhpVulnScanner.Core;

/// <summary>Una lingua disponibile: l'italiano è nel codice, l'inglese è incorporato, le altre sono file <c>lang\&lt;codice&gt;.json</c>.</summary>
public sealed record LanguageInfo(string Code, string Name, string? FilePath)
{
    public override string ToString() => Name;
}

/// <summary>
/// Traduzione dell'interfaccia (stesso schema di DNS Load Tester, AdbSync e Pietrasanta Traceroute GUI, stile gettext).
/// Il testo italiano scritto nel codice è la chiave: <c>L.T("Avvia test")</c>, <c>L.F("Completate {0} query", n)</c>.
/// Un file di lingua associa a ogni testo italiano la sua traduzione; ciò che manca resta in italiano.
/// Formato di <c>lang\en.json</c>:
/// <code>
/// { "code": "en", "language": "English", "culture": "en-GB", "translators": "...", "app_version": "1.0",
///   "strings": { "Avvia test": "Start test", "Completate {0} query": "{0} queries completed" } }
/// </code>
/// I segnaposto {0}, {1:0.0}… devono restare gli stessi: una traduzione che li altera viene ignorata.
/// Ricerca: prima <c>lang\</c> accanto all'eseguibile (modificabile, programma portable), poi la copia di
/// <c>en.json</c> incorporata nella libreria.
/// </summary>
public static class L
{
    public const string DefaultCode = "it";
    public const string DefaultName = "Italiano";
    public const string ReferenceCode = "en";   // file completo usato come riferimento per chi traduce

    private static Dictionary<string, string> _map = new(StringComparer.Ordinal);

    /// <summary>Codice della lingua attiva ("it" se nessun file è caricato).</summary>
    public static string Code { get; private set; } = DefaultCode;
    public static string Name { get; private set; } = DefaultName;

    /// <summary>Cultura per numeri e date dell'interfaccia e del report: it-IT, oppure quella indicata dal file di lingua.</summary>
    public static CultureInfo Culture { get; private set; } = CultureInfo.GetCultureInfo("it-IT");

    /// <summary>Cartella dei file di lingua: <c>lang</c> accanto all'eseguibile.</summary>
    public static string LangDirectory => Path.Combine(AppContext.BaseDirectory, "lang");

    /// <summary>Traduce un testo fisso.</summary>
    public static string T(string italian)
    {
        if (_map.Count == 0) return italian;
        // Un checkout Windows può portare "a capo" CRLF nei testi su più righe: le chiavi usano sempre LF.
        string key = italian.Contains('\r') ? italian.Replace("\r\n", "\n") : italian;
        return _map.TryGetValue(key, out var t) ? t : italian;
    }

    /// <summary>
    /// Traduce una chiave scritta in un file XAML (attributi <c>l:Loc.Text</c> / <c>l:Loc.Tip</c>).
    /// Da non usare nel codice C#: lì il testo va scritto come letterale in <see cref="T"/> o <see cref="F"/>,
    /// perché i test lo estraggono e lo confrontano con lang/en.json.
    /// </summary>
    public static string Xaml(string italian) => T(italian);

    /// <summary>Traduce un testo con segnaposto {0}, {1}… e lo compone con la cultura della lingua attiva.</summary>
    public static string F(string italianFormat, params object?[] args)
    {
        string fmt = T(italianFormat);
        try { return string.Format(Culture, fmt, args); }
        catch (FormatException) { return string.Format(Culture, italianFormat, args); }
    }

    /// <summary>Lingua da usare se l'utente non ha ancora scelto: italiano se Windows è in italiano, altrimenti inglese.</summary>
    public static string AutoCode() =>
        CultureInfo.CurrentUICulture.TwoLetterISOLanguageName.Equals("it", StringComparison.OrdinalIgnoreCase) ? "it" : "en";

    /// <summary>Lingue disponibili: italiano, inglese incorporato e ogni file valido in <paramref name="directory"/>.</summary>
    public static IReadOnlyList<LanguageInfo> Available(string? directory = null)
    {
        var list = new List<LanguageInfo> { new(DefaultCode, DefaultName, null) };
        if (EmbeddedJson(ReferenceCode) is { } emb)
        {
            try
            {
                var f = Parse(emb);
                list.Add(new LanguageInfo(f.Code ?? ReferenceCode, f.Language ?? "English", null));
            }
            catch { /* risorsa non valida: ignorata */ }
        }
        directory ??= LangDirectory;
        if (!Directory.Exists(directory)) return list;
        foreach (var file in Directory.EnumerateFiles(directory, "*.json").Order(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var f = Parse(File.ReadAllText(file));
                string code = f.Code ?? Path.GetFileNameWithoutExtension(file);
                if (code.Equals(DefaultCode, StringComparison.OrdinalIgnoreCase)) continue;
                int i = list.FindIndex(l => l.Code.Equals(code, StringComparison.OrdinalIgnoreCase));
                var info = new LanguageInfo(code, string.IsNullOrWhiteSpace(f.Language) ? code : f.Language!, file);
                if (i >= 0) list[i] = info;      // il file esterno sostituisce la copia incorporata
                else list.Add(info);
            }
            catch { /* file non valido: non proposto */ }
        }
        return list;
    }

    /// <summary>
    /// Attiva una lingua ("" o null = automatica secondo Windows). Restituisce i messaggi da registrare (file mancante
    /// o non valido, traduzioni scartate). In caso di problemi resta l'italiano per ciò che non è utilizzabile.
    /// </summary>
    public static IReadOnlyList<string> Load(string? code, string? directory = null)
    {
        if (string.IsNullOrWhiteSpace(code)) code = AutoCode();
        var (lang, file, map, msgs) = Prepare(code, directory);
        _map = map;
        Code = lang?.Code ?? DefaultCode;
        Name = lang?.Name ?? DefaultName;
        Culture = CultureInfo.GetCultureInfo("it-IT");
        if (lang != null)
        {
            try { Culture = CultureInfo.GetCultureInfo(file?.Culture ?? lang.Code); }
            catch (CultureNotFoundException) { msgs.Add($"Culture \"{file?.Culture}\" not available: using it-IT."); }
        }
        return msgs;
    }

    /// <summary>Legge e valida una lingua senza attivarla (usato da <see cref="Load"/> e dai test).</summary>
    internal static (LanguageInfo? Lang, LangFile? File, Dictionary<string, string> Map, List<string> Messages) Prepare(string? code, string? directory = null)
    {
        var msgs = new List<string>();
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(code) || code.Equals(DefaultCode, StringComparison.OrdinalIgnoreCase)) return (null, null, map, msgs);

        directory ??= LangDirectory;
        var lang = Available(directory).FirstOrDefault(l => l.Code.Equals(code, StringComparison.OrdinalIgnoreCase));
        if (lang is null)
        {
            msgs.Add($"Language \"{code}\" not found in {directory}: using Italian.");
            return (null, null, map, msgs);
        }
        LangFile file;
        try
        {
            string json = lang.FilePath != null ? File.ReadAllText(lang.FilePath) : EmbeddedJson(lang.Code) ?? throw new InvalidDataException("missing resource");
            file = Parse(json);
        }
        catch (Exception ex)
        {
            msgs.Add($"Invalid language file ({lang.FilePath ?? "built-in"}): {ex.Message}. Using Italian.");
            return (null, null, map, msgs);
        }

        int rejected = 0;
        foreach (var (key, value) in file.Strings ?? new Dictionary<string, string>())
        {
            if (string.IsNullOrEmpty(value)) continue;            // non tradotto: resta l'italiano
            if (!SamePlaceholders(key, value))
            {
                rejected++;
                if (rejected <= 10) msgs.Add($"Translation ignored (placeholders {{0}}… differ from the original): \"{Shorten(key)}\"");
                continue;
            }
            map[key.Replace("\r\n", "\n")] = value.Replace("\r\n", "\n");
        }
        if (rejected > 10) msgs.Add($"… {rejected - 10} more translations ignored for different placeholders.");
        return (lang, file, map, msgs);
    }

    private static readonly Regex Placeholder = new(@"(?<!\{)\{(\d+)(?:[,:][^}]*)?\}(?!\})", RegexOptions.CultureInvariant);

    /// <summary>Insieme dei segnaposto ({0}, {1:0.0}, {2,-9}…) di un testo, ordinato.</summary>
    public static IReadOnlyList<string> Placeholders(string s) =>
        Placeholder.Matches(s).Select(m => m.Value).Distinct().Order(StringComparer.Ordinal).ToList();

    public static bool SamePlaceholders(string original, string translation) =>
        Placeholders(original).SequenceEqual(Placeholders(translation));

    private static string Shorten(string s) => s.Length <= 60 ? s.ReplaceLineEndings(" ") : s[..57].ReplaceLineEndings(" ") + "...";

    internal sealed class LangFile
    {
        public string? Code { get; set; }
        public string? Language { get; set; }
        public string? Culture { get; set; }
        public string? Translators { get; set; }
        public string? AppVersion { get; set; }
        public Dictionary<string, string>? Strings { get; set; }
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    internal static LangFile Parse(string json) =>
        JsonSerializer.Deserialize<LangFile>(json, JsonOptions) ?? throw new InvalidDataException("empty file");

    internal static LangFile Read(string path) => Parse(File.ReadAllText(path));

    private static string? EmbeddedJson(string code)
    {
        using var s = typeof(L).Assembly.GetManifestResourceStream("lang." + code + ".json");
        if (s == null) return null;
        using var r = new StreamReader(s);
        return r.ReadToEnd();
    }
}
