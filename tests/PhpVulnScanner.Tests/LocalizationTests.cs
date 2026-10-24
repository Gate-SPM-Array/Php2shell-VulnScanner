using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core;

namespace PhpVulnScanner.Tests;

/// <summary>
/// Coerenza tra i testi del codice e i file di lingua (stesso schema di AdbSync e Pietrasanta Traceroute GUI).
/// Ogni testo mostrato all'utente passa da L.T("…") / L.F("…", …) con un letterale nei .cs, oppure dagli attributi
/// l:Loc.Text / l:Loc.Tip nei .xaml: qui si estraggono tutti e si verifica che lang/en.json li traduca tutti,
/// con gli stessi segnaposto, e che non contenga traduzioni orfane.
/// </summary>
public class LocalizationTests
{
    internal static string RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "PhpVulnScanner.sln"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("radice del repository non trovata");
    }

    private static string LangDir => Path.Combine(RepoRoot(), "lang");

    private static IEnumerable<string> SourceFiles(string pattern) =>
        Directory.EnumerateFiles(Path.Combine(RepoRoot(), "src"), pattern, SearchOption.AllDirectories)
                 .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}") &&
                             !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"));

    /// <summary>Estrae le chiavi (testo italiano) di tutte le chiamate L.T / L.F nei .cs e degli attributi l:Loc nei .xaml.</summary>
    internal static (Dictionary<string, string> Keys, List<string> Problems) ExtractKeys()
    {
        var keys = new Dictionary<string, string>(StringComparer.Ordinal);   // chiave → primo file:riga
        var problems = new List<string>();
        foreach (var file in SourceFiles("*.cs"))
        {
            if (Path.GetFileName(file) == "L.cs") continue;     // definizione della classe di traduzione
            string src = File.ReadAllText(file);
            string name = Path.GetRelativePath(RepoRoot(), file);
            int idx = 0;
            while ((idx = NextCall(src, idx)) >= 0)
            {
                int line = src.Take(idx).Count(c => c == '\n') + 1;
                int p = idx + 4; // dopo "L.T(" / "L.F("
                var sb = new StringBuilder();
                bool ok = true;
                while (true)
                {
                    p = SkipWs(src, p);
                    if (!TryReadLiteral(src, ref p, sb, out string? err)) { problems.Add($"{name}:{line}: {err}"); ok = false; break; }
                    p = SkipWs(src, p);
                    if (p < src.Length && src[p] == '+') { p++; continue; }
                    break;
                }
                if (ok)
                {
                    string key = sb.ToString();
                    if (key.Length == 0) problems.Add($"{name}:{line}: testo vuoto");
                    else keys.TryAdd(key, $"{name}:{line}");
                }
                idx = p;
            }
        }
        foreach (var file in SourceFiles("*.xaml"))
        {
            string src = File.ReadAllText(file);
            string name = Path.GetRelativePath(RepoRoot(), file);
            foreach (Match m in XamlLoc.Matches(src))
            {
                int line = src.Take(m.Index).Count(c => c == '\n') + 1;
                keys.TryAdd(XmlUnescape(m.Groups[2].Value), $"{name}:{line}");
            }
        }
        return (keys, problems);
    }

    private static readonly Regex XamlLoc = new(@"l:Loc\.(Text|Tip)=""([^""]*)""", RegexOptions.CultureInvariant);

    private static string XmlUnescape(string s) =>
        s.Replace("&quot;", "\"").Replace("&apos;", "'").Replace("&lt;", "<").Replace("&gt;", ">").Replace("&amp;", "&");

    private static int NextCall(string s, int from)
    {
        while (true)
        {
            int a = s.IndexOf("L.T(", from, StringComparison.Ordinal);
            int b = s.IndexOf("L.F(", from, StringComparison.Ordinal);
            int i = a < 0 ? b : b < 0 ? a : Math.Min(a, b);
            if (i < 0) return -1;
            // deve essere l'identificatore L (anche qualificato: Core.L.T), non la fine di un altro nome (es. "XL.T(")
            if (i > 0 && (char.IsLetterOrDigit(s[i - 1]) || s[i - 1] == '_')) { from = i + 4; continue; }
            int lineStart = s.LastIndexOf('\n', i) + 1;
            string prefix = s[lineStart..i].TrimStart();
            if (prefix.StartsWith("//", StringComparison.Ordinal) || prefix.StartsWith("*", StringComparison.Ordinal)) { from = i + 4; continue; }
            return i;
        }
    }

    private static int SkipWs(string s, int p)
    {
        while (p < s.Length && char.IsWhiteSpace(s[p])) p++;
        return p;
    }

    private static bool TryReadLiteral(string s, ref int p, StringBuilder sb, out string? error)
    {
        error = null;
        if (p >= s.Length) { error = "fine file"; return false; }
        if (s[p] == '$') { error = "stringa interpolata ($\"…\") in L.T/L.F: usare L.F(\"… {0} …\", valore)"; return false; }
        if (s[p] == '@') { error = "stringa verbatim (@\"…\") in L.T/L.F: usare una stringa normale"; return false; }
        if (s[p] != '"') { error = "L.T/L.F senza letterale: il testo deve essere scritto nel codice (non una variabile)"; return false; }
        p++;
        while (p < s.Length && s[p] != '"')
        {
            if (s[p] == '\\')
            {
                char c = s[p + 1];
                switch (c)
                {
                    case 'n': sb.Append('\n'); break;
                    case 'r': sb.Append('\r'); break;
                    case 't': sb.Append('\t'); break;
                    case '\\': sb.Append('\\'); break;
                    case '"': sb.Append('"'); break;
                    case '\'': sb.Append('\''); break;
                    case 'u': sb.Append((char)Convert.ToInt32(s.Substring(p + 2, 4), 16)); p += 4; break;
                    default: error = $"sequenza di escape non gestita \\{c}"; return false;
                }
                p += 2;
                continue;
            }
            if (s[p] == '\n') { error = "stringa non chiusa"; return false; }
            sb.Append(s[p]);
            p++;
        }
        p++;
        return true;
    }

    private static Dictionary<string, string> EnglishStrings() =>
        L.Read(Path.Combine(LangDir, "en.json")).Strings ?? new Dictionary<string, string>();

    [Fact]
    public void AllLocalizedCallsUseLiterals()
    {
        var (_, problems) = ExtractKeys();
        Assert.True(problems.Count == 0, "Chiamate L.T/L.F non verificabili:\n" + string.Join("\n", problems));
    }

    [Fact]
    public void EnglishFileTranslatesEveryText()
    {
        var (keys, _) = ExtractKeys();
        var en = EnglishStrings();
        var missing = keys.Where(k => !en.TryGetValue(k.Key, out var v) || string.IsNullOrWhiteSpace(v))
                          .Select(k => $"{k.Value}: \"{k.Key}\"").ToList();
        Assert.True(missing.Count == 0, $"{missing.Count} testi senza traduzione inglese in lang/en.json:\n" + string.Join("\n", missing.Take(300)));
    }

    [Fact]
    public void EnglishPlaceholdersMatchOriginals()
    {
        var bad = EnglishStrings().Where(kv => !string.IsNullOrEmpty(kv.Value) && !L.SamePlaceholders(kv.Key, kv.Value))
                                  .Select(kv => $"\"{kv.Key}\" → \"{kv.Value}\"").ToList();
        Assert.True(bad.Count == 0, "Segnaposto diversi:\n" + string.Join("\n", bad));
    }

    [Fact]
    public void EnglishFileHasNoOrphanTexts()
    {
        var (keys, _) = ExtractKeys();
        var orphans = EnglishStrings().Keys.Where(k => !keys.ContainsKey(k)).ToList();
        Assert.True(orphans.Count == 0, $"{orphans.Count} traduzioni non più usate nel codice:\n" + string.Join("\n", orphans.Take(100)));
    }

    [Fact]
    public void EnglishFileIsValidJsonWithMetadata()
    {
        var file = L.Read(Path.Combine(LangDir, "en.json"));
        Assert.Equal("en", file.Code);
        Assert.Equal("English", file.Language);
        Assert.Equal("en-GB", file.Culture);
    }

    /// <summary>Nessun testo visibile scritto direttamente nello XAML (deve passare da l:Loc, salvo marchio e simboli).</summary>
    [Fact]
    public void XamlHasNoUntranslatedVisibleText()
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "PHP Vuln Scanner", "v1.0", "Pronto", "0 / 0" };
        var rx = new Regex(@"(?<![\w.:])(Content|Text|Header|ToolTip|Title)=""([^""{][^""]*)""", RegexOptions.CultureInvariant);
        var bad = new List<string>();
        foreach (var file in SourceFiles("*.xaml"))
        {
            string src = File.ReadAllText(file);
            foreach (Match m in rx.Matches(src))
            {
                string v = m.Groups[2].Value;
                if (allowed.Contains(v) || v.Count(char.IsLetter) < 2) continue;
                bad.Add($"{Path.GetFileName(file)}:{src.Take(m.Index).Count(c => c == '\n') + 1}: {m.Value}");
            }
        }
        Assert.True(bad.Count == 0, "Testi XAML senza l:Loc:\n" + string.Join("\n", bad));
    }

    [Fact]
    public void LoaderRejectsBrokenPlaceholders_KeepsItalianForMissingTexts_AndExternalFileWins()
    {
        string dir = Path.Combine(Path.GetTempPath(), "phpvs_lang_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "en.json"), JsonSerializer.Serialize(new
            {
                code = "en", language = "English (custom)", culture = "en-GB",
                strings = new Dictionary<string, string> { ["Avvia test"] = "Go", ["Completate {0} query"] = "{0} done", ["Due"] = "" },
            }));
            File.WriteAllText(Path.Combine(dir, "de.json"), JsonSerializer.Serialize(new
            {
                code = "de", language = "Deutsch",
                strings = new Dictionary<string, string> { ["Avvia test"] = "Test starten", ["Completate {0} query"] = "Abfragen erledigt" },
            }));
            File.WriteAllText(Path.Combine(dir, "rotto.json"), "{ non è json");

            var langs = L.Available(dir);
            Assert.Equal(new[] { "it", "en", "de" }, langs.Select(l => l.Code).ToArray());
            Assert.Equal("English (custom)", langs[1].Name);                // il file esterno sostituisce l'inglese incorporato

            var (lang, _, map, msgs) = L.Prepare("de", dir);
            Assert.Equal("Deutsch", lang!.Name);
            Assert.Equal("Test starten", map["Avvia test"]);
            Assert.False(map.ContainsKey("Completate {0} query"));         // segnaposto perso: scartata
            Assert.Contains(msgs, m => m.Contains("placeholders"));

            var (_, _, enMap, enMsgs) = L.Prepare("en", dir);
            Assert.Equal(2, enMap.Count);                                    // "Due" vuoto: resta l'italiano
            Assert.Empty(enMsgs);

            var (none, _, emptyMap, noneMsgs) = L.Prepare("xx", dir);
            Assert.Null(none);
            Assert.Empty(emptyMap);
            Assert.Contains(noneMsgs, m => m.Contains("not found"));
        }
        finally { Directory.Delete(dir, true); }
    }

    [Fact]
    public void EmbeddedEnglishMatchesRepositoryFile_AndLoadsWithoutWarnings()
    {
        // senza cartella lang\ si usa la copia incorporata nella libreria
        string empty = Path.Combine(Path.GetTempPath(), "phpvs_nolang_" + Guid.NewGuid().ToString("N"));
        var (lang, file, map, msgs) = L.Prepare("en", empty);
        Assert.NotNull(lang);
        Assert.Null(lang!.FilePath);
        Assert.Empty(msgs);
        Assert.Equal(EnglishStrings().Count(kv => kv.Value.Length > 0), map.Count);
        Assert.Equal("en-GB", file!.Culture);
    }

    [Fact]
    public void LoadSwitchesCultureAndBackToItalian()
    {
        string empty = Path.Combine(Path.GetTempPath(), "phpvs_nolang_" + Guid.NewGuid().ToString("N"));
        try
        {
            L.Load("en", empty);
            Assert.Equal("en", L.Code);
            Assert.Equal("en-GB", L.Culture.Name);
            Assert.Equal("Start scan", L.T("▶  Avvia scansione").Trim('▶', ' '));
            Assert.Equal("1.5 ms", L.F("{0:F1} ms", 1.5));
        }
        finally { L.Load("it", empty); }
        Assert.Equal("it", L.Code);
        Assert.Equal("1,5 ms", L.F("{0:F1} ms", 1.5));
    }

    [Theory]
    [InlineData("Completate {0} di {1}", "{0} of {1} completed", true)]
    [InlineData("{0,-9} {1:0.0}%", "{1:0.0}% {0,-9}", true)]
    [InlineData("Completate {0}", "Completed", false)]
    [InlineData("Valore {0:0.0}", "Value {0}", false)]
    [InlineData("Graffe {{letterali}} {0}", "Braces {{literal}} {0}", true)]
    public void PlaceholderComparison(string it, string en, bool same) => Assert.Equal(same, L.SamePlaceholders(it, en));
}
