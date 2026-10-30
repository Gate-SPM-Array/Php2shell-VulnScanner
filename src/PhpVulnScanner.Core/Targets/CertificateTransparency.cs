using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Targets;

/// <summary>
/// Nomi dai log di Certificate Transparency (crt.sh) per i domini scoperti. Nessun traffico verso i bersagli: una richiesta a
/// crt.sh per dominio registrabile, con cache per tutta la scansione (lo stesso dominio compare su molti host). Opzione spenta
/// per impostazione predefinita: interroga un servizio esterno.
/// </summary>
public static class CertificateTransparency
{
    public const int TimeoutMs = 10000;
    public const int MaxNamesPerQuery = 500;

    /// <summary>Suffissi pubblici a due etichette più comuni: il dominio registrabile prende tre etichette (es. example.co.uk).</summary>
    private static readonly HashSet<string> TwoLabelSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "com.br", "net.br", "org.br", "gov.br",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.nz", "net.nz", "org.nz", "co.za", "org.za",
        "com.cn", "net.cn", "org.cn", "gov.cn", "com.tw", "com.hk", "com.sg", "com.mx", "com.ar", "com.tr",
        "co.in", "net.in", "org.in", "co.kr", "or.kr", "com.es", "nom.es", "org.es", "com.pl", "edu.pl",
        "gov.it", "edu.it", "com.ua", "co.il", "org.il", "ac.il", "com.ru", "com.pt", "edu.pt", "com.vn",
    };

    private static readonly ConcurrentDictionary<string, Task<IReadOnlyList<string>>> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Lazy<HttpClient> Client = new(() =>
    {
        var h = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, PooledConnectionLifetime = TimeSpan.FromMinutes(2), AutomaticDecompression = DecompressionMethods.All };
        var c = new HttpClient(h) { Timeout = TimeSpan.FromMilliseconds(TimeoutMs) };
        c.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", HttpProbe.UserAgent);
        c.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/json");
        return c;
    });

    /// <summary>Dominio registrabile di un nome: le ultime due etichette, tre quando la penultima è un suffisso pubblico noto (co.uk…); null se il nome non è valido.</summary>
    public static string? RegistrableDomain(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        name = name.Trim().TrimEnd('.').ToLowerInvariant();
        if (name.StartsWith("*.", StringComparison.Ordinal)) name = name[2..];
        if (!NameDiscovery.IsValidHostName(name)) return null;
        var labels = name.Split('.');
        if (labels.Length < 2) return null;
        if (labels.Length >= 3 && TwoLabelSuffixes.Contains(labels[^2] + "." + labels[^1])) return string.Join('.', labels[^3..]);
        return labels[^2] + "." + labels[^1];
    }

    /// <summary>v1.8: tra i nomi sotto <paramref name="registrable"/>, il sottodominio a una etichetta in più (es. ente.example.it) più frequente; null se nessun nome ha più di due etichette oltre il dominio.</summary>
    public static string? MostCommonSubdomain(IEnumerable<string> names, string registrable)
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int regLabels = registrable.Split('.').Length;
        foreach (var raw in names)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            string n = raw.Trim().TrimEnd('.').ToLowerInvariant();
            if (n.StartsWith("*.", StringComparison.Ordinal)) n = n[2..];
            if (!n.EndsWith("." + registrable, StringComparison.OrdinalIgnoreCase)) continue;
            var labels = n.Split('.');
            if (labels.Length < regLabels + 1) continue;
            string sub = string.Join('.', labels[^(regLabels + 1)..]);
            counts[sub] = counts.GetValueOrDefault(sub) + 1;
        }
        return counts.Count == 0 ? null : counts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal).First().Key;
    }

    /// <summary>Nomi distinti e validi dall'output JSON di crt.sh (campi name_value, una riga per nome, e common_name); i wildcard sono scartati.</summary>
    public static List<string> ParseCrtSh(string json)
    {
        var names = new List<string>();
        if (string.IsNullOrWhiteSpace(json)) return names;
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Array) return names;
        foreach (var e in doc.RootElement.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.Object) continue;
            foreach (var field in new[] { "name_value", "common_name" })
            {
                if (!e.TryGetProperty(field, out var v) || v.ValueKind != JsonValueKind.String) continue;
                foreach (var raw in (v.GetString() ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    string n = raw.TrimEnd('.').ToLowerInvariant();
                    if (n.StartsWith("*.", StringComparison.Ordinal)) continue;
                    if (!NameDiscovery.IsValidHostName(n)) continue;
                    if (!names.Contains(n)) names.Add(n);
                    if (names.Count >= MaxNamesPerQuery) return names;
                }
            }
        }
        return names;
    }

    /// <summary>Interroga crt.sh per <c>%.dominio</c>, una volta sola per dominio nell'intero processo; in caso di errore restituisce un elenco vuoto (mai un'eccezione, salvo annullamento).</summary>
    public static async Task<IReadOnlyList<string>> QueryAsync(string domain, CancellationToken ct)
    {
        // la richiesta vive con il proprio timeout, non con il token del chiamante: un annullamento non avvelena la cache
        var task = Cache.GetOrAdd(domain.ToLowerInvariant(), static d => FetchAsync(d));
        return await task.WaitAsync(ct).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<string>> FetchAsync(string domain)
    {
        try
        {
            string url = "https://crt.sh/?q=" + Uri.EscapeDataString("%." + domain) + "&output=json";
            using var cts = new CancellationTokenSource(TimeoutMs);
            using var resp = await Client.Value.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode) return [];
            string json = await resp.Content.ReadAsStringAsync(cts.Token).ConfigureAwait(false);
            return ParseCrtSh(json);
        }
        catch (Exception) { return []; }
    }

    /// <summary>Per i test: svuota la cache.</summary>
    public static void ClearCache() => Cache.Clear();
}
