using System.Text;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Core.Output;

/// <summary>
/// Elenchi di testo pronti per altri strumenti (una voce per riga, nessuna intestazione, LF, riga vuota finale):
/// host attivi, host con risposta HTTP, nomi DNS scoperti. Il motore li riscrive alla fine di ogni ciclo con l'unione
/// delle osservazioni raccolte fino a quel momento; qui si deduplica e si ordina (IPv4 numerico, IPv6, nomi).
/// </summary>
public static class HostLists
{
    public const string AliveFilePrefix = "host_attivi_v";
    public const string HttpFilePrefix = "host_http_v";
    public const string NamesFilePrefix = "nomi_scoperti_v";

    /// <summary>
    /// Host attivo: alive check positivo, oppure alive check non eseguito e almeno una risposta HTTP o un handshake TLS
    /// (stessa regola del motore con alive check spento).
    /// </summary>
    public static bool IsAlive(ScanResult r) =>
        r.Alive == AliveState.Alive || (r.Alive == AliveState.NotTested && (r.HttpReachable || r.Tls is { Handshake: true }));

    /// <summary>Indirizzo IP della riga: l'host stesso se IP, altrimenti il primo indirizzo risolto (o il nome, se non risolto).</summary>
    public static string HostIp(ScanResult r) => r.DisplayIp;

    /// <summary>Host (IP) attivi, uno per riga.</summary>
    public static string AliveHostsText(IEnumerable<ScanResult> rows) => Lines(AliveHosts(rows));

    /// <summary>Host (IP) con almeno una risposta HTTP, uno per riga.</summary>
    public static string HttpHostsText(IEnumerable<ScanResult> rows) => Lines(HttpHosts(rows));

    /// <summary>Nomi DNS validi (senza wildcard) raccolti da certificati, Location, link, nomi inseriti e nomi con lo stesso contenuto, uno per riga.</summary>
    public static string DiscoveredNamesText(IEnumerable<ScanResult> rows) => Lines(Names(rows));

    public static List<string> AliveHosts(IEnumerable<ScanResult> rows) => Sorted(rows.Where(IsAlive).Select(HostIp));

    public static List<string> HttpHosts(IEnumerable<ScanResult> rows) => Sorted(rows.Where(r => r.HttpReachable).Select(HostIp));

    public static List<string> Names(IEnumerable<ScanResult> rows) => Sorted(rows.SelectMany(NamesOf));

    /// <summary>Nomi validi di una riga: DisplayName, nomi scoperti, nomi con lo stesso contenuto, nomi con lo stesso esito; wildcard e nomi non validi esclusi.</summary>
    public static IEnumerable<string> NamesOf(ScanResult r)
    {
        if (r.DisplayName.Length > 0) yield return r.DisplayName;
        foreach (var n in r.DiscoveredNames) yield return n;
        foreach (var n in r.SameContentNames) yield return n;
        foreach (var n in r.SameOutcomeNames) yield return n;
    }

    private static List<string> Sorted(IEnumerable<string> values)
    {
        var set = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in values)
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            string v = raw.Trim().TrimEnd('.');
            if (v.Length == 0 || v.Contains('*')) continue;
            if (!System.Net.IPAddress.TryParse(v, out _))
            {
                if (!NameDiscovery.IsValidHostName(v)) continue;
                v = v.ToLowerInvariant();
            }
            set.TryAdd(v, v);
        }
        return set.Values.OrderBy(TargetParser.SortKey, StringComparer.Ordinal).ToList();
    }

    private static string Lines(List<string> entries)
    {
        var sb = new StringBuilder(entries.Count * 16 + 1);
        foreach (var e in entries) sb.Append(e).Append('\n');
        return sb.ToString();
    }

    public static string AliveFileName(string version) => $"{AliveFilePrefix}{version}.txt";
    public static string HttpFileName(string version) => $"{HttpFilePrefix}{version}.txt";
    public static string NamesFileName(string version) => $"{NamesFilePrefix}{version}.txt";

    /// <summary>
    /// Scrive i tre elenchi nella cartella di sessione in modo atomico (file temporaneo + rename). <paramref name="rows"/> può
    /// contenere più osservazioni dello stesso servizio (cicli): la deduplicazione è interna.
    /// </summary>
    public static void Write(string folder, string version, IEnumerable<ScanResult> rows)
    {
        var list = rows as IReadOnlyCollection<ScanResult> ?? rows.ToList();
        SessionFiles.WriteAllTextAtomic(Path.Combine(folder, AliveFileName(version)), AliveHostsText(list));
        SessionFiles.WriteAllTextAtomic(Path.Combine(folder, HttpFileName(version)), HttpHostsText(list));
        SessionFiles.WriteAllTextAtomic(Path.Combine(folder, NamesFileName(version)), DiscoveredNamesText(list));
    }
}
