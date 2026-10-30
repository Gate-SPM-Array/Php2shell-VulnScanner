using System.Net;

namespace PhpVulnScanner.Core.Targets;

/// <summary>
/// v1.12: assegnazioni locali nome → IP, senza query DNS: come il file hosts del sistema operativo. Arrivano da un file in formato hosts
/// (<c>IP nome [nome…]</c>, commenti con <c>#</c>) o dalla lista bersagli con la sintassi <c>nome@IP</c>. Ogni nome diventa una riga
/// "nome @ IP" (TCP verso l'IP, SNI e Host = nome), come un browser con la voce nel file hosts; l'IP entra tra i bersagli se non c'è già.
/// Un nome assegnato nel file non viene mai risolto dal DNS (precedenza come nel sistema operativo) e non ripiega mai su un'altra riga.
/// </summary>
public static class HostsFile
{
    public sealed record Entry(string Name, string Ip);

    /// <summary>Interpreta il contenuto di un file hosts. Il nome "localhost" (copie del file di sistema) viene saltato.</summary>
    public static List<Entry> Parse(string? text, List<string> errors)
    {
        var list = new List<Entry>();
        if (string.IsNullOrWhiteSpace(text)) return list;
        int n = 0;
        foreach (var raw in text.Split('\n'))
        {
            n++;
            string line = raw.Trim();
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash].Trim();
            if (line.Length == 0) continue;
            var tok = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (tok.Length < 2 || !IPAddress.TryParse(tok[0], out var ip))
            {
                errors.Add(L.F("file hosts, riga {0}: attesi un indirizzo IP e almeno un nome", n));
                continue;
            }
            for (int i = 1; i < tok.Length; i++)
            {
                string name = tok[i].TrimEnd('.').ToLowerInvariant();
                if (name is "localhost" or "localhost.localdomain" or "ip6-localhost" or "ip6-loopback") continue;   // righe del file di sistema
                if (!IsName(name)) { errors.Add(L.F("file hosts, riga {0}: nome non valido: {1}", n, tok[i])); continue; }
                Add(list, name, ip.ToString());
            }
        }
        return list;
    }

    /// <summary>Legge un file hosts dal disco; errori di lettura e di formato finiscono in <paramref name="errors"/>.</summary>
    public static List<Entry> Load(string? path, List<string> errors)
    {
        if (string.IsNullOrWhiteSpace(path)) return [];
        try { return Parse(File.ReadAllText(path), errors); }
        catch (Exception ex) { errors.Add(L.F("file hosts non letto ({0}): {1}", path, ex.Message)); return []; }
    }

    /// <summary>Un nome vale una sola assegnazione: la prima vince (come nel sistema operativo).</summary>
    public static void Add(List<Entry> list, string name, string ip)
    {
        if (list.Any(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase))) return;
        list.Add(new Entry(name.ToLowerInvariant(), ip));
    }

    public static bool IsName(string s) => TargetParser.IsHostName(s) && !IPAddress.TryParse(s, out _);
}
