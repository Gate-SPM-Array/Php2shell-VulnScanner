using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace PhpVulnScanner.Core.Targets;

/// <summary>Un bersaglio da scansionare: come l'ha scritto l'utente e come lo si contatta.</summary>
public sealed record ScanTarget(string Input, string Host, bool IsIpLiteral)
{
    public override string ToString() => Host;
}

/// <summary>
/// Interpreta l'elenco dei bersagli scritto nella finestra: una voce per riga oppure separate da virgola, punto e virgola o spazio.
/// Accetta indirizzi IPv4/IPv6, reti CIDR (<c>192.0.2.0/24</c>), intervalli (<c>192.0.2.10-192.0.2.20</c> o <c>192.0.2.10-20</c>)
/// e nomi (FQDN). Le righe che iniziano con <c>#</c> sono commenti. Le reti vengono espanse fino a un limite di sicurezza.
/// </summary>
public static class TargetParser
{
    /// <summary>Numero massimo di indirizzi espansi da una singola rete o intervallo.</summary>
    public const int MaxExpansion = 65536;

    private static readonly Regex HostName = new(@"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$", RegexOptions.CultureInvariant);

    public sealed record ParseResult(List<ScanTarget> Targets, List<string> Errors);

    public static ParseResult Parse(string? text)
    {
        var targets = new List<ScanTarget>();
        var errors = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(text)) return new ParseResult(targets, errors);

        foreach (var rawLine in text.Split('\n'))
        {
            string line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            int hash = line.IndexOf('#');
            if (hash > 0) line = line[..hash].Trim();
            foreach (var tok in line.Split([',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string token = StripScheme(tok);
                if (token.Length == 0) continue;
                try
                {
                    foreach (var t in Expand(token))
                        if (seen.Add(t.Host)) targets.Add(t);
                }
                catch (FormatException ex) { errors.Add($"{tok}: {ex.Message}"); }
            }
        }
        return new ParseResult(targets, errors);
    }

    /// <summary>Toglie <c>http://</c>, <c>https://</c>, percorso e porta scritti per sbaglio nell'elenco (la porta si imposta a parte).</summary>
    internal static string StripScheme(string s)
    {
        s = s.Trim();
        if (s.Contains("://", StringComparison.Ordinal)) s = s[(s.IndexOf("://", StringComparison.Ordinal) + 3)..];
        int slash = s.IndexOf('/');
        bool cidr = slash > 0 && s[(slash + 1)..].All(char.IsDigit) && s[(slash + 1)..].Length is > 0 and <= 3 && !s.Contains('-');
        if (slash >= 0 && !cidr) s = s[..slash];
        if (s.StartsWith('[')) { int e = s.IndexOf(']'); if (e > 0) s = s[1..e]; }   // [IPv6]:porta
        else if (s.Count(c => c == ':') == 1) { int c = s.IndexOf(':'); if (int.TryParse(s[(c + 1)..], out _)) s = s[..c]; }   // host:porta
        return s.Trim().TrimEnd('.');
    }

    private static IEnumerable<ScanTarget> Expand(string token)
    {
        if (token.Contains('/'))
        {
            foreach (var ip in ExpandCidr(token)) yield return new ScanTarget(token, ip.ToString(), true);
            yield break;
        }
        if (IPAddress.TryParse(token, out var single))
        {
            yield return new ScanTarget(token, single.ToString(), true);
            yield break;
        }
        int dash = token.IndexOf('-');
        if (dash > 0 && char.IsDigit(token[0]) && token.Count(c => c == '.') >= 3)
        {
            foreach (var ip in ExpandRange(token[..dash], token[(dash + 1)..])) yield return new ScanTarget(token, ip.ToString(), true);
            yield break;
        }
        if (HostName.IsMatch(token) && token.Contains('.') && !token.All(c => char.IsDigit(c) || c == '.'))
        {
            yield return new ScanTarget(token, token.ToLowerInvariant(), false);
            yield break;
        }
        if (HostName.IsMatch(token) && !token.Contains('.'))
        {
            // nome breve (host interno senza dominio): accettato, lo risolve il DNS locale
            yield return new ScanTarget(token, token.ToLowerInvariant(), false);
            yield break;
        }
        throw new FormatException(L.T("non è un indirizzo IP, una rete CIDR, un intervallo né un nome valido"));
    }

    private static IEnumerable<IPAddress> ExpandCidr(string cidr)
    {
        int slash = cidr.IndexOf('/');
        if (!IPAddress.TryParse(cidr[..slash], out var baseIp) || !int.TryParse(cidr[(slash + 1)..], out int prefix))
            throw new FormatException(L.T("rete CIDR non valida"));
        int bits = baseIp.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > bits) throw new FormatException(L.T("prefisso CIDR fuori intervallo"));
        int hostBits = bits - prefix;
        if (hostBits > 16) throw new FormatException(L.F("la rete contiene più di {0} indirizzi: ridurre il prefisso", MaxExpansion));
        var bytes = baseIp.GetAddressBytes();
        // azzera i bit host
        for (int i = prefix; i < bits; i++) bytes[i / 8] &= (byte)~(0x80 >> (i % 8));
        long count = 1L << hostBits;
        var start = new IPAddress(bytes);
        // per IPv4 con prefisso <= 30 si saltano indirizzo di rete e broadcast
        bool skipEnds = bits == 32 && prefix <= 30;
        for (long i = skipEnds ? 1 : 0; i < (skipEnds ? count - 1 : count); i++)
            yield return Add(start, i);
    }

    private static IEnumerable<IPAddress> ExpandRange(string from, string to)
    {
        if (!IPAddress.TryParse(from, out var a) || a.AddressFamily != AddressFamily.InterNetwork)
            throw new FormatException(L.T("intervallo non valido: l'inizio deve essere un indirizzo IPv4"));
        IPAddress b;
        if (to.All(char.IsDigit) && int.TryParse(to, out int last) && last is >= 0 and <= 255)
        {
            var bytes = a.GetAddressBytes();
            bytes[3] = (byte)last;
            b = new IPAddress(bytes);
        }
        else if (to.Count(c => c == '.') == 3 && IPAddress.TryParse(to, out var full) && full.AddressFamily == AddressFamily.InterNetwork) b = full;
        else throw new FormatException(L.T("intervallo non valido: la fine deve essere un indirizzo IPv4 o l'ultimo ottetto"));
        long ia = ToLong(a), ib = ToLong(b);
        if (ib < ia) throw new FormatException(L.T("intervallo non valido: la fine precede l'inizio"));
        if (ib - ia + 1 > MaxExpansion) throw new FormatException(L.F("l'intervallo contiene più di {0} indirizzi", MaxExpansion));
        for (long i = ia; i <= ib; i++) yield return FromLong(i);
    }

    private static long ToLong(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3];
    }

    private static IPAddress FromLong(long v) => new([(byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v]);

    private static IPAddress Add(IPAddress ip, long n)
    {
        var b = ip.GetAddressBytes();
        for (int i = b.Length - 1; i >= 0 && n > 0; i--)
        {
            long sum = b[i] + (n & 0xFF);
            b[i] = (byte)(sum & 0xFF);
            n = (n >> 8) + (sum >> 8);
        }
        return new IPAddress(b);
    }

    /// <summary>
    /// Chiave di ordinamento testuale: "0:" più i 4 ottetti a 3 cifre per IPv4, "1:" più i 16 byte in esadecimale per IPv6,
    /// "2:" più il nome in minuscolo per gli FQDN. Un ordinamento per stringa su questa chiave rispetta la numerazione IP.
    /// </summary>
    public static string SortKey(string host)
    {
        if (IPAddress.TryParse(host, out var ip))
        {
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork) return "0:" + string.Join(".", b.Select(x => x.ToString("D3")));
            return "1:" + Convert.ToHexString(b);
        }
        return "2:" + host.ToLowerInvariant();
    }

    /// <summary>Interpreta l'elenco delle porte TCP: <c>443</c>, <c>443,8443</c>, <c>8000-8010</c>.</summary>
    public static List<int> ParsePorts(string? text, out List<string> errors)
    {
        errors = [];
        var ports = new List<int>();
        if (string.IsNullOrWhiteSpace(text)) return ports;
        foreach (var tok in text.Split([',', ';', ' ', '\n', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int dash = tok.IndexOf('-');
            if (dash > 0 && int.TryParse(tok[..dash], out int a) && int.TryParse(tok[(dash + 1)..], out int b) && a >= 1 && b <= 65535 && a <= b && b - a <= 1024)
            {
                for (int p = a; p <= b; p++) if (!ports.Contains(p)) ports.Add(p);
            }
            else if (int.TryParse(tok, out int p) && p is >= 1 and <= 65535)
            {
                if (!ports.Contains(p)) ports.Add(p);
            }
            else errors.Add(tok);
        }
        return ports;
    }

    /// <summary>Interpreta l'elenco dei percorsi HTTP da sondare (uno per riga o separati da spazio/virgola); garantisce la barra iniziale.</summary>
    public static List<string> ParsePaths(string? text)
    {
        var paths = new List<string>();
        if (string.IsNullOrWhiteSpace(text)) return paths;
        foreach (var tok in text.Split([',', ';', ' ', '\n', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (tok.StartsWith('#')) continue;
            string p = tok.StartsWith('/') ? tok : "/" + tok;
            if (!paths.Contains(p, StringComparer.Ordinal)) paths.Add(p);
        }
        return paths;
    }
}
