using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;

namespace PhpVulnScanner.Core.Output;

/// <summary>
/// Filtro testuale della tabella dei risultati (v1.5). Sintassi:
/// termini separati da spazio = AND; <c>a|b</c> = OR (lega più stretto dell'AND: <c>a b|c</c> è a AND (b OR c));
/// <c>-x</c> esclude; <c>"testo con spazi"</c>; <c>campo:valore</c> limita il termine a un campo
/// (ip, nome, porta, ver, sapi, app, waf, motivo, superficie, verdetto, priorita, alive, barriera, php, tech, esposizione, os, ciclo,
/// con gli alias inglesi); senza campo il termine è cercato in tutti i campi testuali.
/// Un termine senza jolly è una ricerca di sottostringa (senza distinzione tra maiuscole e minuscole); con <c>*</c> o <c>?</c>
/// è un glob ancorato sull'intero valore (per i campi a elenco basta un elemento). <c>ip:</c> accetta anche una rete CIDR
/// (<c>192.0.2.0/24</c>) o un intervallo (<c>192.0.2.10-50</c>, <c>192.0.2.10-192.0.2.50</c>); <c>porta:</c> e <c>ciclo:</c>
/// accettano l'intervallo numerico <c>a-b</c>. Un'espressione malformata non lancia mai eccezioni: <see cref="IsValid"/> è falso,
/// <see cref="Error"/> spiega il problema e <see cref="Matches(ScanResult)"/> non trova nulla.
/// </summary>
public sealed class ResultFilter
{
    private enum Field
    {
        Any, Ip, Name, Port, Version, Sapi, App, Waf, Reason, Surface, Verdict, Priority, Alive, Barrier, Php, Tech, Exposure, Os, Cycle,
    }

    private static readonly Dictionary<string, Field> FieldNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ip"] = Field.Ip,
        ["nome"] = Field.Name, ["name"] = Field.Name,
        ["porta"] = Field.Port, ["port"] = Field.Port,
        ["ver"] = Field.Version, ["versione"] = Field.Version, ["version"] = Field.Version,
        ["sapi"] = Field.Sapi,
        ["app"] = Field.App,
        ["waf"] = Field.Waf,
        ["motivo"] = Field.Reason, ["reason"] = Field.Reason,
        ["superficie"] = Field.Surface, ["surface"] = Field.Surface,
        ["verdetto"] = Field.Verdict, ["verdict"] = Field.Verdict,
        ["priorita"] = Field.Priority, ["priorità"] = Field.Priority, ["priority"] = Field.Priority,
        ["alive"] = Field.Alive,
        ["barriera"] = Field.Barrier, ["barrier"] = Field.Barrier,
        ["php"] = Field.Php,
        ["tecnologia"] = Field.Tech, ["tech"] = Field.Tech,
        ["esposizione"] = Field.Exposure, ["exposure"] = Field.Exposure,
        ["os"] = Field.Os,
        ["ciclo"] = Field.Cycle, ["cycle"] = Field.Cycle,
    };

    private static readonly Field[] AllFields = Enum.GetValues<Field>().Where(f => f != Field.Any).ToArray();

    /// <summary>Nomi dei campi accettati (italiano e alias), per i messaggi e la guida.</summary>
    public static IReadOnlyCollection<string> KnownFields => FieldNames.Keys;

    private enum Kind { Substring, Glob, Cidr, IpRange, NumberRange, PhpYes, PhpNo, PhpMaybe }

    private sealed class Term
    {
        public bool Negated;
        public Field Field;
        public Kind Kind;
        public string Text = "";                 // sottostringa (minuscolo) o testo originale
        public Regex? Glob;
        public byte[]? NetBase; public int Prefix;   // CIDR
        public long RangeFrom, RangeTo;              // intervallo IPv4 (valore a 32 bit) o numerico
    }

    private readonly List<List<Term>> _groups = [];   // AND di gruppi; ogni gruppo è un OR di termini

    private ResultFilter() { }

    /// <summary>Espressione originale.</summary>
    public string Query { get; private set; } = "";
    /// <summary>Messaggio d'errore (vuoto se l'espressione è valida).</summary>
    public string Error { get; private set; } = "";
    public bool IsValid => Error.Length == 0;
    /// <summary>Vero se l'espressione non contiene termini (tutto passa).</summary>
    public bool IsEmpty => _groups.Count == 0;

    /// <summary>Interpreta l'espressione; non lancia mai: un'espressione malformata dà un filtro non valido che non trova nulla.</summary>
    public static ResultFilter Parse(string? query)
    {
        var f = new ResultFilter { Query = query ?? "" };
        try { f.ParseInto(f.Query); }
        catch (FormatException ex) { f.Error = ex.Message; f._groups.Clear(); }
        catch (Exception ex) { f.Error = L.F("filtro non valido: {0}", ex.Message); f._groups.Clear(); }
        return f;
    }

    /// <summary>Comodità: interpreta e confronta in un colpo solo.</summary>
    public static bool Matches(string? query, ScanResult r) => Parse(query).Matches(r);

    public bool Matches(ScanResult r)
    {
        if (!IsValid) return false;
        foreach (var group in _groups)
        {
            bool any = false;
            foreach (var t in group)
            {
                bool hit = MatchTerm(t, r);
                if (t.Negated) hit = !hit;
                if (hit) { any = true; break; }
            }
            if (!any) return false;
        }
        return true;
    }

    // ---------------------------------------------------------------- analisi

    private void ParseInto(string query)
    {
        int i = 0;
        List<Term>? current = null;
        bool expectAlternative = false;      // dopo un "|"
        while (i < query.Length)
        {
            char c = query[i];
            if (char.IsWhiteSpace(c)) { i++; continue; }
            if (c == '|')
            {
                if (current == null || expectAlternative) throw new FormatException(L.T("filtro: «|» senza un termine prima"));
                expectAlternative = true;
                i++;
                continue;
            }
            var term = ReadTerm(query, ref i);
            if (expectAlternative) { current!.Add(term); expectAlternative = false; }
            else { current = [term]; _groups.Add(current); }
        }
        if (expectAlternative) throw new FormatException(L.T("filtro: «|» senza un termine dopo"));
    }

    private static Term ReadTerm(string q, ref int i)
    {
        var t = new Term();
        if (q[i] == '-' && i + 1 < q.Length && !char.IsWhiteSpace(q[i + 1]) && q[i + 1] != '|') { t.Negated = true; i++; }
        // prefisso campo: lettere seguite da ':'
        int j = i;
        while (j < q.Length && (char.IsLetter(q[j]))) j++;
        if (j > i && j < q.Length && q[j] == ':')
        {
            string name = q[i..j];
            if (!FieldNames.TryGetValue(name, out var field))
                throw new FormatException(L.F("filtro: campo sconosciuto «{0}» (campi: ip, nome, porta, ver, sapi, app, waf, motivo, superficie, verdetto, priorita, alive, barriera, php, tech, esposizione, os, ciclo)", name));
            t.Field = field;
            i = j + 1;
        }
        string value;
        if (i < q.Length && q[i] == '"')
        {
            int end = q.IndexOf('"', i + 1);
            if (end < 0) throw new FormatException(L.T("filtro: virgolette non chiuse"));
            value = q[(i + 1)..end];
            i = end + 1;
        }
        else
        {
            int start = i;
            while (i < q.Length && !char.IsWhiteSpace(q[i]) && q[i] != '|') i++;
            value = q[start..i];
        }
        if (value.Length == 0)
            throw new FormatException(t.Field == Field.Any ? L.T("filtro: termine vuoto") : L.T("filtro: valore mancante dopo il nome del campo"));
        Classify(t, value);
        return t;
    }

    private static void Classify(Term t, string value)
    {
        t.Text = value;
        if (t.Field == Field.Php)
        {
            switch (value.ToLowerInvariant())
            {
                case "si": case "sì": case "yes": t.Kind = Kind.PhpYes; return;
                case "no": t.Kind = Kind.PhpNo; return;
                case "forse": case "maybe": t.Kind = Kind.PhpMaybe; return;
            }
        }
        if (t.Field == Field.Ip)
        {
            if (value.Contains('/'))
            {
                int slash = value.IndexOf('/');
                if (!IPAddress.TryParse(value[..slash], out var baseIp) || !int.TryParse(value[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out int prefix)
                    || prefix < 0 || prefix > (baseIp.AddressFamily == AddressFamily.InterNetwork ? 32 : 128))
                    throw new FormatException(L.F("filtro: rete CIDR non valida «{0}»", value));
                var bytes = baseIp.GetAddressBytes();
                for (int b = prefix; b < bytes.Length * 8; b++) bytes[b / 8] &= (byte)~(0x80 >> (b % 8));
                t.Kind = Kind.Cidr; t.NetBase = bytes; t.Prefix = prefix;
                return;
            }
            int dash = value.IndexOf('-');
            if (dash > 0 && IPAddress.TryParse(value[..dash], out var from) && from.AddressFamily == AddressFamily.InterNetwork)
            {
                string to = value[(dash + 1)..];
                long a = ToLong(from), b;
                if (to.Length > 0 && to.All(char.IsDigit) && int.TryParse(to, NumberStyles.None, CultureInfo.InvariantCulture, out int last) && last <= 255)
                    b = (a & ~0xFFL) | (uint)last;
                else if (IPAddress.TryParse(to, out var toIp) && toIp.AddressFamily == AddressFamily.InterNetwork) b = ToLong(toIp);
                else throw new FormatException(L.F("filtro: intervallo di indirizzi non valido «{0}»", value));
                if (b < a) throw new FormatException(L.F("filtro: intervallo di indirizzi non valido «{0}»", value));
                t.Kind = Kind.IpRange; t.RangeFrom = a; t.RangeTo = b;
                return;
            }
        }
        if (t.Field is Field.Port or Field.Cycle)
        {
            int dash = value.IndexOf('-');
            if (dash > 0 && long.TryParse(value[..dash], NumberStyles.None, CultureInfo.InvariantCulture, out long a)
                && long.TryParse(value[(dash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out long b) && a <= b)
            {
                t.Kind = Kind.NumberRange; t.RangeFrom = a; t.RangeTo = b;
                return;
            }
        }
        if (value.Contains('*') || value.Contains('?'))
        {
            t.Kind = Kind.Glob;
            t.Glob = GlobRegex(value);
        }
        else t.Kind = Kind.Substring;
    }

    private static readonly ConcurrentDictionary<string, Regex> GlobCache = new(StringComparer.Ordinal);

    /// <summary>Glob ancorato: <c>*</c> qualsiasi sequenza (anche vuota), <c>?</c> un carattere; tutto il resto letterale.</summary>
    internal static Regex GlobRegex(string glob)
    {
        if (GlobCache.Count > 512) GlobCache.Clear();
        return GlobCache.GetOrAdd(glob, g =>
        {
            var sb = new StringBuilder("^");
            foreach (char c in g)
                sb.Append(c switch { '*' => ".*", '?' => ".", _ => Regex.Escape(c.ToString()) });
            sb.Append('$');
            return new Regex(sb.ToString(), RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Singleline);
        });
    }

    // ---------------------------------------------------------------- confronto

    private static bool MatchTerm(Term t, ScanResult r)
    {
        switch (t.Kind)
        {
            case Kind.PhpYes: return r.PhpDetected;
            case Kind.PhpNo: return string.Equals(r.PhpPresence, "no", StringComparison.OrdinalIgnoreCase);
            case Kind.PhpMaybe: return string.Equals(r.PhpPresence, "maybe", StringComparison.OrdinalIgnoreCase);
            case Kind.Cidr:
                return IpValues(r).Any(v => IPAddress.TryParse(v, out var ip) && InCidr(ip, t.NetBase!, t.Prefix));
            case Kind.IpRange:
                return IpValues(r).Any(v => IPAddress.TryParse(v, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork && ToLong(ip) >= t.RangeFrom && ToLong(ip) <= t.RangeTo);
            case Kind.NumberRange:
                {
                    long n = t.Field == Field.Port ? r.Port : r.Cycle;
                    return n >= t.RangeFrom && n <= t.RangeTo;
                }
            case Kind.Glob:
                return Values(t.Field, r).Any(v => t.Glob!.IsMatch(v));
            default:
                return Values(t.Field, r).Any(v => v.Contains(t.Text, StringComparison.OrdinalIgnoreCase));
        }
    }

    private static IEnumerable<string> Values(Field f, ScanResult r)
    {
        if (f != Field.Any) return FieldValues(f, r);
        return AllFields.SelectMany(x => FieldValues(x, r));
    }

    private static IEnumerable<string> IpValues(ScanResult r)
    {
        yield return r.DisplayIp;
        foreach (var ip in r.ResolvedIps) yield return ip;
    }

    private static IEnumerable<string> FieldValues(Field f, ScanResult r)
    {
        switch (f)
        {
            case Field.Ip:
                return IpValues(r);
            case Field.Name:
                return new[] { r.DisplayName, r.HostHeader }.Concat(r.DiscoveredNames).Concat(r.SameContentNames).Concat(r.SameOutcomeNames);
            case Field.Port:
                return [r.Port.ToString(CultureInfo.InvariantCulture)];
            case Field.Version:
                return [r.PhpVersionRaw];
            case Field.Sapi:
                return r.Sapi.Length > 0 ? [r.Sapi, Labels.Sapi(r.Sapi)] : [];
            case Field.App:
                return r.Application.Length > 0
                    ? [r.Application + (r.ApplicationVersion.Length > 0 ? " " + r.ApplicationVersion : ""), r.Application, r.ApplicationVersion]
                    : [];
            case Field.Waf:
                return [r.WafSummary];
            case Field.Reason:
                return [r.VerdictReason];
            case Field.Surface:
                return r.PhpSurface;
            case Field.Verdict:
                return [r.Verdict.ToString(), Labels.Verdict(r.Verdict)];
            case Field.Priority:
                return [r.Priority.ToString(), Labels.Priority(r.Priority)];
            case Field.Alive:
                return [r.Alive.ToString(), Labels.Alive(r.Alive)];
            case Field.Barrier:
                return [r.Multipart.ToString(), Labels.Multipart(r.Multipart)];
            case Field.Php:
                return [r.PhpPresence];
            case Field.Tech:
                return r.Technologies;
            case Field.Exposure:
                return r.Exposures;
            case Field.Os:
                return [r.OsHint];
            case Field.Cycle:
                return [r.Cycle.ToString(CultureInfo.InvariantCulture)];
            default:
                return [];
        }
    }

    private static bool InCidr(IPAddress ip, byte[] netBase, int prefix)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != netBase.Length) return false;
        int full = prefix / 8, rest = prefix % 8;
        for (int i = 0; i < full; i++) if (b[i] != netBase[i]) return false;
        if (rest == 0) return true;
        int mask = 0xFF << (8 - rest) & 0xFF;
        return (b[full] & mask) == (netBase[full] & mask);
    }

    private static long ToLong(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3];
    }
}
