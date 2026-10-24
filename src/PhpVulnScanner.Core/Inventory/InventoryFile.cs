using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Core.Inventory;

/// <summary>
/// Una voce dell'inventario fornito dall'utente: il bersaglio come scritto (IP, rete CIDR, intervallo, nome o URL ridotta
/// all'host), la versione di PHP dichiarata, l'ambiente, il referente, una nota e l'applicazione. Tutti i campi tranne
/// <see cref="Target"/> possono essere vuoti.
/// </summary>
public sealed record InventoryEntry(string Target, string PhpVersion, string Environment, string Owner, string Note, string Application)
{
    /// <summary>Vero quando il bersaglio è una rete CIDR o un intervallo: la voce vale per ogni indirizzo contenuto.</summary>
    public bool IsNetwork => InventoryFile.IsNetwork(Target);

    /// <summary>Vero quando <paramref name="hostOrIp"/> (indirizzo IP o nome) è coperto da questa voce: uguaglianza senza
    /// distinzione di maiuscole per i nomi e gli IP singoli, appartenenza per reti CIDR e intervalli IPv4.</summary>
    public bool Matches(string hostOrIp) => InventoryFile.Covers(Target, hostOrIp);
}

/// <summary>
/// Lettura dell'inventario (CSV o JSON) con cui riconciliare i risultati. Il file è dato dall'utente e trattato come dati:
/// nessuna riga viene eseguita o interpretata oltre ai campi previsti. Limite di dimensione 5 MB.
/// </summary>
public static class InventoryFile
{
    public const long MaxBytes = 5 * 1024 * 1024;

    /// <summary>Righe scartate dall'ultima lettura (vuote, commenti e intestazione esclusi): colonne mancanti o bersaglio non valido.</summary>
    [ThreadStatic] private static int _skipped;
    public static int LastSkippedRows => _skipped;

    private static readonly string[] TargetAliases = ["target", "host", "ip", "name", "nome", "fqdn", "url", "hostname", "indirizzo", "bersaglio"];
    private static readonly string[] VersionAliases = ["php", "php_version", "phpversion", "versione", "versione_php", "versione php", "php version"];
    private static readonly string[] EnvironmentAliases = ["environment", "ambiente", "env"];
    private static readonly string[] OwnerAliases = ["owner", "referente", "responsabile", "contact", "team", "contatto"];
    private static readonly string[] NoteAliases = ["note", "notes", "descrizione", "description"];
    private static readonly string[] ApplicationAliases = ["application", "app", "applicazione"];

    /// <summary>Legge il file (CSV o JSON, riconosciuto dall'estensione e in subordine dal primo carattere non bianco).</summary>
    public static List<InventoryEntry> Load(string path)
    {
        var fi = new FileInfo(path);
        if (!fi.Exists) throw new FileNotFoundException(L.F("file di inventario non trovato: {0}", path), path);
        if (fi.Length > MaxBytes) throw new InvalidDataException(L.F("file di inventario oltre il limite di {0} MB", MaxBytes / 1024 / 1024));
        string text = File.ReadAllText(path, Encoding.UTF8);   // il BOM UTF-8 viene tolto dalla decodifica
        text = text.TrimStart('﻿');
        bool json = path.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ||
                    (!path.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) && !path.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) && text.TrimStart().Length > 0 && text.TrimStart()[0] is '{' or '[');
        return json ? ParseJson(text) : ParseCsv(text);
    }

    // ---- CSV -----------------------------------------------------------------------------------------------------------

    /// <summary>CSV con riga di intestazione: nomi di colonna senza distinzione di maiuscole e con alias (target|host|ip|name|nome|fqdn|url;
    /// php|php_version|versione|versione_php; environment|ambiente|env; owner|referente|responsabile|contact|team; note|notes|descrizione;
    /// application|app|applicazione). Separatore riconosciuto tra , ; e tabulazione; virgolette gestite; righe vuote e commenti <c>#</c> saltati.</summary>
    public static List<InventoryEntry> ParseCsv(string text) => ParseCsv(text, out _);

    /// <summary>Come <see cref="ParseCsv(string)"/>, con il numero di righe scartate.</summary>
    public static List<InventoryEntry> ParseCsv(string text, out int skipped)
    {
        _skipped = 0;
        var entries = new List<InventoryEntry>();
        text = text.TrimStart('﻿');
        var lines = SplitLines(text);
        var dataLines = lines.Where(l => l.Trim().Length > 0 && !l.TrimStart().StartsWith('#')).ToList();
        skipped = 0;
        if (dataLines.Count == 0) return entries;

        char sep = DetectSeparator(dataLines[0]);
        var header = SplitCsvLine(dataLines[0], sep).Select(h => h.Trim().Trim('"').ToLowerInvariant()).ToList();
        int iTarget = IndexOf(header, TargetAliases), iVer = IndexOf(header, VersionAliases), iEnv = IndexOf(header, EnvironmentAliases),
            iOwner = IndexOf(header, OwnerAliases), iNote = IndexOf(header, NoteAliases), iApp = IndexOf(header, ApplicationAliases);
        if (iTarget < 0) throw new InvalidDataException(L.T("inventario CSV: manca la colonna del bersaglio (target, host, ip, name, nome, fqdn o url)"));

        foreach (var line in dataLines.Skip(1))
        {
            var cells = SplitCsvLine(line, sep);
            string target = NormalizeTarget(Cell(cells, iTarget));
            if (target.Length == 0) { _skipped++; continue; }
            entries.Add(new InventoryEntry(target, Cell(cells, iVer), Cell(cells, iEnv), Cell(cells, iOwner), Cell(cells, iNote), Cell(cells, iApp)));
        }
        skipped = _skipped;
        return entries;
    }

    private static string Cell(List<string> cells, int i) => i >= 0 && i < cells.Count ? cells[i].Trim() : "";

    private static int IndexOf(List<string> header, string[] aliases)
    {
        foreach (var a in aliases)
        {
            int i = header.IndexOf(a);
            if (i >= 0) return i;
        }
        return -1;
    }

    private static List<string> SplitLines(string text)
    {
        // le virgolette possono contenere interruzioni di riga: si ricompongono le righe fisiche finché le virgolette sono pari
        var result = new List<string>();
        var sb = new StringBuilder();
        int quotes = 0;
        foreach (var physical in text.Replace("\r\n", "\n").Split('\n'))
        {
            if (sb.Length > 0) sb.Append('\n');
            sb.Append(physical);
            quotes += physical.Count(c => c == '"');
            if (quotes % 2 == 0) { result.Add(sb.ToString()); sb.Clear(); quotes = 0; }
        }
        if (sb.Length > 0) result.Add(sb.ToString());
        return result;
    }

    internal static char DetectSeparator(string headerLine)
    {
        int Count(char c)
        {
            int n = 0; bool q = false;
            foreach (var ch in headerLine) { if (ch == '"') q = !q; else if (!q && ch == c) n++; }
            return n;
        }
        int comma = Count(','), semi = Count(';'), tab = Count('\t');
        if (tab >= comma && tab >= semi && tab > 0) return '\t';
        if (semi > comma) return ';';
        return ',';
    }

    internal static List<string> SplitCsvLine(string line, char sep)
    {
        var cells = new List<string>();
        var sb = new StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQuotes)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQuotes = false;
                }
                else sb.Append(c);
            }
            else if (c == '"') inQuotes = true;
            else if (c == sep) { cells.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        cells.Add(sb.ToString());
        return cells;
    }

    // ---- JSON ----------------------------------------------------------------------------------------------------------

    /// <summary>JSON: <c>{"assets":[{…}]}</c> oppure un array di oggetti, con le stesse chiavi (e alias) del CSV.</summary>
    public static List<InventoryEntry> ParseJson(string text) => ParseJson(text, out _);

    /// <summary>Come <see cref="ParseJson(string)"/>, con il numero di voci scartate.</summary>
    public static List<InventoryEntry> ParseJson(string text, out int skipped)
    {
        _skipped = 0;
        var entries = new List<InventoryEntry>();
        text = text.TrimStart('﻿');
        using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
        JsonElement arr = doc.RootElement;
        if (arr.ValueKind == JsonValueKind.Object)
        {
            if (!TryProperty(arr, out arr, "assets", "inventory", "inventario", "hosts", "items"))
                throw new InvalidDataException(L.T("inventario JSON: atteso un array \"assets\" oppure un array di oggetti"));
        }
        if (arr.ValueKind != JsonValueKind.Array) throw new InvalidDataException(L.T("inventario JSON: atteso un array \"assets\" oppure un array di oggetti"));
        foreach (var el in arr.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.Object) { _skipped++; continue; }
            string target = NormalizeTarget(Str(el, TargetAliases));
            if (target.Length == 0) { _skipped++; continue; }
            entries.Add(new InventoryEntry(target, Str(el, VersionAliases), Str(el, EnvironmentAliases), Str(el, OwnerAliases), Str(el, NoteAliases), Str(el, ApplicationAliases)));
        }
        skipped = _skipped;
        return entries;
    }

    private static bool TryProperty(JsonElement obj, out JsonElement value, params string[] names)
    {
        foreach (var p in obj.EnumerateObject())
            foreach (var n in names)
                if (p.Name.Equals(n, StringComparison.OrdinalIgnoreCase)) { value = p.Value; return true; }
        value = default;
        return false;
    }

    private static string Str(JsonElement obj, string[] aliases)
    {
        if (!TryProperty(obj, out var v, aliases)) return "";
        return v.ValueKind switch
        {
            JsonValueKind.String => (v.GetString() ?? "").Trim(),
            JsonValueKind.Number => v.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => "",
        };
    }

    // ---- bersagli ------------------------------------------------------------------------------------------------------

    /// <summary>Normalizza il bersaglio: toglie schema, percorso e porta (una URL si riduce al suo host), minuscole per i nomi;
    /// restituisce "" quando non è un IP, una rete CIDR, un intervallo né un nome valido (riga scartata).</summary>
    public static string NormalizeTarget(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return "";
        string token = TargetParser.StripScheme(raw.Trim().Trim('"'));
        if (token.Length == 0) return "";
        if (IsNetwork(token))
        {
            // la validità la decide il parser dei bersagli (stesse regole della finestra); non si espande, si tiene la rete
            var pr = TargetParser.Parse(token);
            return pr.Errors.Count == 0 && pr.Targets.Count > 0 ? token : "";
        }
        if (IPAddress.TryParse(token, out var ip)) return ip.ToString();
        var single = TargetParser.Parse(token);
        if (single.Errors.Count > 0 || single.Targets.Count != 1) return "";
        return single.Targets[0].Host;
    }

    internal static bool IsNetwork(string target) =>
        target.Contains('/') || (target.Contains('-') && target.Length > 0 && char.IsDigit(target[0]) && target.Count(c => c == '.') >= 3);

    /// <summary>Vero quando <paramref name="target"/> (voce dell'inventario) copre <paramref name="hostOrIp"/>.</summary>
    public static bool Covers(string target, string hostOrIp)
    {
        if (string.IsNullOrWhiteSpace(target) || string.IsNullOrWhiteSpace(hostOrIp)) return false;
        hostOrIp = hostOrIp.Trim().TrimEnd('.');
        if (target.Equals(hostOrIp, StringComparison.OrdinalIgnoreCase)) return true;
        if (!IPAddress.TryParse(hostOrIp, out var ip)) return target.TrimEnd('.').Equals(hostOrIp, StringComparison.OrdinalIgnoreCase);
        if (IPAddress.TryParse(target, out var tip)) return tip.Equals(ip);
        if (!IsNetwork(target)) return false;
        return InNetwork(target, ip);
    }

    /// <summary>Appartenenza di un indirizzo a una rete CIDR (IPv4 o IPv6) o a un intervallo IPv4 (<c>a.b.c.d-e.f.g.h</c> o <c>a.b.c.d-h</c>), senza espandere.</summary>
    internal static bool InNetwork(string network, IPAddress ip)
    {
        int slash = network.IndexOf('/');
        if (slash > 0)
        {
            if (!IPAddress.TryParse(network[..slash], out var baseIp) || !int.TryParse(network[(slash + 1)..], out int prefix)) return false;
            if (baseIp.AddressFamily != ip.AddressFamily) return false;
            var a = baseIp.GetAddressBytes(); var b = ip.GetAddressBytes();
            int bits = a.Length * 8;
            if (prefix < 0 || prefix > bits) return false;
            for (int i = 0; i < prefix; i++)
            {
                int mask = 0x80 >> (i % 8);
                if ((a[i / 8] & mask) != (b[i / 8] & mask)) return false;
            }
            return true;
        }
        int dash = network.IndexOf('-');
        if (dash <= 0 || ip.AddressFamily != AddressFamily.InterNetwork) return false;
        if (!IPAddress.TryParse(network[..dash], out var from) || from.AddressFamily != AddressFamily.InterNetwork) return false;
        string toText = network[(dash + 1)..];
        IPAddress to;
        if (toText.All(char.IsDigit) && int.TryParse(toText, out int last) && last is >= 0 and <= 255)
        {
            var fb = from.GetAddressBytes(); fb[3] = (byte)last; to = new IPAddress(fb);
        }
        else if (!IPAddress.TryParse(toText, out to!) || to.AddressFamily != AddressFamily.InterNetwork) return false;
        uint v = ToUInt(ip), lo = ToUInt(from), hi = ToUInt(to);
        return v >= lo && v <= hi;
    }

    private static uint ToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
    }
}
