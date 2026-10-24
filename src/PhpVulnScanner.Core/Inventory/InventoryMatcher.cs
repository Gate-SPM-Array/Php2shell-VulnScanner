using System.Text.Json;
using System.Text.Json.Serialization;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;

namespace PhpVulnScanner.Core.Inventory;

/// <summary>Riferimento compatto a un servizio (riga della tabella) dentro il report di inventario: basta per ritrovarlo e per nominare chi deve agire.</summary>
public sealed record InventoryServiceRef(string Key, string Ip, int Port, List<string> Names, string Verdict, string Owner);

/// <summary>Versione dichiarata nell'inventario diversa da quella osservata su un servizio.</summary>
public sealed record InventoryVersionMismatch(InventoryServiceRef Service, string Declared, string Observed);

/// <summary>
/// Esito della riconciliazione tra inventario e risultati: contatori, voci dichiarate mai osservate, servizi HTTP non inventariati,
/// versioni diverse, referente per servizio. Viene scritto nella cartella della sessione come <c>inventario_vX.Y.json</c>.
/// </summary>
public sealed class InventoryReport
{
    public string AppVersion { get; set; } = HttpProbe.AppVersion;
    public string InventoryPath { get; set; } = "";
    /// <summary>Voci lette dall'inventario.</summary>
    public int Entries { get; set; }
    /// <summary>Righe o voci scartate alla lettura (bersaglio mancante o non valido).</summary>
    public int SkippedRows { get; set; }
    /// <summary>Servizi (righe) riconciliati con una voce dell'inventario.</summary>
    public int Matched { get; set; }
    /// <summary>Voci dell'inventario il cui bersaglio non compare mai con HTTP nei risultati.</summary>
    public List<InventoryEntry> DeclaredNotObserved { get; set; } = [];
    /// <summary>Servizi con HTTP il cui indirizzo e i cui nomi non sono in inventario.</summary>
    public List<InventoryServiceRef> ObservedNotInventoried { get; set; } = [];
    /// <summary>Servizi con versione dichiarata diversa da quella osservata.</summary>
    public List<InventoryVersionMismatch> VersionMismatches { get; set; } = [];
    /// <summary>Servizi in inventario con una versione dichiarata ma nessun PHP osservato.</summary>
    public List<InventoryServiceRef> DeclaredPhpNotObserved { get; set; } = [];
    /// <summary>Referente per chiave di servizio (<see cref="ScanResult.Key"/>).</summary>
    public Dictionary<string, string> OwnerByService { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Referente di un servizio, "" se non in inventario.</summary>
    public string OwnerOf(ScanResult r) => OwnerByService.TryGetValue(r.Key, out var o) ? o : "";

    /// <summary>Una riga di sintesi nella lingua dell'interfaccia.</summary>
    public string Summary() =>
        L.F("Inventario: {0} voci, {1} servizi riconciliati, {2} dichiarati ma non osservati, {3} osservati ma non inventariati, {4} versioni diverse",
            Entries, Matched, DeclaredNotObserved.Count, ObservedNotInventoried.Count, VersionMismatches.Count)
        + (DeclaredPhpNotObserved.Count > 0 ? ", " + L.F("{0} con PHP dichiarato ma non osservato", DeclaredPhpNotObserved.Count) : "")
        + (SkippedRows > 0 ? " " + L.F("({0} righe scartate alla lettura)", SkippedRows) : "");

    /// <summary>Nome del file nella cartella della sessione: <c>inventario_v&lt;versione&gt;.json</c>.</summary>
    public static string FileName(string? appVersion = null) => $"inventario_v{appVersion ?? HttpProbe.AppVersion}.json";

    public static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() }, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
}

/// <summary>
/// Riconciliazione tra l'inventario dichiarato e ciò che la scansione ha osservato. Il confronto avviene su indirizzo
/// (<see cref="ScanResult.DisplayIp"/>, indirizzi risolti) e su nomi (host, Host header, nomi scoperti, stesso contenuto,
/// stesso esito), senza distinzione di maiuscole; una voce CIDR o intervallo copre ogni indirizzo contenuto.
/// Idempotente: ogni applicazione azzera e ricalcola i campi Inventory* dei risultati.
/// </summary>
public static class InventoryMatcher
{
    public const string StatusOk = "ok";
    public const string StatusVersionDiffers = "versione diversa";
    public const string StatusDeclaredPhpNotObserved = "dichiarato, PHP non osservato";
    public const string StatusVersionNotObserved = "versione non osservata";
    public const string StatusNotObserved = "non osservato";

    /// <summary>Etichetta dello stato (chiave stabile nei file) nella lingua dell'interfaccia.</summary>
    public static string StatusLabel(string status) => status switch
    {
        StatusOk => L.T("ok"),
        StatusVersionDiffers => L.T("versione diversa"),
        StatusDeclaredPhpNotObserved => L.T("dichiarato, PHP non osservato"),
        StatusVersionNotObserved => L.T("versione non osservata"),
        StatusNotObserved => L.T("non osservato"),
        "" => "",
        _ => status,
    };

    /// <summary>Riconcilia e compila i campi Inventory* di ogni risultato; restituisce il report.</summary>
    public static InventoryReport Reconcile(IReadOnlyList<InventoryEntry> inventory, IReadOnlyList<ScanResult> results)
    {
        var rep = new InventoryReport { Entries = inventory.Count, SkippedRows = InventoryFile.LastSkippedRows };
        var observedEntries = new HashSet<InventoryEntry>();

        foreach (var r in results)
        {
            r.InventoryStatus = ""; r.InventoryDeclaredVersion = ""; r.InventoryOwner = ""; r.InventoryEnvironment = ""; r.InventoryNote = "";
            var entry = Find(inventory, r);
            if (entry == null)
            {
                if (r.HttpReachable) rep.ObservedNotInventoried.Add(Ref(r, ""));
                continue;
            }
            rep.Matched++;
            r.InventoryOwner = entry.Owner; r.InventoryEnvironment = entry.Environment; r.InventoryNote = entry.Note; r.InventoryDeclaredVersion = entry.PhpVersion;
            if (entry.Owner.Length > 0) rep.OwnerByService[r.Key] = entry.Owner;
            if (r.HttpReachable) observedEntries.Add(entry);

            r.InventoryStatus = Status(entry, r);
            if (r.InventoryStatus == StatusVersionDiffers) rep.VersionMismatches.Add(new InventoryVersionMismatch(Ref(r, entry.Owner), entry.PhpVersion, r.PhpVersionRaw));
            else if (r.InventoryStatus == StatusDeclaredPhpNotObserved) rep.DeclaredPhpNotObserved.Add(Ref(r, entry.Owner));
        }

        foreach (var e in inventory)
            if (!observedEntries.Contains(e)) rep.DeclaredNotObserved.Add(e);
        return rep;
    }

    /// <summary>Stesso lavoro di <see cref="Reconcile"/> per i percorsi di unione e di riapertura di una sessione.</summary>
    public static InventoryReport ApplyToResults(IReadOnlyList<InventoryEntry> entries, IReadOnlyList<ScanResult> results) => Reconcile(entries, results);

    /// <summary>
    /// Se <see cref="ScanConfig.InventoryPath"/> è impostato: legge l'inventario, riconcilia i risultati della sessione (campi
    /// Inventory* serializzati con i risultati) e scrive il report in <c>&lt;cartella della sessione&gt;\inventario_vX.Y.json</c>.
    /// Restituisce null quando non c'è inventario; gli errori di lettura vanno nel log e non fermano la scansione.
    /// </summary>
    public static InventoryReport? Apply(ScanConfig cfg, ScanSession s, Action<string>? log)
    {
        if (string.IsNullOrWhiteSpace(cfg.InventoryPath)) return null;
        List<InventoryEntry> entries;
        try { entries = InventoryFile.Load(cfg.InventoryPath.Trim()); }
        catch (Exception ex)
        {
            log?.Invoke(L.F("Inventario non letto: {0}", ex.GetBaseException().Message));
            return null;
        }
        var rep = Reconcile(entries, s.Results);
        rep.InventoryPath = cfg.InventoryPath.Trim();
        rep.AppVersion = s.AppVersion;
        if (!string.IsNullOrWhiteSpace(s.Folder))
        {
            try
            {
                Directory.CreateDirectory(s.Folder);
                SessionFiles.WriteAllTextAtomic(Path.Combine(s.Folder, InventoryReport.FileName(s.AppVersion)), JsonSerializer.Serialize(rep, InventoryReport.JsonOptions));
            }
            catch (Exception ex) { log?.Invoke(L.F("Report di inventario non scritto: {0}", ex.GetBaseException().Message)); }
        }
        log?.Invoke(rep.Summary());
        return rep;
    }

    /// <summary>Legge il report scritto da <see cref="Apply"/> nella cartella di una sessione, null se assente o illeggibile.</summary>
    public static InventoryReport? Read(string folder, string? appVersion = null)
    {
        try
        {
            string path = Path.Combine(folder, InventoryReport.FileName(appVersion));
            if (!File.Exists(path))
            {
                path = Directory.EnumerateFiles(folder, "inventario_v*.json").OrderBy(f => f, StringComparer.Ordinal).LastOrDefault() ?? "";
                if (path.Length == 0) return null;
            }
            return JsonSerializer.Deserialize<InventoryReport>(File.ReadAllText(path), InventoryReport.JsonOptions);
        }
        catch { return null; }
    }

    // ---- confronto -----------------------------------------------------------------------------------------------------

    /// <summary>Candidati di confronto di un servizio: indirizzo, indirizzi risolti, host, Host header, nomi scoperti e ripiegati.</summary>
    public static IEnumerable<string> Candidates(ScanResult r)
    {
        yield return r.DisplayIp;
        foreach (var ip in r.ResolvedIps) yield return ip;
        yield return r.Host;
        yield return r.HostHeader;
        foreach (var n in r.DiscoveredNames) yield return n;
        foreach (var n in r.SameContentNames) yield return n;
        foreach (var n in r.SameOutcomeNames) yield return n;
    }

    /// <summary>La voce che copre il servizio: prima le corrispondenze esatte (IP singolo o nome), poi le reti.</summary>
    public static InventoryEntry? Find(IReadOnlyList<InventoryEntry> inventory, ScanResult r)
    {
        var cands = Candidates(r).Where(c => !string.IsNullOrWhiteSpace(c)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        foreach (var e in inventory)
            if (!e.IsNetwork && cands.Any(e.Matches)) return e;
        foreach (var e in inventory)
            if (e.IsNetwork && cands.Any(e.Matches)) return e;
        return null;
    }

    private static string Status(InventoryEntry e, ScanResult r)
    {
        if (!r.HttpReachable) return StatusNotObserved;
        bool declared = e.PhpVersion.Trim().Length > 0;
        if (!declared) return StatusOk;
        if (!r.PhpDetected) return StatusDeclaredPhpNotObserved;
        if (r.PhpVersionRaw.Length == 0) return StatusVersionNotObserved;
        return SameVersion(e.PhpVersion, r.PhpVersionRaw) ? StatusOk : StatusVersionDiffers;
    }

    /// <summary>Uguaglianza di major.minor.patch ignorando il suffisso di pacchetto; una dichiarazione senza patch ("8.3") confronta solo il ramo.</summary>
    public static bool SameVersion(string declared, string observed)
    {
        var d = PhpVersion.Parse(declared); var o = PhpVersion.Parse(observed);
        if (d == null || o == null) return declared.Trim().Equals(observed.Trim(), StringComparison.OrdinalIgnoreCase);
        if (d.Major != o.Major || d.Minor != o.Minor) return false;
        if (d.Patch < 0 || o.Patch < 0) return true;
        return d.Patch == o.Patch;
    }

    private static InventoryServiceRef Ref(ScanResult r, string owner) =>
        new(r.Key, r.DisplayIp, r.Port, HostLists.Names([r]), r.Verdict.ToString(), owner);
}
