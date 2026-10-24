using System.Text.Json;
using System.Text.Json.Serialization;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;

namespace PhpVulnScanner.Core.Engine;

/// <summary>Configurazione completa di una scansione, salvata in session.json e nelle impostazioni del programma.</summary>
public sealed class ScanConfig
{
    public string TargetsText { get; set; } = "";
    public string PortsText { get; set; } = "443";
    public string PathsText { get; set; } = "/\n/index.php";
    /// <summary>Header Host da inviare quando il bersaglio è un IP (vuoto = l'IP stesso). Utile per vhost dietro un IP.</summary>
    public string HostHeader { get; set; } = "";
    /// <summary>Resolver DNS esplicito per i nomi (es. 1.1.1.1); vuoto = resolver di sistema. Regola: le verifiche DNS non devono dipendere dal DNS interno.</summary>
    public string ResolverIp { get; set; } = "";

    public int ConnectTimeoutMs { get; set; } = 3000;
    public int ReadTimeoutMs { get; set; } = 8000;
    public int Threads { get; set; } = 8;

    public AliveConfig Alive { get; set; } = new();

    /// <summary>Livello 1: lettura delle pagine rivelatrici (phpinfo.php, info.php). Solo GET.</summary>
    public bool Level1InfoPages { get; set; } = true;
    /// <summary>Livello 1: easter egg di PHP (?=PHPE9568F34-…): rivela PHP &lt; 5.5 con expose_php attivo. Solo GET.</summary>
    public bool Level1EasterEgg { get; set; } = false;
    /// <summary>Modalità leggera: HEAD al posto di GET sui percorsi (GET solo se HEAD risponde 405/501). Meno traffico, ma si perdono i segnali nel corpo (errori PHP, phpinfo, applicazione).</summary>
    public bool LightMode { get; set; } = false;

    /// <summary>Livello 2: precondizioni e barriere (multipart minimo, varianti di Content-Type, campo upload progress, limite di dimensione).</summary>
    public bool Level2 { get; set; } = true;
    public int SizeProbeKiB { get; set; } = 256;

    public bool WafDetect { get; set; } = true;
    public bool WafBehaviour { get; set; } = true;

    public string OutputFolder { get; set; } = "";
    public CsvDialect CsvDialect { get; set; } = CsvDialect.ExcelItalian;
    public string SessionLabel { get; set; } = "";

    // ---- v1.3 ----
    /// <summary>Scoperta della superficie PHP: sonda del file .php inesistente (firma di FPM/CGI/mod_php) e punti di ingresso comuni (solo HEAD/GET).</summary>
    public bool SurfaceDiscovery { get; set; } = true;
    /// <summary>Raccolta dei nomi (CN/SAN del certificato, Location, link) e tabella "Nomi scoperti".</summary>
    public bool DiscoverNames { get; set; } = true;
    /// <summary>Seconda passata sugli stessi IP con header Host e SNI = nome scoperto (una riga in più per nome).</summary>
    public bool RescanDiscoveredNames { get; set; } = true;
    public int MaxNamesPerHost { get; set; } = 10;

    /// <summary>Numero di cicli (passate complete sull'elenco). 1 = scansione singola.</summary>
    public int Cycles { get; set; } = 1;
    /// <summary>Pausa tra un ciclo e il successivo, in secondi.</summary>
    public int CyclePauseSec { get; set; } = 60;
    /// <summary>Vero: un'unica sessione con i risultati consolidati (vince il più informativo); falso: una sessione per ciclo.</summary>
    public bool Consolidate { get; set; } = true;

    /// <summary>Ordine casuale degli host (e delle porte) a ogni ciclo.</summary>
    public bool RandomOrder { get; set; } = false;
    /// <summary>Pausa casuale prima di ogni richiesta HTTP verso lo stesso host, in millisecondi (0-0 = nessuna).</summary>
    public int DelayMinMs { get; set; } = 0;
    public int DelayMaxMs { get; set; } = 0;
    /// <summary>Tetto globale di richieste HTTP al secondo (0 = nessun limite).</summary>
    public int MaxRequestsPerSecond { get; set; } = 0;

    /// <summary>Modalità debug: corpi completi (fino a 1 MiB), intestazioni inviate, campioni anonimizzati per l'analisi.</summary>
    public bool DebugMode { get; set; } = false;
    /// <summary>Report: schede di dettaglio anche per i bersagli non raggiungibili (altrimenti solo nella tabella).</summary>
    public bool ReportUnreachableDetails { get; set; } = false;

    // ---- v1.4 ----
    /// <summary>Sezione "Avanzate": test aggiuntivi in sola lettura, una casella ciascuno.</summary>
    public AdvancedOptions Advanced { get; set; } = new();
    /// <summary>Seconda passata sui nomi: non creare la riga quando il nome restituisce lo stesso contenuto del vhost predefinito (il nome va nella colonna Nome della riga per IP).</summary>
    public bool FoldSameContentNames { get; set; } = true;
    /// <summary>v1.5: non creare la riga per nome quando l'esito (verdetto, versione, SAPI, applicazione, barriera, WAF, priorità) è uguale a quello della riga per IP o di un'altra riga per nome dello stesso IP+porta; il nome va in SameOutcomeNames.</summary>
    public bool FoldSameOutcomeNames { get; set; } = true;
    /// <summary>v1.6: budget di tempo per servizio (ms): oltre, le sonde facoltative restanti (superficie, test aggiuntivi) vengono saltate e segnate in SkippedForBudget. 0 = nessun budget.</summary>
    public int ServiceBudgetMs { get; set; } = 120000;
    /// <summary>v1.6: file di inventario (CSV o JSON) da riconciliare con i risultati; vuoto = nessuno.</summary>
    public string InventoryPath { get; set; } = "";
    /// <summary>Pre-controllo TCP di tutte le porte in parallelo sugli host attivi: handshake TLS e HTTP solo dove la porta risponde (porte chiuse o filtrate costano una volta sola).</summary>
    public bool PortPrecheck { get; set; } = true;
    /// <summary>Rami fuori supporto con numero "puro" (senza suffisso di distribuzione): "Vulnerabile per versione" invece di "Probabilmente vulnerabile" (nessun distributore può aver fatto backport).</summary>
    public bool PureVersionIsVulnerable { get; set; } = true;

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    public ScanConfig Clone() => JsonSerializer.Deserialize<ScanConfig>(JsonSerializer.Serialize(this, JsonOptions), JsonOptions)!;

    /// <summary>Riporta i valori numerici entro limiti sensati.</summary>
    public void Clamp()
    {
        ConnectTimeoutMs = Math.Clamp(ConnectTimeoutMs, 200, 60000);
        ReadTimeoutMs = Math.Clamp(ReadTimeoutMs, 500, 300000);
        Threads = Math.Clamp(Threads, 1, 64);
        Alive.TimeoutMs = Math.Clamp(Alive.TimeoutMs, 100, 30000);
        SizeProbeKiB = Math.Clamp(SizeProbeKiB, 1, 4096);
        MaxNamesPerHost = Math.Clamp(MaxNamesPerHost, 1, 50);
        Cycles = Math.Clamp(Cycles, 1, 1000);
        CyclePauseSec = Math.Clamp(CyclePauseSec, 0, 86400);
        DelayMinMs = Math.Clamp(DelayMinMs, 0, 60000);
        DelayMaxMs = Math.Clamp(DelayMaxMs, DelayMinMs, 60000);
        MaxRequestsPerSecond = Math.Clamp(MaxRequestsPerSecond, 0, 10000);
    }
}
