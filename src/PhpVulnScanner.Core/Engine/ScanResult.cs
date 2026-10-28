using System.Text.Json.Serialization;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Targets;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Core.Engine;

/// <summary>Verdetto PHP2Shell di un bersaglio/porta. I nomi sono chiavi stabili nei file; a video passano da <see cref="Labels"/>.</summary>
public enum Verdict
{
    /// <summary>Bersaglio non attivo o nessuna risposta HTTP.</summary>
    NotReachable,
    /// <summary>Risponde HTTP ma nessun indizio di PHP.</summary>
    NoPhpDetected,
    /// <summary>PHP rilevato ma versione non dichiarata: nessun test esterno può dimostrare lo stato.</summary>
    Undetermined,
    /// <summary>Versione dichiarata uguale o successiva alla correzione del suo ramo.</summary>
    FixedByVersion,
    /// <summary>Versione dichiarata di un ramo supportato precedente alla correzione.</summary>
    VulnerableByVersion,
    /// <summary>Versione dichiarata di un ramo fuori supporto: vulnerabile per versione, backport non escludibile.</summary>
    LikelyVulnerable,
    /// <summary>Le richieste multipart non raggiungono PHP (barriera al perimetro completa): tampone, non correzione.</summary>
    MitigatedAtEdge,
}

public enum TestOutcome { Info, Pass, Warn, Fail, Skipped, Error }

/// <summary>Priorità di remediation (chiave stabile nei file).</summary>
public enum Priority { None, Low, Medium, High, Critical }

/// <summary>Esito di un singolo test, con l'evidenza che lo sostiene (P-024: nessun verdetto senza evidenza).</summary>
public sealed class TestEvidence
{
    public string Id { get; init; } = "";          // es. L1-BANNER, L2-MULTIPART, L3-OOM, WAF-SIG
    public string Name { get; init; } = "";        // testo già nella lingua dell'interfaccia
    public TestOutcome Outcome { get; init; }
    public string Detail { get; init; } = "";
    public string Request { get; init; } = "";     // "GET /index.php"
    public string Response { get; init; } = "";    // "200 OK, 12.3 ms"
}

public enum MultipartBarrier { NotTested, Accepted, Blocked, PartiallyBlocked, PostNotAllowed, NoResponse }

/// <summary>Risultato completo per un bersaglio e una porta.</summary>
public sealed class ScanResult
{
    public string Input { get; init; } = "";
    public string Host { get; init; } = "";
    public bool IsIpLiteral { get; init; }
    public int Port { get; init; }
    public string Scheme { get; set; } = "";
    public string HostHeader { get; set; } = "";
    public List<string> ResolvedIps { get; set; } = [];
    public DateTime StartedLocal { get; set; }
    public double DurationMs { get; set; }
    /// <summary>Tempo per fase (alive, dns, tls, http), per attribuire ogni millisecondo.</summary>
    public Dictionary<string, double> PhaseMs { get; set; } = [];
    [JsonIgnore] public string PhaseSummary => string.Join(", ", PhaseMs.Select(kv => $"{kv.Key} {kv.Value:F0}"));

    public AliveState Alive { get; set; } = AliveState.NotTested;
    public string AliveMethod { get; set; } = "";
    public string AliveDetails { get; set; } = "";
    /// <summary>Tutti i metodi dell'alive check nell'ordine configurato, con esito e durata.</summary>
    public string AliveMethods { get; set; } = "";

    public TlsInfo? Tls { get; set; }

    public bool HttpReachable { get; set; }
    public string ServerHeader { get; set; } = "";
    public string PoweredBy { get; set; } = "";

    public bool PhpDetected { get; set; }
    public string PhpEvidence { get; set; } = "";
    public string PhpVersionRaw { get; set; } = "";
    public string PhpVersionSource { get; set; } = "";
    public VersionStatus VersionStatus { get; set; } = VersionStatus.Unknown;
    public string FixedRelease { get; set; } = "";
    public bool PackageSuffix { get; set; }
    public string SessionCookie { get; set; } = "";

    /// <summary>SAPI dedotta dai banner: "mod_php", "fpm", "" (non determinabile). L'avviso PHP indica mod_php come caso a rischio massimo.</summary>
    public string Sapi { get; set; } = "";
    public string SapiEvidence { get; set; } = "";
    /// <summary>Sistema operativo o distribuzione dichiarati nel banner (Debian, Ubuntu, Win64…): orientano la verifica dei backport.</summary>
    public string OsHint { get; set; } = "";
    /// <summary>Applicazione riconosciuta passivamente (WordPress, phpMyAdmin, Nextcloud…), con rimando all'inventario NCSC-NL.</summary>
    public string Application { get; set; } = "";
    public string ApplicationEvidence { get; set; } = "";
    public string ApplicationReference { get; set; } = "";
    /// <summary>Priorità di remediation derivata da verdetto, SAPI e barriera: ordinamento, non un verdetto nuovo.</summary>
    public Priority Priority { get; set; } = Priority.None;

    public MultipartBarrier Multipart { get; set; } = MultipartBarrier.NotTested;
    public string MultipartDetail { get; set; } = "";
    public int VariantsBlocked { get; set; } = -1;    // -1 = non provato
    public int VariantsTotal { get; set; }
    public bool? UploadProgressFieldBlocked { get; set; }
    public string SizeLimit { get; set; } = "";

    public List<WafFinding> Waf { get; set; } = [];
    public string WafSummary { get; set; } = "";

    public Verdict Verdict { get; set; } = Verdict.NotReachable;
    public string VerdictReason { get; set; } = "";

    public List<TestEvidence> Tests { get; set; } = [];
    public List<HttpSnapshot> Requests { get; set; } = [];
    public string Error { get; set; } = "";

    // ---- v1.3 ----
    /// <summary>Vero quando la riga è la seconda passata su un nome scoperto (Host header e SNI = <see cref="HostHeader"/>, TCP verso <see cref="Host"/>).</summary>
    public bool NameRescan { get; set; }
    /// <summary>Nomi raccolti da certificato (CN/SAN), Location e link, validati come nomi DNS.</summary>
    public List<string> DiscoveredNames { get; set; } = [];
    /// <summary>Superficie PHP scoperta: percorsi che esistono (stato HTTP), es. "/wp-login.php (200)".</summary>
    public List<string> PhpSurface { get; set; } = [];
    /// <summary>Esito della sonda del file .php inesistente quando rivela PHP: Fpm, Cgi, ModPhp (chiave stabile).</summary>
    public string PhpSurfaceProbe { get; set; } = "";
    /// <summary>Ciclo in cui questo risultato è stato osservato (1 = primo).</summary>
    public int Cycle { get; set; } = 1;
    /// <summary>Con il consolidamento: esito di ogni ciclo, es. "ciclo 1: Non raggiungibile", così la variazione resta visibile.</summary>
    public List<string> History { get; set; } = [];

    // ---- v1.3 database applicazioni ----
    /// <summary>Versione dell'applicazione riconosciuta, quando una firma la estrae (es. meta generator "WordPress 6.5").</summary>
    public string ApplicationVersion { get; set; } = "";
    /// <summary>Tecnologie riconosciute dal database firme, "Nome versione", le più sicure e quelle che implicano PHP per prime (max 12).</summary>
    public List<string> Technologies { get; set; } = [];
    /// <summary>Sintesi dello stato PHP2Shell dell'applicazione nell'inventario NCSC-NL (una riga, già tradotta), "" se assente.</summary>
    public string NcscStatus { get; set; } = "";
    /// <summary>Pagina dell'inventario NCSC-NL che riguarda l'applicazione.</summary>
    public string NcscReference { get; set; } = "";

    // ---- v1.4 ----
    /// <summary>Nome DNS della riga: nome scoperto (seconda passata) o nome inserito (bersaglio FQDN); vuoto per le righe per IP. Colonna "Nome".</summary>
    [JsonIgnore] public string DisplayName => NameRescan ? HostHeader : IsIpLiteral ? "" : Host;
    /// <summary>Indirizzo a cui ci si è connessi: l'host stesso se IP, altrimenti il primo indirizzo risolto. Colonna "Bersaglio".</summary>
    [JsonIgnore] public string DisplayIp => IsIpLiteral ? Host : ResolvedIps.Count > 0 ? ResolvedIps[0] : Host;
    /// <summary>Nomi scoperti che hanno restituito lo stesso contenuto del vhost predefinito (nessuna riga aggiuntiva per loro).</summary>
    public List<string> SameContentNames { get; set; } = [];
    /// <summary>Esito del confronto HEAD contro GET sul percorso principale: "" non eseguito, "uguali", oppure la descrizione delle differenze.</summary>
    public string HeadVsGet { get; set; } = "";
    /// <summary>Metodi dichiarati dall'intestazione Allow (OPTIONS), es. "GET, HEAD, POST, OPTIONS, TRACE".</summary>
    public string AllowedMethods { get; set; } = "";
    /// <summary>Versione minima di PHP dichiarata dall'applicazione (vincolo "php" di composer.json), es. ">=8.1".</summary>
    public string PhpVersionFloor { get; set; } = "";
    public string PhpVersionFloorSource { get; set; } = "";
    /// <summary>Librerie PHP con versione (vendor/composer/installed.json), "nome versione", max 50.</summary>
    public List<string> Libraries { get; set; } = [];
    /// <summary>Componenti dell'applicazione (plugin, temi, moduli) ricavati dalle pagine scaricate, "tipo:nome versione".</summary>
    public List<string> Components { get; set; } = [];
    /// <summary>Esposizioni accessorie trovate (phpinfo, directory listing, .env, .git, sorgenti .phps/.bak, server-status, TRACE…): "percorso (stato): descrizione".</summary>
    public List<string> Exposures { get; set; } = [];
    /// <summary>Sonda FastCGI sulla 9000: null non eseguita, true php-fpm esposto, false nessuna risposta FastCGI.</summary>
    public bool? FastCgiExposed { get; set; }
    public string FastCgiDetail { get; set; } = "";
    /// <summary>Esito del secondo giro con User-Agent da browser: "" non eseguito, "uguale", oppure le differenze.</summary>
    public string BrowserUaResult { get; set; } = "";

    // ---- v1.5 ----
    /// <summary>Presenza di PHP a tre valori: "yes" (prova), "maybe" (solo indizi, vedi PhpHints), "no" (niente). Calcolata da PhpHints.Compute; PhpDetected resta la prova binaria.</summary>
    public string PhpPresence { get; set; } = "no";
    /// <summary>Indizi di PHP senza prova, "peso: descrizione" (forte 3, medio 2, debole 1); la somma è PhpHintScore. Compilati anche quando PhpDetected è vero.</summary>
    public List<string> PhpHints { get; set; } = [];
    public int PhpHintScore { get; set; }
    /// <summary>Impostazioni lette da una pagina phpinfo esposta (session.upload_progress.enabled, session.serialize_handler, session.save_handler, expose_php, memory_limit, post_max_size…): "nome=valore".</summary>
    public List<string> IniHints { get; set; } = [];
    /// <summary>Indice di loquacità 0-5: quanto l'host racconta di sé gratis (versioni nei banner, phpinfo, directory listing, server-status, pagine di debug, composer, nomi interni nel certificato).</summary>
    public int VerbosityScore { get; set; }
    /// <summary>Voci che compongono VerbosityScore, "peso: descrizione".</summary>
    public List<string> VerbosityItems { get; set; } = [];
    /// <summary>Nomi scoperti che hanno dato lo stesso esito (verdetto, versione, SAPI, applicazione, barriera, WAF, priorità) di questa riga: nessuna riga aggiuntiva per loro, l'osservazione resta nel results.jsonl.</summary>
    public List<string> SameOutcomeNames { get; set; } = [];

    // ---- v1.6 ----
    /// <summary>Stato del certificato TLS: "" non valutato, altrimenti problemi separati da "; " (scaduto il …, autofirmato, catena non attendibile, nome non corrispondente, chiave debole…) oppure "valido".</summary>
    public string CertificateStatus { get; set; } = "";
    /// <summary>Cache o intermediario davanti all'origine, dalle intestazioni (Via, Age, X-Cache, CF-Cache-Status, X-Varnish, X-Served-By): "" nessuno, altrimenti la descrizione.</summary>
    public string CacheHint { get; set; } = "";
    /// <summary>Versioni di PHP dichiarate nel corpo delle pagine (fuori da phpinfo), non verificate: non entrano nel verdetto.</summary>
    public List<string> BodyDeclaredVersions { get; set; } = [];
    /// <summary>Adozione dell'ID di sessione (test facoltativo): null non eseguito, true il server ha adottato l'ID proposto (use_strict_mode spento), false ne ha emesso uno suo.</summary>
    public bool? SessionIdAdopted { get; set; }
    public string SessionIdDetail { get; set; } = "";
    /// <summary>Riconciliazione con l'inventario: "" non in inventario, altrimenti "ok" / "versione diversa" / "dichiarato non osservato"; dettagli nei campi seguenti.</summary>
    public string InventoryStatus { get; set; } = "";
    public string InventoryDeclaredVersion { get; set; } = "";
    public string InventoryOwner { get; set; } = "";
    public string InventoryEnvironment { get; set; } = "";
    public string InventoryNote { get; set; } = "";
    /// <summary>Sonde facoltative saltate per budget di tempo del servizio (ScanConfig.ServiceBudgetMs): elenco dei nomi, vuoto se nessuna.</summary>
    public List<string> SkippedForBudget { get; set; } = [];
    /// <summary>v1.10: nomi arrivati da Certificate Transparency (sottoinsieme di <see cref="DiscoveredNames"/> prima della verifica DNS).</summary>
    public List<string> CtNames { get; set; } = [];
    /// <summary>v1.10: nomi da CT che non risolvono su questo IP ("nome → ip" quando risolvono su un altro IP del perimetro, "nome → –" se fuori o non risolti): tracciati, non riscansionati.</summary>
    public List<string> CtNamesElsewhere { get; set; } = [];
    /// <summary>Versione dell'applicazione confrontata con l'inventario NCSC-NL ("6.4.2 < corretto in 6.4.3"), "" se non confrontabile.</summary>
    public string AppVersionCheck { get; set; } = "";
    /// <summary>Stato VEX NCSC-NL delle altre tecnologie riconosciute, "Nome: stato".</summary>
    public List<string> TechnologyStatuses { get; set; } = [];

    [JsonIgnore] public string Display => NameRescan ? $"{HostHeader} @ {Host}" : IsIpLiteral || Host == Input ? Host : $"{Host} ({Input})";

    /// <summary>Chiave di ordinamento: indirizzi IPv4 per valore numerico, poi IPv6, poi i nomi in ordine alfabetico; le righe dei nomi scoperti seguono il loro IP.</summary>
    [JsonIgnore] public string SortKey => Targets.TargetParser.SortKey(Host) + (NameRescan ? "~" + HostHeader.ToLowerInvariant() : "");

    /// <summary>Chiave di consolidamento tra cicli: host, porta, nome usato come Host.</summary>
    [JsonIgnore] public string Key => $"{Host}|{Port}|{(NameRescan ? HostHeader : "")}".ToLowerInvariant();

    public TestEvidence Add(string id, string name, TestOutcome outcome, string detail, HttpSnapshot? snap = null)
    {
        var ev = new TestEvidence
        {
            Id = id, Name = name, Outcome = outcome, Detail = detail,
            Request = snap == null ? "" : $"{snap.Method} {RequestPath(snap.Url)}",
            Response = snap == null ? "" : snap.HasResponse ? $"{snap.Status} {snap.Reason}, {snap.ElapsedMs:F0} ms, {snap.BodyLength} B" : (snap.Error ?? ""),
        };
        Tests.Add(ev);
        if (snap != null) Requests.Add(snap);
        return ev;
    }

    private static string RequestPath(string url)
    {
        int i = url.IndexOf("://", StringComparison.Ordinal);
        if (i < 0) return url;
        int s = url.IndexOf('/', i + 3);
        return s < 0 ? "/" : url[s..];
    }
}
