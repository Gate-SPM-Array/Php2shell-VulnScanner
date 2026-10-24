using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Engine;

/// <summary>Tutto ciò che i test di un bersaglio condividono: client HTTP, punto di contatto, risultato in costruzione, log.</summary>
public sealed class ScanContext
{
    public required ScanConfig Config { get; init; }
    public required HttpProbe Http { get; init; }
    public required HttpEndpoint Endpoint { get; init; }
    public required ScanResult Result { get; init; }
    public required List<string> Paths { get; init; }
    public required Action<string> Log { get; init; }
    public required CancellationToken Ct { get; init; }
    /// <summary>Ritmo delle richieste (pause casuali, tetto globale); null = nessun ritmo imposto.</summary>
    public Pacer? Pacer { get; init; }
    /// <summary>Pausa (v1.4): ogni richiesta attende la ripresa prima di partire.</summary>
    public PauseToken? Pause { get; init; }

    /// <summary>
    /// Budget di tempo del servizio (v1.6): cronometro avviato quando la scansione del servizio comincia (dopo il pre-controllo della porta).
    /// Il motore ne passa uno solo per servizio, così i contesti successivi (cambio di schema) misurano lo stesso tempo.
    /// </summary>
    public System.Diagnostics.Stopwatch Budget { get; init; } = System.Diagnostics.Stopwatch.StartNew();

    /// <summary>Vero quando il budget per servizio (ScanConfig.ServiceBudgetMs, 0 = nessuno) è esaurito: le fasi facoltative saltano ciò che resta. Livello 1, livello 2 e WAF non guardano mai questo valore.</summary>
    public bool OverBudget => Config.ServiceBudgetMs > 0 && Budget.ElapsedMilliseconds > Config.ServiceBudgetMs;

    /// <summary>
    /// Header Host: il nome quando il bersaglio è un FQDN o una seconda passata su un nome scoperto, altrimenti quello
    /// configurato o nessuno (= IP). Quando l'endpoint porta già il nome nella URL (ConnectHost valorizzato) non serve forzarlo.
    /// </summary>
    public string? HostHeader => Endpoint.ConnectHost != null ? null
        : Result.IsIpLiteral ? (string.IsNullOrWhiteSpace(Config.HostHeader) ? null : Config.HostHeader.Trim()) : Result.Host;

    /// <summary>Percorso principale su cui fare i confronti (il primo che ha risposto con uno stato HTTP, altrimenti il primo).</summary>
    public string PrimaryPath { get; set; } = "/";

    /// <summary>Risposta GET di riferimento sul percorso principale.</summary>
    public HttpSnapshot? Baseline { get; set; }

    /// <summary>Percorsi .php scoperti che rispondono 200/401: candidati per il livello 2 quando i percorsi configurati non ne offrono uno.</summary>
    public List<string> SurfacePhpPaths { get; set; } = [];

    public async Task<HttpSnapshot> GetAsync(string path, IEnumerable<KeyValuePair<string, string>>? headers = null)
    {
        if (Pause != null) await Pause.WaitAsync(Ct).ConfigureAwait(false);
        if (Pacer != null) await Pacer.WaitAsync(Ct).ConfigureAwait(false);
        return await Http.GetAsync(Endpoint, path, Ct, HostHeader, headers).ConfigureAwait(false);
    }

    public async Task<HttpSnapshot> HeadAsync(string path)
    {
        if (Pause != null) await Pause.WaitAsync(Ct).ConfigureAwait(false);
        if (Pacer != null) await Pacer.WaitAsync(Ct).ConfigureAwait(false);
        return await Http.SendAsync(Endpoint, HttpMethod.Head, path, null, Ct, HostHeader).ConfigureAwait(false);
    }

    /// <summary>Richiesta con metodo arbitrario (OPTIONS, HEAD con intestazioni aggiuntive…), sempre senza corpo.</summary>
    public async Task<HttpSnapshot> SendAsync(HttpMethod method, string path, IEnumerable<KeyValuePair<string, string>>? headers = null)
    {
        if (Pause != null) await Pause.WaitAsync(Ct).ConfigureAwait(false);
        if (Pacer != null) await Pacer.WaitAsync(Ct).ConfigureAwait(false);
        return await Http.SendAsync(Endpoint, method, path, null, Ct, HostHeader, headers).ConfigureAwait(false);
    }

    public async Task<HttpSnapshot> PostAsync(string path, HttpContent content, int? readTimeoutMs = null)
    {
        if (Pause != null) await Pause.WaitAsync(Ct).ConfigureAwait(false);
        if (Pacer != null) await Pacer.WaitAsync(Ct).ConfigureAwait(false);
        return await Http.PostAsync(Endpoint, path, content, Ct, HostHeader, null, readTimeoutMs).ConfigureAwait(false);
    }
}
