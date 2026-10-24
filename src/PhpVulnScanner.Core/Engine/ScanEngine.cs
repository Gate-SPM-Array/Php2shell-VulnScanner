using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Targets;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Core.Engine;

/// <summary>Stato finale di una scansione, salvato in session.json (chiave stabile, a video tradotta).</summary>
public enum ScanStatus { Running, Completed, Stopped, Error }

/// <summary>Una scansione completa: configurazione, bersagli espansi, risultati, tempi.</summary>
public sealed class ScanSession
{
    public string AppVersion { get; set; } = HttpProbe.AppVersion;
    public string Machine { get; set; } = Environment.MachineName;
    public string OsDescription { get; set; } = System.Runtime.InteropServices.RuntimeInformation.OSDescription;
    public DateTime StartLocal { get; set; }
    public DateTime? EndLocal { get; set; }
    public ScanStatus Status { get; set; } = ScanStatus.Running;
    public string Folder { get; set; } = "";
    public int TargetCount { get; set; }
    public int PortCount { get; set; }
    public List<string> Ports { get; set; } = [];
    public List<string> Paths { get; set; } = [];
    public List<string> ParseErrors { get; set; } = [];
    /// <summary>Bersagli come inseriti (CIDR, intervalli, nomi), per il report: "203.0.113.0/22, www.example.org".</summary>
    public string TargetsSummary { get; set; } = "";
    /// <summary>Ciclo a cui si riferisce questa sessione (sessioni distinte) o ultimo ciclo eseguito (consolidata).</summary>
    public int Cycle { get; set; } = 1;
    public int Cycles { get; set; } = 1;
    public bool Consolidated { get; set; }
    public int HostsTotal { get; set; }
    /// <summary>Host distinti confermati attivi dall'alive check (o, con alive check spento, con almeno una risposta TCP/TLS/HTTP).</summary>
    public int HostsAlive { get; set; }
    public int HostsHttp { get; set; }
    /// <summary>Versione dei dati del database applicazioni (webappanalyzer, NCSC-NL) usati dalla scansione; vuota se il database non era caricato.</summary>
    public string DataVersion { get; set; } = "";
    public ScanConfig Config { get; set; } = new();
    public List<ScanResult> Results { get; set; } = [];
}

/// <summary>
/// Motore della scansione. L'unità di lavoro è l'HOST: risoluzione e alive check una volta sola, poi le porte in sequenza
/// (così il parallelismo, limitato da un semaforo, è tra host diversi e un host muto non blocca più di un thread).
/// Per ogni porta: handshake TLS, livello 1, scoperta della superficie, livello 2, rilevazione WAF, verdetto; poi, se
/// richiesto, la seconda passata sui nomi scoperti. Cicli ripetuti con pausa, ordine casuale, ritmo delle richieste,
/// stima di fine ciclo e di fine loop. Interrompibile in qualsiasi momento: i risultati già completati restano.
/// </summary>
public sealed class ScanEngine
{
    public event Action<string>? Log;
    /// <summary>Risultato pronto (con il consolidamento: il vincente per quella chiave, che sostituisce il precedente).</summary>
    public event Action<ScanResult>? ResultReady;
    public event Action<ScanProgress>? Progress;
    /// <summary>Inizio di un ciclo: (ciclo, cicli, sessione che lo raccoglie).</summary>
    public event Action<int, int, ScanSession>? CycleStarted;
    /// <summary>Fine di un ciclo con la sessione che lo contiene (con sessioni distinte: una per ciclo, già chiusa su disco).</summary>
    public event Action<ScanSession>? CycleCompleted;

    /// <summary>Pausa / ripresa (v1.4): il motore si ferma prima del prossimo host e della prossima richiesta; i risultati completati restano.</summary>
    public PauseToken Pause { get; } = new();

    /// <summary>Prepara la sessione senza eseguire nulla: espansione dei bersagli, porte, percorsi, cartella.</summary>
    public static ScanSession Prepare(ScanConfig cfg, out List<ScanTarget> targets, out List<int> ports, out List<string> paths)
    {
        cfg.Clamp();
        var parsed = TargetParser.Parse(cfg.TargetsText);
        targets = parsed.Targets;
        ports = TargetParser.ParsePorts(cfg.PortsText, out var portErrors);
        if (ports.Count == 0) ports = [443];
        paths = TargetParser.ParsePaths(cfg.PathsText);
        if (paths.Count == 0) paths = ["/"];
        var session = new ScanSession
        {
            StartLocal = DateTime.Now,
            Config = cfg.Clone(),
            TargetCount = targets.Count,
            PortCount = ports.Count,
            Ports = ports.Select(p => p.ToString()).ToList(),
            Paths = paths,
            TargetsSummary = SummarizeTargets(targets),
            Cycles = cfg.Cycles,
            Consolidated = cfg.Consolidate && cfg.Cycles > 1,
            HostsTotal = targets.Select(t => t.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            DataVersion = Apps.TechnologyDatabase.Default?.DataVersion ?? "",
        };
        session.ParseErrors.AddRange(parsed.Errors);
        session.ParseErrors.AddRange(portErrors.Select(p => L.F("porta non valida: {0}", p)));
        return session;
    }

    /// <summary>"203.0.113.0/22, 192.0.2.10-20, www.example.org" (prime 6 voci come inserite, poi "e altre N").</summary>
    public static string SummarizeTargets(IReadOnlyList<ScanTarget> targets)
    {
        var inputs = targets.Select(t => t.Input).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (inputs.Count == 0) return "";
        var shown = inputs.Take(6).ToList();
        return string.Join(", ", shown) + (inputs.Count > shown.Count ? " " + L.F("e altre {0}", inputs.Count - shown.Count) : "");
    }

    // ---- stato di una esecuzione ----
    private sealed class Run
    {
        public required ScanConfig Cfg;
        public required List<ScanTarget> Targets;
        public required List<int> Ports;
        public required List<string> Paths;
        public required HttpProbe Http;
        public required Pacer? Pacer;
        public required IPAddress? ResolverIp;
        public required CancellationToken Ct;
        public required Action<string> Log;
        public required Action<ScanResult> Emit;
        /// <summary>Osservazione ripiegata su un'altra riga (nome con lo stesso contenuto o lo stesso esito): solo in results.jsonl, nessuna riga in tabella.</summary>
        public required Action<ScanResult> Observe;
        /// <summary>Anteprima (v1.7): riga per IP già completa, mostrata in tabella prima della seconda passata sui nomi; la stessa chiave viene poi riemessa con <see cref="Emit"/>.</summary>
        public required Action<ScanResult> Preview;
        public required PauseToken Pause;
        /// <summary>Riemissione (v1.8): stessa chiave già emessa (seconda chance dell'alive check): sostituisce la riga senza contare un completamento in più.</summary>
        public required Action<ScanResult> Replace;
        /// <summary>Coda dei lavori sui nomi scoperti (v1.8): i lavoratori la servono prima degli host nuovi, così la seconda passata non resta in coda dietro migliaia di host.</summary>
        public readonly ConcurrentQueue<Func<Task>> NameJobs = new();
        /// <summary>Lavori in corso o in coda (host, nomi, chiusure): a zero la passata è finita.</summary>
        public int Outstanding;
        /// <summary>Tetto dell'alive check (v1.8), indipendente dai thread HTTP.</summary>
        public SemaphoreSlim? AliveSem;
        /// <summary>Corsie della seconda chance (v1.9): metà dei thread, minimo 4.</summary>
        public SemaphoreSlim? RetrySem;
        /// <summary>Coda della seconda chance (v1.9): riempita appena la coda degli host si svuota, servita dai lavoratori liberi mentre finiscono i nomi.</summary>
        public readonly ConcurrentQueue<ScanTarget> RetryQueue = new();
        public int RetryStarted, RetryCount, RetryAliveBefore;
        /// <summary>Host saltati perché non confermati attivi (v1.8): candidati alla seconda chance a fine ciclo.</summary>
        public readonly ConcurrentBag<(ScanTarget Target, List<int> Ports)> NotAlive = [];
        public int Total, Done, HostsDone;
        public readonly ConcurrentDictionary<string, byte> AliveHosts = new(StringComparer.OrdinalIgnoreCase);
        public readonly ConcurrentDictionary<string, byte> HttpHosts = new(StringComparer.OrdinalIgnoreCase);
        public Stopwatch Clock = Stopwatch.StartNew();
    }

    private sealed record HostInfo(List<string> Ips, double DnsMs, AliveResult? Alive, double AliveMs, string? Error);

    public async Task<ScanSession> RunAsync(ScanConfig cfg, CancellationToken ct)
    {
        var session = Prepare(cfg, out var targets, out var ports, out var paths);
        foreach (var e in session.ParseErrors) Log?.Invoke(L.F("Avviso: {0}", e));
        if (targets.Count == 0) throw new ArgumentException(L.T("Nessun bersaglio valido nell'elenco."));

        int cycles = cfg.Cycles;
        bool consolidate = cfg.Consolidate && cycles > 1;
        VerdictEngine.PureVersionIsVulnerable = cfg.PureVersionIsVulnerable;
        // unione di tutte le osservazioni del loop per i file degli host (host_attivi, host_http, nomi_scoperti): vince il più informativo
        var cumulative = new ConcurrentDictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
        string? firstFolder = null;
        var consolidated = new ConcurrentDictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
        var estimator = new ScanEstimator { Cycles = cycles, CyclePauseSec = cfg.CyclePauseSec };
        IPAddress? resolverIp = IPAddress.TryParse(cfg.ResolverIp, out var rip) ? rip : null;
        using var http = new HttpProbe(cfg.ConnectTimeoutMs, cfg.ReadTimeoutMs, null, cfg.DebugMode);
        var pacer = cfg.DelayMaxMs > 0 || cfg.MaxRequestsPerSecond > 0 ? new Pacer(cfg.DelayMinMs, cfg.DelayMaxMs, cfg.MaxRequestsPerSecond) : null;
        var loopClock = Stopwatch.StartNew();
        double pausedBefore = 0;

        SessionWriter? writer = null;
        ScanSession current = session;
        if (consolidate || cycles == 1)
        {
            session.Folder = SessionFiles.CreateSessionFolder(cfg, session.StartLocal);
            writer = new SessionWriter(session, consolidate);
        }
        void LogLine(string msg) { Log?.Invoke(msg); writer?.Log(msg); }

        try
        {
            for (int cycle = 1; cycle <= cycles; cycle++)
            {
                ct.ThrowIfCancellationRequested();
                if (!consolidate && cycles > 1)
                {
                    // una sessione per ciclo, con il proprio indice nel nome della cartella
                    current = Prepare(cfg, out _, out _, out _);
                    current.Cycle = cycle;
                    current.Folder = SessionFiles.CreateSessionFolder(cfg, current.StartLocal, $"c{cycle}of{cycles}");
                    writer?.Dispose();
                    writer = new SessionWriter(current, false);
                }
                current.Cycle = cycle;
                session.Cycle = cycle;
                estimator.Reset(cycle);
                CycleStarted?.Invoke(cycle, cycles, current);

                string cycleTag = cycles > 1 ? L.F("ciclo {0} di {1}: ", cycle, cycles) : "";
                LogLine(cycleTag + L.F("Scansione avviata: {0} bersagli ({1}), porte {2}, percorsi {3}, {4} thread", targets.Count, session.TargetsSummary, string.Join(",", ports), string.Join(" ", paths), cfg.Threads));
                if (cycle == 1)
                {
                    LogLine(L.F("Alive check: {0}; livello 2: {1}; rilevazione WAF: {2}", cfg.Alive.Enabled ? DescribeAlive(cfg.Alive) : L.T("disattivato"), cfg.Level2 ? L.T("attivo") : L.T("disattivato"), cfg.WafDetect ? L.T("attiva") : L.T("disattivata")));
                    LogLine(L.F("Superficie PHP: {0}; nomi scoperti: {1}; ordine: {2}; ritmo: {3}{4}", cfg.SurfaceDiscovery ? L.T("attiva") : L.T("disattivata"),
                        !cfg.DiscoverNames ? L.T("disattivati") : cfg.RescanDiscoveredNames ? L.F("raccolti e riscansionati (max {0} per host)", cfg.MaxNamesPerHost) : L.T("solo raccolti"),
                        cfg.RandomOrder ? L.T("casuale") : L.T("sequenziale"),
                        pacer == null ? L.T("nessuna pausa") : L.F("pausa {0}-{1} ms per richiesta, tetto {2}/s", cfg.DelayMinMs, cfg.DelayMaxMs, cfg.MaxRequestsPerSecond == 0 ? "∞" : cfg.MaxRequestsPerSecond.ToString()),
                        cfg.DebugMode ? "; " + L.T("modalità debug") : ""));
                    LogLine(Apps.TechnologyDatabase.Default is { } db ? L.F("Database applicazioni: {0} tecnologie, inventario NCSC-NL {1} pacchetti ({2})", db.Count, db.Inventory.Count, db.DataVersion.Replace("\n", " | ")) : L.T("Database applicazioni non caricato (cartella data\\ assente): solo le firme incorporate"));
                    if (cycles > 1) LogLine(L.F("Cicli: {0}, pausa {1} s, {2}", cycles, cfg.CyclePauseSec, consolidate ? L.T("risultati consolidati in una sessione") : L.T("una sessione per ciclo")));
                }

                var run = new Run
                {
                    Cfg = cfg, Targets = targets, Ports = ports, Paths = paths, Http = http, Pacer = pacer, ResolverIp = resolverIp, Ct = ct, Log = LogLine, Pause = Pause,
                    Emit = r =>
                    {
                        r.Cycle = cycle;
                        ScanResult outR = r;
                        if (consolidate)
                        {
                            outR = consolidated.AddOrUpdate(r.Key, _ => ResultMerger.Merge(null, r), (_, cur) => ResultMerger.Merge(cur, r));
                            writer?.Upsert(outR);
                        }
                        else
                        {
                            // sessioni distinte: la riga di storia del proprio ciclo resta comunque, così report e CSV dicono a quale ciclo appartiene l'osservazione
                            if (cycles > 1 && r.History.Count == 0) r.History.Add(ResultMerger.HistoryLine(r));
                            writer?.Upsert(r);
                        }
                        if (!consolidate) cumulative.AddOrUpdate(r.Key, _ => r, (_, cur) => ResultMerger.Score(r) >= ResultMerger.Score(cur) ? r : cur);
                        ResultReady?.Invoke(outR);
                    },
                    Observe = r => { r.Cycle = cycle; writer?.Observe(r); },
                    Preview = r => { r.Cycle = cycle; ResultReady?.Invoke(r); },
                    Replace = null!,
                };
                var passResults = new ConcurrentDictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
                var origEmit = run.Emit;
                run.Emit = r => { passResults[r.Key] = r; origEmit(r); };
                run.Replace = r =>
                {
                    // v1.8: riemissione nello stesso ciclo (seconda chance dell'alive check): il consolidato fonde per chiave sostituendo la riga di storia,
                    // il writer sostituisce per chiave, la tabella aggiorna la riga
                    r.Cycle = cycle;
                    ScanResult outR = r;
                    if (consolidate) { outR = consolidated.AddOrUpdate(r.Key, _ => ResultMerger.Merge(null, r), (_, cur) => ResultMerger.Merge(cur, r, sameCycle: true)); writer?.Upsert(outR); }
                    else { if (cycles > 1) { r.History.Clear(); r.History.Add(ResultMerger.HistoryLine(r)); } writer?.Upsert(r); }
                    if (!consolidate) cumulative.AddOrUpdate(r.Key, _ => r, (_, cur) => ResultMerger.Score(r) >= ResultMerger.Score(cur) ? r : cur);
                    passResults[r.Key] = outR;
                    ResultReady?.Invoke(outR);
                };

                firstFolder ??= current.Folder;
                var passClock = Stopwatch.StartNew();
                var status = await RunPassAsync(run, estimator, cycle, cycles).ConfigureAwait(false);
                double passSec = passClock.Elapsed.TotalSeconds - Pause.TotalPaused.TotalSeconds + pausedBefore;
                pausedBefore = Pause.TotalPaused.TotalSeconds;
                estimator.LastCycleSec = passSec;

                // file degli host (un IP per riga) aggiornati a ogni ciclo: unione di tutto il loop, così sono completi anche dopo un'interruzione
                try
                {
                    var union = consolidate ? consolidated.Values : cumulative.Values;
                    Output.HostLists.Write(current.Folder, session.AppVersion, union);
                    if (!consolidate && firstFolder != null && firstFolder != current.Folder) Output.HostLists.Write(firstFolder, session.AppVersion, union);
                }
                catch (Exception ex) { LogLine(L.F("File degli host non scritti: {0}", ex.Message)); }

                var list = consolidate ? consolidated.Values.ToList() : passResults.Values.ToList();
                current.Results = list.OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
                current.HostsAlive = run.AliveHosts.Count;
                current.HostsHttp = run.HttpHosts.Count;
                current.EndLocal = DateTime.Now;
                current.Status = status;
                if (consolidate) { session.HostsAlive = run.AliveHosts.Count; session.HostsHttp = run.HttpHosts.Count; }

                LogLine(cycleTag + (status == ScanStatus.Completed
                    ? L.F("Scansione completata in {0} ({1:F1} s): {2} risultati, {3} host attivi su {4}, {5} con HTTP", ScanEstimator.Duration(passSec), passSec, passResults.Count, run.AliveHosts.Count, current.HostsTotal, run.HttpHosts.Count)
                    : L.F("Scansione interrotta dall'utente: {0} di {1} completati", run.Done, run.Total)));
                if (!consolidate) { writer?.Finish(current); CycleCompleted?.Invoke(current); }
                else CycleCompleted?.Invoke(current);

                if (status != ScanStatus.Completed) { session.Status = status; break; }
                session.Status = ScanStatus.Completed;

                if (cycle < cycles)
                {
                    var eta = loopClock.Elapsed.TotalSeconds;
                    LogLine(L.F("Pausa di {0} s prima del ciclo {1} di {2} (loop in corso da {3})", cfg.CyclePauseSec, cycle + 1, cycles, ScanEstimator.Duration(eta)));
                    await Task.Delay(TimeSpan.FromSeconds(cfg.CyclePauseSec), ct).ConfigureAwait(false);
                    await Pause.WaitAsync(ct).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException)
        {
            session.Status = ScanStatus.Stopped;
            LogLine(L.T("Loop interrotto dall'utente durante la pausa tra i cicli"));
        }
        catch (Exception ex)
        {
            session.Status = ScanStatus.Error;
            LogLine(L.F("Errore della scansione: {0}", ex.Message));
        }

        if (consolidate || cycles == 1)
        {
            session.EndLocal = DateTime.Now;
            if (consolidate) session.Results = consolidated.Values.OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
            else session.Results = current.Results;
            if (cycles > 1) LogLine(L.F("Loop di {0} cicli terminato in {1}: {2} risultati consolidati, {3} con verdetto cambiato tra i cicli",
                session.Cycle, ScanEstimator.Duration(loopClock.Elapsed.TotalSeconds), session.Results.Count, session.Results.Count(ResultMerger.VerdictChanged)));
            Inventory.InventoryMatcher.Apply(cfg, session, LogLine);   // v1.6: riconciliazione con l'inventario (nessuna azione senza file)
            writer?.Finish(session);
            writer?.Dispose();
            return session;
        }
        writer?.Dispose();
        // sessioni distinte: si restituisce l'ultima, con lo stato del loop
        current.Status = session.Status == ScanStatus.Completed ? current.Status : session.Status;
        return current;
    }

    /// <summary>Una passata completa su tutti gli host (un ciclo). Restituisce lo stato: completata o interrotta.</summary>
    private async Task<ScanStatus> RunPassAsync(Run run, ScanEstimator estimator, int cycle, int cycles)
    {
        var cfg = run.Cfg;
        var hosts = run.Targets.GroupBy(t => t.Host, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
        var ports = run.Ports.ToList();
        if (cfg.RandomOrder)
        {
            var rng = new Random();
            hosts = hosts.OrderBy(_ => rng.Next()).ToList();
        }
        run.Total = hosts.Count * ports.Count;
        run.Done = 0; run.HostsDone = 0;
        run.Clock = Stopwatch.StartNew();
        int hostsTotal = hosts.Count;

        run.AliveSem = cfg.Alive.Enabled ? new SemaphoreSlim(cfg.Alive.Parallel > 0 ? Math.Min(cfg.Alive.Parallel, cfg.Threads) : cfg.Threads) : null;
        using var progressCts = CancellationTokenSource.CreateLinkedTokenSource(run.Ct);
        var progressLoop = ProgressLoopAsync(run, estimator, hostsTotal, progressCts.Token);

        ScanStatus status = ScanStatus.Completed;
        try
        {
            // v1.8: lavoratori con coda a priorità. Prima (v1.7) tutti gli host erano task in attesa sullo stesso semaforo e i lavori sui nomi
            // finivano in coda dietro migliaia di host (16 min di attesa misurati sulla /20); ora ogni lavoratore prende prima un nome, poi un host.
            var hostQueue = new ConcurrentQueue<ScanTarget>(hosts);
            run.Outstanding = hosts.Count;
            bool retryOn = cfg.Alive.Enabled && cfg.Alive.SkipIfNotAlive && cfg.Alive.Retry;
            // v1.9: corsie della seconda chance = metà dei thread (minimo 4, mai più dei thread); timeout 1,5×. Sulla /22 con 4 corsie e timeout 2×
            // costava 11,5 min per ciclo (914 host) per 3-4 host recuperati.
            run.RetrySem = retryOn ? new SemaphoreSlim(Math.Max(1, Math.Min(cfg.Threads, Math.Max(4, cfg.Threads / 2)))) : null;
            await RunWorkersAsync(run, cfg.Threads, hostQueue, ports, estimator).ConfigureAwait(false);
            // v1.8/v1.9: seconda chance per gli host non confermati attivi (ICMP + TCP sulle porte della scansione, timeout 1,5×): un ciclo "tirato"
            // non perde host per sempre; chi risponde viene scansionato per intero e la sua riga sostituisce quella "non raggiungibile".
            // Dalla v1.9 parte appena la coda degli host si svuota (lavoratori liberi mentre finiscono i nomi); qui resta solo la coda finale
            // degli host che erano ancora in corso a quel momento.
            if (retryOn && !run.NotAlive.IsEmpty)
            {
                StartRetry(run, ports);
                run.Outstanding = run.RetryQueue.Count;
                await RunWorkersAsync(run, cfg.Threads, new ConcurrentQueue<ScanTarget>(), ports, estimator).ConfigureAwait(false);
            }
            if (retryOn && run.RetryStarted > 0)
                run.Log(L.F("Seconda chance: {0} host recuperati su {1}", run.AliveHosts.Count - run.RetryAliveBefore, run.RetryCount));
        }
        catch (OperationCanceledException) { status = ScanStatus.Stopped; }
        finally
        {
            progressCts.Cancel();
            try { await progressLoop.ConfigureAwait(false); } catch { }
        }
        Progress?.Invoke(estimator.Snapshot(run.Done, run.Total, run.Clock.Elapsed.TotalSeconds, run.AliveHosts.Count, run.HostsDone, hostsTotal));
        return status;
    }

    /// <summary>Pubblica l'avanzamento ogni 2 s e scrive nel log una riga con la stima ogni 5 minuti (per misurare a posteriori l'errore).</summary>
    private async Task ProgressLoopAsync(Run run, ScanEstimator estimator, int hostsTotal, CancellationToken ct)
    {
        double nextLog = 300;
        bool wasPaused = false;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(2000, ct).ConfigureAwait(false);
                // in pausa l'orologio della passata si ferma: la stima non conta il tempo fermo
                bool paused = run.Pause.IsPaused;
                if (paused && !wasPaused) { run.Clock.Stop(); run.Log(L.T("Scansione in pausa: le richieste in volo finiscono, nessun nuovo host o richiesta fino alla ripresa")); }
                else if (!paused && wasPaused) { run.Clock.Start(); run.Log(L.F("Scansione ripresa dopo {0} di pausa", ScanEstimator.Duration(run.Pause.TotalPaused.TotalSeconds))); }
                wasPaused = paused;
                if (paused) continue;
                double elapsed = run.Clock.Elapsed.TotalSeconds;
                estimator.Add(elapsed, Volatile.Read(ref run.Done));
                var p = estimator.Snapshot(run.Done, run.Total, elapsed, run.AliveHosts.Count, run.HostsDone, hostsTotal);
                Progress?.Invoke(p);
                if (elapsed >= nextLog)
                {
                    nextLog += 300;
                    run.Log(L.F("Avanzamento: {0} di {1} coppie in {2}, {3:F2} coppie/s, {4} host attivi; fine ciclo stimata {5}{6}",
                        p.Done, p.Total, ScanEstimator.Duration(elapsed), p.RatePerSec, p.HostsAlive,
                        p.CycleEtaLocal is DateTime c ? $"{c:HH:mm} (+{ScanEstimator.Duration(p.CycleRemainingSec!.Value)})" : L.T("in calcolo"),
                        p.Cycles > 1 && p.LoopEtaLocal is DateTime l ? L.F(", fine loop stimata {0:HH:mm} (+{1})", l, ScanEstimator.Duration(p.LoopRemainingSec!.Value)) : ""));
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>Esito del pre-controllo TCP di una porta (v1.4): aperta, rifiutata (RST), nessuna risposta.</summary>
    private enum PortState { Unknown, Open, Refused, Timeout }

    /// <summary>
    /// Pre-controllo TCP di tutte le porte in parallelo (v1.4): sugli host attivi le porte chiuse o filtrate costavano un handshake TLS
    /// ciascuna (3-5 s in sequenza: il 22% del tempo della /20); così costano una sola attesa, e TLS/HTTP partono solo dove la porta risponde.
    /// </summary>
    private static async Task<Dictionary<int, (PortState State, double Ms)>> PrecheckPortsAsync(string host, IReadOnlyList<int> ports, int timeoutMs, CancellationToken ct)
    {
        var tasks = ports.Select(async port =>
        {
            var sw = Stopwatch.StartNew();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            using var sock = new System.Net.Sockets.Socket(System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
            try { await sock.ConnectAsync(host, port, cts.Token).ConfigureAwait(false); return (port, PortState.Open, sw.Elapsed.TotalMilliseconds); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { return (port, PortState.Timeout, sw.Elapsed.TotalMilliseconds); }
            catch (System.Net.Sockets.SocketException ex) when (ex.SocketErrorCode == System.Net.Sockets.SocketError.ConnectionRefused) { return (port, PortState.Refused, sw.Elapsed.TotalMilliseconds); }
            catch (Exception) { return (port, PortState.Timeout, sw.Elapsed.TotalMilliseconds); }
        }).ToList();
        var res = await Task.WhenAll(tasks).ConfigureAwait(false);
        return res.ToDictionary(x => x.Item1, x => (x.Item2, x.Item3));
    }

    /// <summary>
    /// Lavoratori della passata (v1.8): ognuno prende prima un lavoro sui nomi (<see cref="Run.NameJobs"/>), poi un host dalla coda; finisce
    /// quando code e lavori in corso sono a zero. La chiusura di un host (ripiegamento dei nomi, righe definitive) è l'ultimo lavoro sui
    /// nomi di quell'host, così nessun lavoratore resta fermo ad aspettare.
    /// </summary>
    private async Task RunWorkersAsync(Run run, int workers, ConcurrentQueue<ScanTarget> hostQueue, List<int> ports, ScanEstimator estimator)
    {
        var cfg = run.Cfg;
        bool retryOn = run.RetrySem != null;
        async Task Worker()
        {
            while (true)
            {
                run.Ct.ThrowIfCancellationRequested();
                if (run.NameJobs.TryDequeue(out var job))
                {
                    await run.Pause.WaitAsync(run.Ct).ConfigureAwait(false);
                    try { await job().ConfigureAwait(false); }
                    finally { Interlocked.Decrement(ref run.Outstanding); }
                    continue;
                }
                if (hostQueue.TryDequeue(out var host))
                {
                    await run.Pause.WaitAsync(run.Ct).ConfigureAwait(false);
                    var hostPorts = cfg.RandomOrder ? ports.OrderBy(_ => Random.Shared.Next()).ToList() : ports;
                    try { await ScanHostAsync(run, host, hostPorts, estimator, false).ConfigureAwait(false); }
                    finally { Interlocked.Decrement(ref run.Outstanding); }
                    continue;
                }
                // v1.9: coda degli host vuota: la seconda chance parte subito (una volta sola) e i lavoratori liberi la servono mentre gli altri finiscono i nomi
                if (retryOn && Interlocked.CompareExchange(ref run.RetryStarted, 1, 0) == 0) StartRetry(run, ports);
                if (run.RetryQueue.TryDequeue(out var again))
                {
                    await run.Pause.WaitAsync(run.Ct).ConfigureAwait(false);
                    try { await ScanHostAsync(run, again, ports, estimator, true).ConfigureAwait(false); }
                    finally { Interlocked.Decrement(ref run.Outstanding); }
                    continue;
                }
                if (Volatile.Read(ref run.Outstanding) <= 0) return;
                await Task.Delay(25, run.Ct).ConfigureAwait(false);
            }
        }
        var tasks = Enumerable.Range(0, Math.Max(1, workers)).Select(_ => Worker()).ToList();
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    /// <summary>Seconda chance (v1.9): sposta gli host non confermati raccolti finora nella coda della seconda chance (lavoro in più per i lavoratori).</summary>
    private static void StartRetry(Run run, List<int> ports)
    {
        var batch = new List<ScanTarget>();
        while (run.NotAlive.TryTake(out var x)) batch.Add(x.Target);
        if (batch.Count == 0) return;
        if (run.RetryCount == 0) { run.RetryAliveBefore = run.AliveHosts.Count; run.RetryStarted = 1; }
        Interlocked.Add(ref run.RetryCount, batch.Count);
        Interlocked.Add(ref run.Outstanding, batch.Count);
        run.Log(L.F("Seconda chance dell'alive check: {0} host non confermati riprovati a ritmo lento (ICMP + TCP {1}, timeout {2} ms)", batch.Count, string.Join(",", ports), run.Cfg.Alive.TimeoutMs * 3 / 2));
        foreach (var t in batch) run.RetryQueue.Enqueue(t);
    }

    /// <summary>Un host: risoluzione e alive check una volta, qualunque sia il numero di porte, pre-controllo delle porte, poi le porte in sequenza; le righe per IP vanno in anteprima e la seconda passata sui nomi scoperti viene accodata (v1.8), con la chiusura dell'host come ultimo lavoro.</summary>
    private async Task ScanHostAsync(Run run, ScanTarget target, List<int> ports, ScanEstimator estimator, bool retry = false)
    {
        var cfg = run.Cfg;
        var info = await ProbeHostAsync(run, target, retry).ConfigureAwait(false);
        if (info.Alive?.State == AliveState.Alive) run.AliveHosts.TryAdd(target.Host, 0);

        bool skipAll = info.Error != null || (info.Alive != null && info.Alive.State != AliveState.Alive && cfg.Alive.SkipIfNotAlive);
        if (retry && skipAll) return;   // seconda chance fallita: la riga "non raggiungibile" resta quella già emessa
        Dictionary<int, (PortState State, double Ms)>? precheck = null;
        if (!skipAll && cfg.PortPrecheck && ports.Count > 1)
        {
            await run.Pause.WaitAsync(run.Ct).ConfigureAwait(false);
            string connectHost = target.IsIpLiteral ? target.Host : (info.Ips.FirstOrDefault() ?? target.Host);
            precheck = await PrecheckPortsAsync(connectHost, ports, cfg.ConnectTimeoutMs, run.Ct).ConfigureAwait(false);
        }

        var results = new List<ScanResult>();
        bool first = true;
        foreach (int port in ports)
        {
            run.Ct.ThrowIfCancellationRequested();
            var pre = precheck != null && precheck.TryGetValue(port, out var ps) ? ps : (PortState.Unknown, 0);
            var r = await ScanOneAsync(run, target, port, info, first, null, pre).ConfigureAwait(false);
            first = false;
            results.Add(r);
        }

        // test avanzati a livello di host (FastCGI 9000, PTR): una volta, sul primo risultato raggiunto, poi copiati sugli altri
        ScanResult? hostPivot = null;
        if (cfg.Advanced.Any && results.Any(r => r.HttpReachable || r.Alive == AliveState.Alive))
        {
            var pivot = hostPivot = results.FirstOrDefault(r => r.HttpReachable) ?? results[0];
            try { await Php.AdvancedProbes.RunHostLevelAsync(cfg, pivot, run.Ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { run.Log(L.F("{0}: test avanzati a livello di host non completati: {1}", target.Host, ex.Message)); }
            foreach (var r in results)
            {
                if (ReferenceEquals(r, pivot)) continue;
                CopyHostLevel(pivot, r);
                foreach (var n in pivot.DiscoveredNames) if (!r.DiscoveredNames.Contains(n)) r.DiscoveredNames.Add(n);
            }
            // i test a livello di host possono aggiungere evidenze di PHP (php-fpm esposto): verdetto e priorità ricalcolati
            foreach (var r in results) VerdictEngine.Apply(r);
        }

        // seconda passata sui nomi scoperti (stessi IP, Host e SNI = nome), solo dove HTTP ha risposto
        if (cfg.DiscoverNames && cfg.RescanDiscoveredNames)
        {
            var names = new List<string>();
            foreach (var r in results) foreach (var n in r.DiscoveredNames) if (!names.Contains(n)) names.Add(n);
            string? used = target.IsIpLiteral ? (string.IsNullOrWhiteSpace(cfg.HostHeader) ? null : cfg.HostHeader.Trim()) : target.Host;
            var rescan = NameDiscovery.Rescannable(names, target.Host, used, cfg.MaxNamesPerHost);
            var httpPorts = results.Where(r => r.HttpReachable).Select(r => r.Port).Distinct().ToList();
            if (rescan.Count > 0 && httpPorts.Count > 0)
            {
                // v1.7: le righe per IP sono complete: anteprima in tabella subito; la stessa chiave viene riemessa alla fine dell'host con nomi ripiegati e test NAME-*
                foreach (var r in results) run.Preview(r);
                Interlocked.Add(ref run.Total, rescan.Count * httpPorts.Count);
                run.Log(L.F("{0}: {1} nomi scoperti ({2}), seconda passata su {3} porte", target.Host, rescan.Count, string.Join(", ", rescan.Take(5)) + (rescan.Count > 5 ? " …" : ""), httpPorts.Count));
                // v1.8: un lavoro per coppia nome/porta nella coda a priorità; l'ultimo che finisce accoda la chiusura dell'host.
                // Il ripiegamento resta sequenziale e nell'ordine dei nomi (la chiusura lo fa in un colpo solo), così l'esito è identico alla v1.5.
                var pairs = new List<(string Name, int Port)>();
                foreach (var name in rescan) foreach (int port in httpPorts) pairs.Add((name, port));
                var scanned = new ScanResult?[pairs.Count];
                int remaining = pairs.Count;
                Interlocked.Add(ref run.Outstanding, pairs.Count);
                for (int i = 0; i < pairs.Count; i++)
                {
                    int idx = i;
                    var (name, port) = pairs[idx];
                    run.NameJobs.Enqueue(async () =>
                    {
                        try
                        {
                            var r = await ScanOneAsync(run, target, port, info, false, name, (PortState.Open, 0)).ConfigureAwait(false);
                            if (hostPivot != null && r.HttpReachable)
                            {
                                // i risultati a livello di host (FastCGI 9000) valgono anche per il nome: copiati prima del verdetto definitivo, così il confronto dell'esito è alla pari
                                CopyHostLevel(hostPivot, r);
                                VerdictEngine.Apply(r);
                            }
                            scanned[idx] = r;
                        }
                        finally
                        {
                            if (Interlocked.Decrement(ref remaining) == 0)
                            {
                                Interlocked.Increment(ref run.Outstanding);
                                run.NameJobs.Enqueue(() => { FinishHost(run, target, results, pairs, scanned, retry); return Task.CompletedTask; });
                            }
                        }
                    });
                }
                return;
            }
        }

        FinishHost(run, target, results, [], [], retry);
        // v1.9: candidato alla seconda chance solo dopo che le righe "non raggiungibile" sono uscite (la riemissione deve sostituirle, non precederle)
        if (skipAll && info.Error == null && info.Alive != null && cfg.Alive.Retry && !retry) run.NotAlive.Add((target, ports));
    }

    /// <summary>Chiusura dell'host (v1.8): ripiegamento dei nomi nell'ordine delle coppie, poi le righe definitive (per IP ed extra).</summary>
    private void FinishHost(Run run, ScanTarget target, List<ScanResult> results, List<(string Name, int Port)> pairs, ScanResult?[] scanned, bool retry)
    {
        var cfg = run.Cfg;
        var extra = new List<ScanResult>();
        for (int i = 0; i < pairs.Count; i++)
        {
            var (name, port) = pairs[i];
            var r = scanned[i];
            if (r == null) continue;   // lavoro interrotto
            var ipRow = results.FirstOrDefault(x => x.Port == port);
            if (cfg.FoldSameContentNames && ipRow != null && SameContent(ipRow, r, name))
            {
                // il nome è il vhost predefinito: nessuna riga in più, il nome va nella colonna Nome della riga per IP; l'osservazione resta in results.jsonl
                if (!ipRow.SameContentNames.Contains(name)) ipRow.SameContentNames.Add(name);
                ipRow.Add("NAME-SAME", L.T("Nome con lo stesso contenuto"), TestOutcome.Info, L.F("{0}: stesso contenuto del vhost predefinito (stato, intestazioni, versione, applicazione e corpo uguali): nessuna riga aggiuntiva", name));
                Interlocked.Decrement(ref run.Total);
                run.Log(L.F("{0}:{1} {2}: stesso contenuto del vhost predefinito, riga non aggiunta", target.Host, port, name));
                run.Observe(r);
                continue;
            }
            if (cfg.FoldSameOutcomeNames)
            {
                // v1.5: contenuto diverso ma stesso esito della riga per IP o di un nome già tenuto: il nome va nella colonna Nome del
                // "titolare", la riga non si aggiunge; l'osservazione completa resta in results.jsonl
                var keeper = ipRow != null && SameOutcome(ipRow, r) ? ipRow : extra.FirstOrDefault(x => x.Port == port && SameOutcome(x, r));
                if (keeper != null)
                {
                    if (!keeper.SameOutcomeNames.Contains(name)) keeper.SameOutcomeNames.Add(name);
                    keeper.Add("NAME-OUTCOME", L.T("Nome con lo stesso esito"), TestOutcome.Info, L.F("{0}: stesso esito della riga (verdetto, versione, SAPI, applicazione, barriera, WAF, priorità): nessuna riga aggiuntiva", name));
                    Interlocked.Decrement(ref run.Total);
                    run.Log(L.F("{0}:{1} {2}: stesso esito di {3}, riga non aggiunta", target.Host, port, name, keeper.Display));
                    run.Observe(r);
                    continue;
                }
            }
            extra.Add(r);
        }
        foreach (var r in results) Complete(run, r, retry);
        foreach (var r in extra) Complete(run, r, false);
        if (!retry) Interlocked.Increment(ref run.HostsDone);   // l'host della seconda chance era già contato
    }

    /// <summary>Copia su <paramref name="r"/> i risultati dei test a livello di host (FastCGI 9000, esposizioni sulla 9000, test ADV-HOST) ottenuti sul pivot.</summary>
    private static void CopyHostLevel(ScanResult pivot, ScanResult r)
    {
        r.FastCgiExposed = pivot.FastCgiExposed; r.FastCgiDetail = pivot.FastCgiDetail;
        foreach (var x in pivot.Exposures) if (x.Contains("9000", StringComparison.Ordinal) && !r.Exposures.Contains(x)) r.Exposures.Add(x);
        if (pivot.FastCgiExposed == true && r.HttpReachable && r.Sapi.Length == 0) { r.Sapi = "fpm"; r.SapiEvidence = pivot.SapiEvidence; }
        foreach (var t in pivot.Tests.Where(t => t.Id.StartsWith("ADV-HOST", StringComparison.Ordinal))) if (!r.Tests.Any(x => x.Id == t.Id)) r.Tests.Add(t);
    }

    /// <summary>
    /// Chiave dell'esito (v1.5): tutto ciò che la tabella e il report dicono di un servizio al di là del contenuto. Due righe con la stessa
    /// chiave non insegnano nulla l'una in più dell'altra: verdetto, versione PHP, SAPI, applicazione e versione, barriera multipart,
    /// WAF/proxy, priorità, presenza di PHP (sì/forse/no), FastCGI esposto.
    /// </summary>
    internal static string OutcomeKey(ScanResult r) =>
        string.Join("|", r.Verdict, r.PhpVersionRaw, r.Sapi, r.Application, r.ApplicationVersion, r.Multipart, r.WafSummary, r.Priority, r.PhpPresence,
            r.FastCgiExposed is null ? "" : r.FastCgiExposed.Value ? "1" : "0");

    /// <summary>Vero se due righe raggiunte via HTTP hanno lo stesso esito (<see cref="OutcomeKey"/>): il nome non aggiunge informazione e non ha una riga propria.</summary>
    internal static bool SameOutcome(ScanResult a, ScanResult b) =>
        a.HttpReachable && b.HttpReachable && OutcomeKey(a) == OutcomeKey(b);

    /// <summary>Vero se la risposta ottenuta con il nome coincide con quella per IP: stesso verdetto, banner, versione, applicazione e corpo della pagina principale (nome e IP sostituiti prima del confronto).</summary>
    internal static bool SameContent(ScanResult ip, ScanResult named, string name)
    {
        if (!ip.HttpReachable || !named.HttpReachable) return false;
        if (ip.Verdict != named.Verdict || ip.ServerHeader != named.ServerHeader || ip.PoweredBy != named.PoweredBy) return false;
        if (ip.PhpVersionRaw != named.PhpVersionRaw || ip.Application != named.Application || ip.ApplicationVersion != named.ApplicationVersion) return false;
        var a = ip.Requests.FirstOrDefault(q => q.Method == "GET" && !q.Url.Contains('?'));
        var b = named.Requests.FirstOrDefault(q => q.Method == "GET" && !q.Url.Contains('?'));
        if (a == null || b == null || a.Status != b.Status) return false;
        if (a.Status is >= 300 and < 400 && (a.Header("Location") ?? "") != (b.Header("Location") ?? "")) return false;
        return Normalize(a.Body, ip.Host, name) == Normalize(b.Body, ip.Host, name);
    }

    private static string Normalize(string body, string host, string name)
    {
        var t = body.Replace(name, "#", StringComparison.OrdinalIgnoreCase).Replace(host, "#", StringComparison.OrdinalIgnoreCase);
        t = System.Text.RegularExpressions.Regex.Replace(t, @"\s+", " ");
        // nonce, token e timestamp cambiano a ogni richiesta: si confrontano i primi 4 KiB dopo aver tolto i valori alfanumerici lunghi
        t = System.Text.RegularExpressions.Regex.Replace(t, @"[A-Za-z0-9+/=_-]{24,}", "#");
        return t.Length > 4096 ? t[..4096] : t;
    }

    private void Complete(Run run, ScanResult r, bool replace = false)
    {
        if (r.HttpReachable) run.HttpHosts.TryAdd(r.Host, 0);
        if (!run.Cfg.Alive.Enabled && (r.HttpReachable || r.Tls is { Handshake: true })) run.AliveHosts.TryAdd(r.Host, 0);
        if (replace) { run.Replace(r); return; }   // v1.8: riga già contata come completata (seconda chance)
        run.Emit(r);
        Interlocked.Increment(ref run.Done);
    }

    /// <summary>Risoluzione e alive check: una volta per host, qualunque sia il numero di porte.</summary>
    private static async Task<HostInfo> ProbeHostAsync(Run run, ScanTarget target, bool retry = false)
    {
        var cfg = run.Cfg;
        List<string> ips;
        double dnsMs = 0;
        if (!target.IsIpLiteral)
        {
            var swDns = Stopwatch.StartNew();
            try
            {
                var res = await Resolver.ResolveAsync(target.Host, run.ResolverIp, true, cfg.ConnectTimeoutMs, run.Ct).ConfigureAwait(false);
                ips = res.Addresses.Select(a => a.ToString()).ToList();
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { return new HostInfo([], swDns.Elapsed.TotalMilliseconds, null, 0, ex.GetBaseException().Message); }
            dnsMs = swDns.Elapsed.TotalMilliseconds;
            if (ips.Count == 0) return new HostInfo(ips, dnsMs, null, 0, L.T("nome non risolto"));
        }
        else ips = [target.Host];

        AliveResult? alive = null;
        double aliveMs = 0;
        if (cfg.Alive.Enabled)
        {
            // v1.8: tetto separato per l'alive check (sulla /20 con 36 thread × 13 sonde erano ~470 flussi aperti insieme e tutti i timeout);
            // nella seconda chance solo ICMP e TCP sulle porte della scansione, con timeout doppio
            var acfg = retry ? new AliveConfig { Enabled = true, Icmp = cfg.Alive.Icmp, TcpPorts = run.Ports.ToList(), UdpPorts = [], TimeoutMs = cfg.Alive.TimeoutMs * 3 / 2, SkipIfNotAlive = cfg.Alive.SkipIfNotAlive } : cfg.Alive;
            var sem = retry ? run.RetrySem : run.AliveSem;
            if (sem != null) await sem.WaitAsync(run.Ct).ConfigureAwait(false);
            try
            {
                var sw = Stopwatch.StartNew();
                alive = await AliveChecker.CheckAsync(target.Host, acfg, run.Ct).ConfigureAwait(false);
                aliveMs = sw.Elapsed.TotalMilliseconds;
            }
            finally { sem?.Release(); }
        }
        return new HostInfo(ips, dnsMs, alive, aliveMs, null);
    }

    private async Task<ScanResult> ScanOneAsync(Run run, ScanTarget target, int port, HostInfo info, bool firstPort, string? rescanName, (PortState State, double Ms) pre)
    {
        var cfg = run.Cfg;
        var paths = run.Paths;
        var sw = Stopwatch.StartNew();
        var r = new ScanResult { Input = target.Input, Host = target.Host, IsIpLiteral = target.IsIpLiteral, Port = port, StartedLocal = DateTime.Now, NameRescan = rescanName != null };
        if (rescanName != null) r.HostHeader = rescanName;
        string tag = $"{r.Display}:{port}";
        bool skipHttp = false;
        ScanContext? lastCtx = null;
        try
        {
            r.ResolvedIps = info.Ips;
            if (!target.IsIpLiteral)
            {
                if (firstPort) r.PhaseMs["dns"] = info.DnsMs;
                if (info.Error != null)
                {
                    r.Error = info.Error;
                    r.Add("DNS", L.T("Risoluzione del nome"), TestOutcome.Error, r.Error);
                    if (firstPort) run.Log($"{tag}: {r.Error}");
                    return Finish(r, sw);
                }
                r.Add("DNS", L.T("Risoluzione del nome"), TestOutcome.Info, string.Join(", ", info.Ips) + (run.ResolverIp != null ? L.F(" (resolver {0})", run.ResolverIp) : L.T(" (resolver di sistema)")));
            }

            if (info.Alive != null)
            {
                var alive = info.Alive;
                if (firstPort) r.PhaseMs["alive"] = info.AliveMs;
                r.Alive = alive.State; r.AliveMethod = alive.Method; r.AliveDetails = alive.Details; r.AliveMethods = alive.MethodsSummary;
                r.Add("ALIVE", L.T("Alive check"), alive.State == AliveState.Alive ? TestOutcome.Pass : TestOutcome.Warn,
                    (alive.State == AliveState.Alive ? L.F("attivo via {0}", alive.Method) : L.T("nessuna conferma")) + L.F(" [{0:F0} ms]", alive.ElapsedMs) + (firstPort ? "" : " " + L.T("(eseguito una volta per host)")) + " — " + alive.MethodsSummary);
                if (alive.State != AliveState.Alive && cfg.Alive.SkipIfNotAlive)
                {
                    if (firstPort) run.Log(L.F("{0}: non attivo, saltato ({1})", target.Host, alive.Details));
                    return Finish(r, sw);
                }
            }

            // Nome da usare come Host/SNI: nome scoperto, oppure quello configurato per gli IP, oppure il bersaglio stesso
            string? vhost = rescanName ?? (target.IsIpLiteral ? (string.IsNullOrWhiteSpace(cfg.HostHeader) ? null : cfg.HostHeader.Trim()) : null);
            string sni = vhost ?? target.Host;

            if (pre.State is PortState.Refused or PortState.Timeout)
            {
                // pre-controllo TCP: porta chiusa o muta, nessun handshake e nessuna richiesta (costo già pagato una volta per tutte le porte)
                r.PhaseMs["precheck"] = pre.Ms;
                r.Error = pre.State == PortState.Refused ? L.T("porta chiusa (connessione rifiutata)") : L.T("porta senza risposta (timeout di connessione)");
                r.Scheme = port == 80 ? "http" : "https";
                r.Add("PORT", L.T("Pre-controllo della porta"), TestOutcome.Warn, r.Error + L.F(" [{0:F0} ms]", pre.Ms));
                r.Add("HTTP", L.T("Richieste HTTP"), TestOutcome.Skipped, L.F("non tentate: {0}", r.Error));
                return Finish(r, sw);
            }
            if (pre.State == PortState.Open) r.Add("PORT", L.T("Pre-controllo della porta"), TestOutcome.Info, L.F("porta aperta [{0:F0} ms]", pre.Ms));
            // v1.6: budget di tempo del servizio, da qui in avanti (TLS, livello 1, superficie, livello 2, WAF, test avanzati)
            var budget = Stopwatch.StartNew();

            if (port != 80)
            {
                r.Tls = await TlsProbe.ProbeAsync(target.Host, port, sni, cfg.ConnectTimeoutMs + 2000, run.Ct).ConfigureAwait(false);
                r.PhaseMs["tls"] = r.Tls.ElapsedMs;
                r.Add("TLS", L.T("Handshake TLS"), r.Tls.Handshake ? TestOutcome.Info : TestOutcome.Warn, (r.Tls.Handshake ? r.Tls.Summary + (vhost != null ? $" (SNI {vhost})" : "") : L.F("nessun TLS: {0}", r.Tls.Error)) + L.F(" [{0:F0} ms]", r.Tls.ElapsedMs));
                if (r.Tls.ConnectFailed || r.Tls.Silent)
                {
                    // porta chiusa, muta o che accetta la connessione senza rispondere: una seconda connessione HTTP costerebbe
                    // lo stesso tempo per lo stesso esito (su Windows un RST costa ~2 s per i nuovi tentativi di SYN dello stack)
                    r.Error = r.Tls.Error ?? "";
                    r.Scheme = port == 443 ? "https" : "http";
                    r.Add("HTTP", L.T("Richieste HTTP"), TestOutcome.Skipped, L.F("non tentate: {0}", r.Error));
                    skipHttp = true;
                }
            }
            if (!skipHttp)
            {
                r.Scheme = r.Tls is { Handshake: true } || port == 443 ? "https" : "http";
                if (port == 443 && r.Tls is { Handshake: false }) r.Scheme = "http";

                HttpEndpoint Endpoint(string scheme) => vhost != null && target.IsIpLiteral
                    ? new HttpEndpoint(scheme, vhost, port) { ConnectHost = target.Host }
                    : rescanName != null ? new HttpEndpoint(scheme, rescanName, port) { ConnectHost = info.Ips.FirstOrDefault() ?? target.Host }
                    : new HttpEndpoint(scheme, target.Host, port);
                var ctx = new ScanContext { Config = cfg, Http = run.Http, Endpoint = Endpoint(r.Scheme), Result = r, Paths = paths, Log = run.Log, Ct = run.Ct, Pacer = run.Pacer, Pause = run.Pause, Budget = budget };
                r.HostHeader = ctx.HostHeader ?? (ctx.Endpoint.ConnectHost != null ? ctx.Endpoint.Host : target.Host);

                var swHttp = Stopwatch.StartNew();
                await PhpFingerprint.RunAsync(ctx).ConfigureAwait(false);
                if (!r.HttpReachable && r.Requests.Count > 0 && r.Requests[0].ErrorKind is "tls" or "invalid" or "reset" && port != 80 && port != 443)
                {
                    // porta non standard che ha stretto TLS ma non parla HTTP, o viceversa: si prova l'altro schema una volta
                    r.Scheme = r.Scheme == "https" ? "http" : "https";
                    var ctx2 = new ScanContext { Config = cfg, Http = run.Http, Endpoint = Endpoint(r.Scheme), Result = r, Paths = paths, Log = run.Log, Ct = run.Ct, Pacer = run.Pacer, Pause = run.Pause, Budget = budget };
                    await PhpFingerprint.RunAsync(ctx2).ConfigureAwait(false);
                    ctx = ctx2;
                }

                r.PhaseMs["http-l1"] = swHttp.Elapsed.TotalMilliseconds;
                lastCtx = ctx;
                if (r.HttpReachable)
                {
                    await ChoosePrimaryAsync(ctx).ConfigureAwait(false);

                    if (cfg.Level2)
                    {
                        var swL2 = Stopwatch.StartNew();
                        await MitigationProbe.RunAsync(ctx).ConfigureAwait(false);
                        r.PhaseMs["http-l2"] = swL2.Elapsed.TotalMilliseconds;
                    }
                    if (cfg.WafDetect)
                    {
                        var swWaf = Stopwatch.StartNew();
                        await WafProbe.RunAsync(ctx).ConfigureAwait(false);
                        r.PhaseMs["waf"] = swWaf.Elapsed.TotalMilliseconds;
                    }
                }
                else run.Log(L.F("{0}: nessuna risposta HTTP ({1})", tag, r.Error));
            }
            if (cfg.DiscoverNames)
            {
                foreach (var n in NameDiscovery.Collect(r)) if (!r.DiscoveredNames.Contains(n)) r.DiscoveredNames.Add(n);
                if (r.DiscoveredNames.Count > 0)
                    r.Add("NAMES", L.T("Nomi scoperti"), TestOutcome.Info, string.Join(", ", r.DiscoveredNames) + " " + L.T("(da certificato e Location)"));
            }
            // test avanzati per servizio (sezione Avanzate): dopo livello 2, WAF e raccolta dei nomi, così completano senza essere sovrascritti
            if (r.HttpReachable && cfg.Advanced.Any && lastCtx != null)
            {
                var swAdv = Stopwatch.StartNew();
                try { await Php.AdvancedProbes.RunAsync(lastCtx).ConfigureAwait(false); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { r.Add("ADV", L.T("Test avanzati"), TestOutcome.Error, ex.GetBaseException().Message); run.Log(L.F("{0}: test avanzati non completati: {1}", tag, ex.Message)); }
                r.PhaseMs["advanced"] = swAdv.Elapsed.TotalMilliseconds;
            }
            // v1.6: fasi facoltative saltate per budget di tempo (superficie, test avanzati): una riga di test e una di log, mai silenzioso
            if (r.SkippedForBudget.Count > 0)
            {
                string skipped = string.Join(", ", r.SkippedForBudget);
                r.Add("BUDGET", L.T("Budget di tempo per servizio"), TestOutcome.Warn, L.F("budget di {0} s per servizio esaurito: saltati {1}", cfg.ServiceBudgetMs / 1000.0, skipped));
                run.Log(L.F("{0}: budget di {1} s per servizio esaurito dopo {2:F0} ms: saltati {3}", tag, cfg.ServiceBudgetMs / 1000.0, budget.Elapsed.TotalMilliseconds, skipped));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            r.Error = ex.GetBaseException().Message;
            r.Add("ERROR", L.T("Errore interno"), TestOutcome.Error, r.Error);
            run.Log(L.F("{0}: errore {1}", tag, r.Error));
        }
        var res = Finish(r, sw);
        run.Log(L.F("{0}: {1} ({2:F0} ms: {3})", tag, Labels.Verdict(res.Verdict), res.DurationMs, res.PhaseSummary));
        return res;
    }

    /// <summary>Percorso principale per i confronti: il primo .php configurato che risponde 2xx/3xx, altrimenti un .php scoperto, altrimenti il primo che risponde.</summary>
    private static async Task ChoosePrimaryAsync(ScanContext ctx)
    {
        var gets = ctx.Result.Requests.Where(s => s.Method is "GET" or "HEAD" && s.HasResponse && !s.Url.Contains('?')).ToList();
        foreach (var p in ctx.Paths)
        {
            var s = gets.FirstOrDefault(g => g.Url.EndsWith(ctx.Endpoint.Url(p), StringComparison.Ordinal));
            if (s != null && p.EndsWith(".php", StringComparison.OrdinalIgnoreCase) && s.Status is >= 200 and < 400) { ctx.PrimaryPath = p; ctx.Baseline = s; return; }
        }
        foreach (var p in ctx.SurfacePhpPaths)
        {
            var s = await ctx.GetAsync(p).ConfigureAwait(false);
            if (s.HasResponse && s.Status is >= 200 and < 400)
            {
                ctx.Result.Add("L2-PATH", L.T("Percorso per il livello 2"), TestOutcome.Info, L.F("{0} dalla superficie scoperta (i percorsi configurati non offrono un .php che risponde)", p), s);
                ctx.PrimaryPath = p; ctx.Baseline = s; return;
            }
        }
        foreach (var p in ctx.Paths)
        {
            var s = gets.FirstOrDefault(g => g.Url.EndsWith(ctx.Endpoint.Url(p), StringComparison.Ordinal));
            if (s != null && s.Status is >= 200 and < 400) { ctx.PrimaryPath = p; ctx.Baseline = s; return; }
        }
    }

    private static ScanResult Finish(ScanResult r, Stopwatch sw)
    {
        r.DurationMs = sw.Elapsed.TotalMilliseconds;
        VerdictEngine.Apply(r);
        return r;
    }

    public static string DescribeAlive(AliveConfig a)
    {
        var parts = new List<string>();
        if (a.Icmp) parts.Add("ICMP");
        if (a.TcpPorts.Count > 0) parts.Add("TCP " + string.Join(",", a.TcpPorts));
        if (a.UdpPorts.Count > 0) parts.Add("UDP " + string.Join(",", a.UdpPorts));
        return (parts.Count == 0 ? L.T("nessun metodo") : string.Join(" + ", parts)) + L.F(", timeout {0} ms", a.TimeoutMs) + (a.SkipIfNotAlive ? L.T(", salta i non attivi") : "");
    }
}
