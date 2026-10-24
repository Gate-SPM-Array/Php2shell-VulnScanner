using System.Text;
using System.Text.Json;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Php;

namespace PhpVulnScanner.Core.Output;

/// <summary>Nomi dei file prodotti in ogni cartella di sessione.</summary>
public static class SessionFiles
{
    public const string SessionJson = "session.json";
    public const string ResultsJson = "results.json";
    public const string ResultsCsv = "results.csv";
    public const string TestsCsv = "tests.csv";
    public const string ScanLog = "scan.log";
    public const string ReportPrefix = "report_v";

    public static readonly UTF8Encoding Utf8Bom = new(encoderShouldEmitUTF8Identifier: true);

    public const string ResultsJsonl = "results.jsonl";
    public const string SamplesJson = "samples.json";

    public static string CreateSessionFolder(ScanConfig cfg, DateTime startLocal, string? suffix = null)
    {
        string label = string.IsNullOrWhiteSpace(cfg.SessionLabel) ? "" : "_" + cfg.SessionLabel.Trim();
        string name = $"{startLocal:yyyyMMdd_HHmmss}_phpscan{label}" + (string.IsNullOrEmpty(suffix) ? "" : "_" + suffix);
        foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '-');
        name = name.Replace(' ', '_').Replace(':', '-');
        var dir = Path.Combine(cfg.OutputFolder, name);
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>Scrittura atomica (file temporaneo + rename) per non lasciare JSON corrotti in caso di crash.</summary>
    public static void WriteAllTextAtomic(string path, string content)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content, new UTF8Encoding(false));
        for (int attempt = 0; ; attempt++)
        {
            try { File.Move(tmp, path, overwrite: true); return; }
            catch (IOException) when (attempt < 10) { Thread.Sleep(50); }
            catch (UnauthorizedAccessException) when (attempt < 10) { Thread.Sleep(50); }
        }
    }

    /// <summary>
    /// Scrittura atomica di un oggetto JSON in streaming (v1.6): serializza direttamente nel file temporaneo, poi rename.
    /// Stesso contenuto di <see cref="WriteAllTextAtomic"/> con <c>JsonSerializer.Serialize</c>, senza costruire la stringa intera
    /// (results.json della /20 in debug: 256 MB, che come stringa UTF-16 erano 512 MB di heap per ogni riscrittura).
    /// </summary>
    public static void WriteJsonAtomic<T>(string path, T value, JsonSerializerOptions options)
    {
        var tmp = path + ".tmp";
        using (var fs = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16))
            JsonSerializer.Serialize(fs, value, options);
        for (int attempt = 0; ; attempt++)
        {
            try { File.Move(tmp, path, overwrite: true); return; }
            catch (IOException) when (attempt < 10) { Thread.Sleep(50); }
            catch (UnauthorizedAccessException) when (attempt < 10) { Thread.Sleep(50); }
        }
    }

    /// <summary>results.json: la sessione completa in streaming (<see cref="WriteJsonAtomic"/>), stesso contenuto di <see cref="ResultsToJson"/>.</summary>
    public static void WriteResultsJson(string path, ScanSession session) => WriteJsonAtomic(path, session, ScanConfig.JsonOptions);

    /// <summary>Intestazioni CSV: chiavi stabili, mai tradotte (R: i file sono dati, non interfaccia).</summary>
    public static readonly string[] ResultColumns =
    [
        "input", "host", "port", "scheme", "resolved_ips", "alive", "alive_method", "http_reachable", "server", "x_powered_by",
        "php_detected", "php_version", "php_version_source", "version_status", "fixed_release", "package_suffix",
        "multipart_barrier", "variants_blocked", "variants_total", "upload_progress_field_blocked", "size_limit",
        "waf_summary", "verdict", "priority", "sapi", "os_hint", "application", "verdict_reason", "tls_subject", "tls_issuer", "duration_ms", "started", "alive_methods", "error",
        "host_header", "name_rescan", "discovered_names", "php_surface", "surface_probe", "cycle", "history",
        "application_version", "technologies", "ncsc_status",
        "ip", "name", "same_content_names", "head_vs_get", "allowed_methods", "php_version_floor", "libraries", "components", "exposures", "fastcgi_exposed", "browser_ua", "app_version_check", "technology_statuses",
        "same_outcome_names", "php_presence", "php_hints", "php_hint_score", "ini_hints", "verbosity_score", "verbosity_items",
    ];

    public static string ResultsToCsv(IEnumerable<ScanResult> results, CsvFormat csv)
    {
        var sb = new StringBuilder();
        sb.AppendLine(csv.Join(ResultColumns));
        foreach (var r in results)
        {
            sb.AppendLine(csv.Join(new[]
            {
                csv.Escape(r.Input), csv.Escape(r.Host), r.Port.ToString(), r.Scheme, csv.Escape(string.Join(" ", r.ResolvedIps)),
                r.Alive.ToString(), csv.Escape(r.AliveMethod), r.HttpReachable ? "1" : "0", csv.Escape(r.ServerHeader), csv.Escape(r.PoweredBy),
                r.PhpDetected ? "1" : "0", csv.Escape(r.PhpVersionRaw), csv.Escape(r.PhpVersionSource), r.VersionStatus.ToString(), r.FixedRelease, r.PackageSuffix ? "1" : "0",
                r.Multipart.ToString(), r.VariantsBlocked < 0 ? "" : r.VariantsBlocked.ToString(), r.VariantsTotal == 0 ? "" : r.VariantsTotal.ToString(),
                r.UploadProgressFieldBlocked is null ? "" : r.UploadProgressFieldBlocked.Value ? "1" : "0", csv.Escape(r.SizeLimit),
                csv.Escape(r.WafSummary), r.Verdict.ToString(), r.Priority.ToString(), r.Sapi, csv.Escape(r.OsHint), csv.Escape(r.Application), csv.Escape(r.VerdictReason), csv.Escape(r.Tls?.Subject ?? ""), csv.Escape(r.Tls?.Issuer ?? ""),
                csv.Num(r.DurationMs, 0), csv.Escape(Stamp.Local(r.StartedLocal)), csv.Escape(r.AliveMethods), csv.Escape(r.Error),
                csv.Escape(r.HostHeader), r.NameRescan ? "1" : "0", csv.Escape(string.Join(" ", r.DiscoveredNames)), csv.Escape(string.Join(" ", r.PhpSurface)), r.PhpSurfaceProbe, r.Cycle.ToString(), csv.Escape(string.Join(" | ", r.History)),
                csv.Escape(r.ApplicationVersion), csv.Escape(string.Join(" | ", r.Technologies)), csv.Escape(r.NcscStatus),
                csv.Escape(r.DisplayIp), csv.Escape(r.DisplayName), csv.Escape(string.Join(" ", r.SameContentNames)), csv.Escape(r.HeadVsGet), csv.Escape(r.AllowedMethods), csv.Escape(r.PhpVersionFloor),
                csv.Escape(string.Join(" | ", r.Libraries)), csv.Escape(string.Join(" | ", r.Components)), csv.Escape(string.Join(" | ", r.Exposures)),
                r.FastCgiExposed is null ? "" : r.FastCgiExposed.Value ? "1" : "0", csv.Escape(r.BrowserUaResult), csv.Escape(r.AppVersionCheck), csv.Escape(string.Join(" | ", r.TechnologyStatuses)),
                csv.Escape(string.Join("; ", r.SameOutcomeNames)), r.PhpPresence, csv.Escape(string.Join("; ", r.PhpHints)), r.PhpHintScore.ToString(), csv.Escape(string.Join("; ", r.IniHints)), r.VerbosityScore.ToString(), csv.Escape(string.Join("; ", r.VerbosityItems)),
            }));
        }
        return sb.ToString();
    }

    public static readonly string[] TestColumns = ["input", "host", "port", "test_id", "test", "outcome", "detail", "request", "response"];

    public static string TestsToCsv(IEnumerable<ScanResult> results, CsvFormat csv)
    {
        var sb = new StringBuilder();
        sb.AppendLine(csv.Join(TestColumns));
        foreach (var r in results)
            foreach (var t in r.Tests)
                sb.AppendLine(csv.Join(new[] { csv.Escape(r.Input), csv.Escape(r.Host), r.Port.ToString(), t.Id, csv.Escape(t.Name), t.Outcome.ToString(), csv.Escape(t.Detail), csv.Escape(t.Request), csv.Escape(t.Response) }));
        return sb.ToString();
    }

    public static string ResultsToJson(ScanSession session) => JsonSerializer.Serialize(session, ScanConfig.JsonOptions);

    public static ScanSession? ReadSession(string folder)
    {
        var p = Path.Combine(folder, ResultsJson);
        if (!File.Exists(p)) p = Path.Combine(folder, SessionJson);
        if (!File.Exists(p)) return null;
        var session = JsonSerializer.Deserialize<ScanSession>(File.ReadAllText(p), ScanConfig.JsonOptions);
        if (session == null) return null;
        // Sessione non chiusa (crash o chiusura forzata): results.json può essere indietro di qualche secondo rispetto a
        // results.jsonl, che riceve ogni risultato appena pronto (con il consolidamento ogni riga è lo stato vincente di quel momento).
        var jl = Path.Combine(folder, ResultsJsonl);
        if (session.Status == ScanStatus.Running && File.Exists(jl))
        {
            var byKey = new Dictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in session.Results) byKey[r.Key] = r;
            foreach (var r in ReadJsonl(jl)) byKey[r.Key] = r;   // l'ultima riga per chiave è la più aggiornata
            // le osservazioni dei nomi ripiegati su un'altra riga (stesso contenuto o stesso esito) stanno in results.jsonl ma non sono righe
            var folded = new HashSet<string>(byKey.Values.SelectMany(r => r.SameContentNames.Concat(r.SameOutcomeNames).Select(n => $"{r.Host}|{r.Port}|{n}".ToLowerInvariant())), StringComparer.Ordinal);
            session.Results = byKey.Values.Where(r => !r.NameRescan || !folded.Contains(r.Key)).OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
        }
        return session;
    }

    public static List<ScanResult> ReadJsonl(string path)
    {
        var list = new List<ScanResult>();
        foreach (var line in File.ReadLines(path))
        {
            if (line.Length == 0) continue;
            try { var r = JsonSerializer.Deserialize<ScanResult>(line, JsonlOptions); if (r != null) list.Add(r); } catch { }
        }
        return list;
    }

    public static readonly JsonSerializerOptions JsonlOptions = new() { WriteIndented = false, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    /// <summary>
    /// Percorso di un report mai sovrascritto: "&lt;prefisso&gt;_v&lt;versione del programma&gt;.html", e alle rigenerazioni "_2", "_3", …
    /// (fino alla v1.3 il nome portava un numero di revisione "report_v1.N" che si confondeva con la versione del programma).
    /// </summary>
    public static string NextReportPath(string dir, string prefix = "report", string? appVersion = null)
    {
        appVersion ??= Net.HttpProbe.AppVersion;
        string baseName = $"{prefix}_v{appVersion}";
        string path = Path.Combine(dir, baseName + ".html");
        for (int i = 2; File.Exists(path); i++) path = Path.Combine(dir, $"{baseName}_{i}.html");
        return path;
    }

    /// <summary>Report compatto (quello aperto dal pulsante) e report completo: prefissi dei nomi.</summary>
    public const string CompactReportPrefix = "report";
    public const string FullReportPrefix = "report_completo";
}

/// <summary>
/// Scrive i file della sessione man mano: log riga per riga, results.jsonl (una riga per risultato, append) a ogni risultato,
/// results.json riscritto al massimo ogni 30 s e alla fine (riscriverlo a ogni risultato costava O(n²): sulla /20 della v1.2,
/// decine di GB di serializzazione). Con il consolidamento ogni chiave tiene solo il risultato vincente.
/// v1.6: la riscrittura periodica non blocca più lo scanner. Sotto il lock si prende solo l'istantanea dei risultati (gli oggetti
/// non cambiano dopo l'emissione; il consolidamento sostituisce le voci, cosa che un'istantanea tollera); serializzazione in streaming
/// e scrittura atomica avvengono fuori dal lock, su un thread di sfondo, una alla volta (se una è in corso, si riprova all'Upsert
/// successivo). Sulla /20 in debug (results.json da 256 MB) ogni riscrittura teneva fermi tutti i thread per decine di secondi.
/// </summary>
public sealed class SessionWriter : IDisposable
{
    private readonly ScanSession _session;
    private readonly bool _consolidate;
    private readonly StreamWriter _log;
    private readonly StreamWriter _jsonl;
    private readonly object _lock = new();
    private readonly List<ScanResult> _results = [];
    private readonly Dictionary<string, int> _index = new(StringComparer.OrdinalIgnoreCase);
    private readonly System.Diagnostics.Stopwatch _sinceWrite = System.Diagnostics.Stopwatch.StartNew();
    private bool _dirty;
    private bool _rewriteRunning;
    private Task? _rewriteTask;
    public static int RewriteIntervalMs { get; set; } = 30000;
    /// <summary>Intervallo minimo tra due riscritture di results.json per questa istanza (predefinito: <see cref="RewriteIntervalMs"/> al momento della creazione).</summary>
    public int RewriteInterval { get; set; } = RewriteIntervalMs;

    /// <summary>Riscritture periodiche di results.json avviate (diagnostica e test).</summary>
    public int BackgroundRewrites { get; private set; }

    public SessionWriter(ScanSession session, bool consolidate = false)
    {
        _session = session;
        _consolidate = consolidate;
        _log = new StreamWriter(Path.Combine(session.Folder, SessionFiles.ScanLog), append: true, SessionFiles.Utf8Bom) { AutoFlush = true };
        _jsonl = new StreamWriter(Path.Combine(session.Folder, SessionFiles.ResultsJsonl), append: true, new UTF8Encoding(false)) { AutoFlush = true };
        SessionFiles.WriteAllTextAtomic(Path.Combine(session.Folder, SessionFiles.SessionJson), JsonSerializer.Serialize(session, ScanConfig.JsonOptions));
    }

    public void Log(string message)
    {
        lock (_lock) _log.WriteLine($"{Stamp.LogNow()} {message}");
    }

    /// <summary>Aggiunge o sostituisce (stessa chiave, con il consolidamento) un risultato.</summary>
    public void Upsert(ScanResult r)
    {
        lock (_lock)
        {
            try { _jsonl.WriteLine(JsonSerializer.Serialize(r, SessionFiles.JsonlOptions)); }
            catch (Exception ex) { _log.WriteLine($"{Stamp.LogNow()} results.jsonl: {ex.Message}"); }
            if (_consolidate && _index.TryGetValue(r.Key, out int i)) _results[i] = r;
            else { _index[r.Key] = _results.Count; _results.Add(r); }
            _dirty = true;
            if (!_rewriteRunning && _sinceWrite.ElapsedMilliseconds >= RewriteInterval) StartRewrite();
        }
    }

    /// <summary>Compatibilità: aggiunta semplice.</summary>
    public void AddResult(ScanResult r) => Upsert(r);

    /// <summary>
    /// Osservazione senza riga (v1.5): un nome ripiegato sulla riga per IP o su un altro nome (stesso contenuto o stesso esito) va in
    /// results.jsonl come ogni altra osservazione, ma non in results.json, nel CSV né in tabella: lì il nome sta nella colonna Nome del titolare.
    /// </summary>
    public void Observe(ScanResult r)
    {
        lock (_lock)
        {
            try { _jsonl.WriteLine(JsonSerializer.Serialize(r, SessionFiles.JsonlOptions)); }
            catch (Exception ex) { _log.WriteLine($"{Stamp.LogNow()} results.jsonl: {ex.Message}"); }
        }
    }

    /// <summary>Istantanea della sessione con i risultati attuali (da chiamare sotto il lock: copia solo l'elenco, non gli oggetti).</summary>
    private ScanSession Snapshot(ScanStatus status) => new()
    {
        AppVersion = _session.AppVersion, Machine = _session.Machine, OsDescription = _session.OsDescription, StartLocal = _session.StartLocal, EndLocal = _session.EndLocal,
        Status = status, Folder = _session.Folder, TargetCount = _session.TargetCount, PortCount = _session.PortCount,
        Ports = _session.Ports, Paths = _session.Paths, ParseErrors = _session.ParseErrors, Config = _session.Config, TargetsSummary = _session.TargetsSummary,
        Cycle = _session.Cycle, Cycles = _session.Cycles, Consolidated = _session.Consolidated, HostsTotal = _session.HostsTotal, HostsAlive = _session.HostsAlive, HostsHttp = _session.HostsHttp, DataVersion = _session.DataVersion,
        Results = [.. _results],
    };

    /// <summary>Avvia la riscrittura periodica in sfondo (sotto il lock): istantanea subito, serializzazione e scrittura fuori dal lock.</summary>
    private void StartRewrite()
    {
        var snapshot = Snapshot(ScanStatus.Running);
        _rewriteRunning = true;
        _dirty = false;
        _sinceWrite.Restart();
        BackgroundRewrites++;
        string path = Path.Combine(_session.Folder, SessionFiles.ResultsJson);
        _rewriteTask = Task.Run(() =>
        {
            try { SessionFiles.WriteResultsJson(path, snapshot); }
            catch (Exception ex) { lock (_lock) _log.WriteLine($"{Stamp.LogNow()} results.json: {ex.Message}"); }
            finally { lock (_lock) _rewriteRunning = false; }
        });
    }

    /// <summary>Attende la riscrittura di sfondo in corso, se c'è (fuori dal lock: il task lo prende alla fine).</summary>
    private void WaitRewrite()
    {
        Task? t;
        lock (_lock) t = _rewriteTask;
        if (t == null) return;
        try { t.Wait(); } catch { }
    }

    /// <summary>Scrittura sincrona di results.json con lo stato indicato (sotto il lock, nessuna riscrittura di sfondo in corso).</summary>
    private void WriteResultsJsonNow(ScanStatus status)
    {
        try { SessionFiles.WriteResultsJson(Path.Combine(_session.Folder, SessionFiles.ResultsJson), Snapshot(status)); _dirty = false; _sinceWrite.Restart(); }
        catch (Exception ex) { _log.WriteLine($"{Stamp.LogNow()} results.json: {ex.Message}"); }
    }

    public void Finish(ScanSession session)
    {
        WaitRewrite();
        lock (_lock)
        {
            var csv = new CsvFormat(session.Config.CsvDialect);
            SessionFiles.WriteResultsJson(Path.Combine(session.Folder, SessionFiles.ResultsJson), session);
            _dirty = false;
            SessionFiles.WriteAllTextAtomic(Path.Combine(session.Folder, SessionFiles.SessionJson), JsonSerializer.Serialize(new ScanSession
            {
                AppVersion = session.AppVersion, Machine = session.Machine, OsDescription = session.OsDescription, StartLocal = session.StartLocal, EndLocal = session.EndLocal,
                Status = session.Status, Folder = session.Folder, TargetCount = session.TargetCount, PortCount = session.PortCount, Ports = session.Ports, Paths = session.Paths,
                ParseErrors = session.ParseErrors, Config = session.Config, TargetsSummary = session.TargetsSummary, Cycle = session.Cycle, Cycles = session.Cycles,
                Consolidated = session.Consolidated, HostsTotal = session.HostsTotal, HostsAlive = session.HostsAlive, HostsHttp = session.HostsHttp, DataVersion = session.DataVersion,
            }, ScanConfig.JsonOptions));
            File.WriteAllText(Path.Combine(session.Folder, SessionFiles.ResultsCsv), SessionFiles.ResultsToCsv(session.Results, csv), SessionFiles.Utf8Bom);
            File.WriteAllText(Path.Combine(session.Folder, SessionFiles.TestsCsv), SessionFiles.TestsToCsv(session.Results, csv), SessionFiles.Utf8Bom);
            if (session.Config.DebugMode)
            {
                try { File.WriteAllText(Path.Combine(session.Folder, SessionFiles.SamplesJson), Samples.Build(session), new UTF8Encoding(false)); }
                catch (Exception ex) { _log.WriteLine($"{Stamp.LogNow()} samples.json: {ex.Message}"); }
            }
        }
    }

    public void Dispose()
    {
        WaitRewrite();
        lock (_lock)
        {
            if (_dirty) WriteResultsJsonNow(_session.Status);
            _log.Dispose();
            _jsonl.Dispose();
        }
    }
}
