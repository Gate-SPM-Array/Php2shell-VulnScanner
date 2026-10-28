using System.Text;
using System.Text.Json;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Core.Cli;

/// <summary>
/// Modalità a riga di comando, senza interfaccia: stessa scansione, stessi file di sessione e report, esito nel codice di uscita
/// per script e attività pianificate (idea ripresa dal checker php2shell "openai": esiti stabili e leggibili da una pipeline).
/// Codici: 0 = nessun bersaglio vulnerabile; 1 = almeno un "vulnerabile per versione" o "probabilmente vulnerabile";
/// 2 = argomenti non validi; 3 = nessun vulnerabile ma almeno un "non determinabile"; 4 = scansione interrotta o in errore.
/// </summary>
public static class CliRunner
{
    public const int ExitClean = 0, ExitVulnerable = 1, ExitUsage = 2, ExitUndetermined = 3, ExitError = 4;

    public static bool IsCliInvocation(string[] args) =>
        args.Any(a => a is "--scan" or "--help" or "-h" or "/?" or "--version" or "--merge");

    /// <summary>Cartelle passate a --merge nell'ultima chiamata a Parse (fusione di sessioni, nessuna scansione).</summary>
    public static List<string> MergeFolders { get; } = [];

    public static string Usage() => string.Join("\n",
    [
        L.F("PHP Vuln Scanner v{0} – riga di comando", HttpProbe.AppVersion),
        L.T("Uso: PhpVulnScanner.exe --scan <file o elenco> [opzioni]"),
        "",
        L.T("  --scan <file|a,b,c>      file di bersagli (uno per riga) oppure elenco separato da virgole"),
        L.T("  --ports 443[,8443]       porte TCP (predefinita 443)"),
        L.T("  --paths \"/ /index.php\"   percorsi da sondare"),
        L.T("  --out <cartella>         cartella delle sessioni (predefinita: Sessioni accanto all'eseguibile)"),
        L.T("  --label <testo>          etichetta della sessione"),
        L.T("  --no-alive               nessun alive check preliminare"),
        L.T("  --alive-tcp 443,80       porte TCP dell'alive check    --alive-udp 53   porte UDP    --no-icmp"),
        L.T("  --alive-timeout <ms>     timeout dell'alive check       --scan-not-alive  scansiona anche i non confermati"),
        L.T("  --alive-parallel <n>     host in alive check insieme (8; 0 = thread)   --no-alive-retry  nessuna seconda chance a fine ciclo"),
        L.T("  --no-level2              salta precondizioni e barriere  --no-waf   salta la rilevazione WAF/proxy"),
        L.T("  --light                  HEAD al posto di GET (meno traffico, meno segnali)"),
        L.T("  --threads <n>  --connect-timeout <ms>  --read-timeout <ms>  --resolver <ip>  --host-header <nome>"),
        L.T("  --cycles <n>             cicli di scansione (predefinito 1)   --cycle-pause <s>  pausa tra i cicli in secondi (60)"),
        L.T("  --separate-sessions      una sessione per ciclo invece del consolidamento (vince il risultato più informativo)"),
        L.T("  --random                 ordine casuale degli host   --delay <min>-<max>  pausa casuale in ms tra le richieste   --rate <n>  tetto di richieste al secondo"),
        L.T("  --no-surface             nessuna scoperta della superficie PHP (sonda .php inesistente, punti di ingresso, link)"),
        L.T("  --no-names               nessuna raccolta dei nomi   --no-rescan-names  raccolta senza seconda passata   --max-names <n>  nomi per host (10)"),
        L.T("  --debug                  corpi completi, intestazioni inviate, samples.json anonimizzato   --report-unreachable  schede anche per i non raggiungibili"),
        L.T("  --advanced all|none|k1,k2  test avanzati (sezione Avanzate): headvsget, composer, status, appversion, fastcgi, behaviours, level2all, browserua, components, exposures, ptr, ct"),
        L.T("  --no-fold-names          una riga per ogni nome anche quando restituisce lo stesso contenuto del vhost predefinito"),
        L.T("  --no-fold-outcome        una riga per ogni nome anche quando l'esito è uguale a quello del vhost predefinito"),
        L.T("  --inventory <file>       inventario CSV o JSON (target, php_version, ambiente, referente, note) riconciliato a fine scansione: sezione Inventario nel report"),
        L.T("  --no-precheck            nessun pre-controllo TCP delle porte (handshake TLS su ogni porta)   --no-pure-version  rami fuori supporto sempre \"probabilmente vulnerabile\""),
        L.T("  --budget 120             budget di tempo per servizio in secondi: oltre, le sonde facoltative restanti vengono saltate (0 = nessun budget)"),
        L.T("  --merge <cartella> …     fonde due o più sessioni (stessi range) in una nuova sessione in --out, con report delle differenze; nessuna scansione"),
        L.T("  --json <file>            copia di results.json nel percorso indicato"),
        L.T("  --config <file>          carica la configurazione da un file JSON (anche il session.json di una sessione); le opzioni esplicite vincono"),
        L.T("  --save-config <file>     scrive la configurazione risultante e termina senza scansione"),
        L.T("  --analysis-bundle        a fine scansione crea <sessione>_analisi_vX.Y.zip senza i corpi delle risposte (sotto i limiti di upload)"),
        L.T("  --no-ct-dns              nessuna verifica DNS dei nomi da Certificate Transparency (entrano tutti, anche se non vivono sull'IP)"),
        L.T("  --csv standard|excel     formato dei CSV (predefinito excel: ; e virgola decimale)"),
        L.T("  --quiet                  solo il riepilogo finale"),
        "",
        L.T("Codici di uscita: 0 nessun vulnerabile; 1 vulnerabile o probabilmente vulnerabile; 2 argomenti non validi; 3 solo non determinabili; 4 scansione interrotta o in errore."),
        L.T("Uso responsabile: scansionare solo sistemi propri o con autorizzazione scritta."),
    ]);

    /// <summary>Interpreta gli argomenti. Restituisce null e un messaggio se non validi.</summary>
    /// <summary>v1.10: --save-config scrive qui la configurazione e la scansione non parte; --analysis-bundle crea lo zip per analisi a fine scansione.</summary>
    public static string? SaveConfigPath { get; private set; }
    public static bool AnalysisBundleRequested { get; private set; }

    /// <summary>v1.10: legge una configurazione da file JSON: un ScanConfig, oppure un session.json (ne prende il blocco Config).</summary>
    public static ScanConfig LoadConfigFile(string path)
    {
        string text = File.ReadAllText(path);
        using var doc = JsonDocument.Parse(text);
        if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("Config", out var inner) && inner.ValueKind == JsonValueKind.Object)
            return JsonSerializer.Deserialize<ScanConfig>(inner.GetRawText(), ScanConfig.JsonOptions) ?? new ScanConfig();
        return JsonSerializer.Deserialize<ScanConfig>(text, ScanConfig.JsonOptions) ?? new ScanConfig();
    }

    public static ScanConfig? Parse(string[] args, string defaultOutput, out string? error, out string? jsonCopy, out bool quiet)
    {
        error = null; jsonCopy = null; quiet = false; SaveConfigPath = null; AnalysisBundleRequested = false;
        var cfg = new ScanConfig { OutputFolder = defaultOutput };
        // v1.10: --config viene applicato prima di tutto, così le altre opzioni della riga di comando vincono
        for (int i = 0; i + 1 < args.Length; i++)
            if (args[i] == "--config")
            {
                try { cfg = LoadConfigFile(args[i + 1]); if (string.IsNullOrWhiteSpace(cfg.OutputFolder)) cfg.OutputFolder = defaultOutput; }
                catch (Exception ex) { error = L.F("configurazione non leggibile ({0}): {1}", args[i + 1], ex.Message); return null; }
            }
        string? scan = string.IsNullOrWhiteSpace(cfg.TargetsText) ? null : cfg.TargetsText;
        MergeFolders.Clear();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException(L.F("manca il valore dopo {0}", a));
            try
            {
                switch (a)
                {
                    case "--config": Next(); break;
                    case "--save-config": SaveConfigPath = Next(); break;
                    case "--analysis-bundle": AnalysisBundleRequested = true; break;
                    case "--no-ct-dns": cfg.CtDnsCheck = false; break;
                    case "--scan": scan = Next(); break;
                    case "--ports": cfg.PortsText = Next(); break;
                    case "--paths": cfg.PathsText = Next(); break;
                    case "--out": cfg.OutputFolder = Next(); break;
                    case "--label": cfg.SessionLabel = Next(); break;
                    case "--no-alive": cfg.Alive.Enabled = false; break;
                    case "--no-icmp": cfg.Alive.Icmp = false; break;
                    case "--alive-tcp": cfg.Alive.TcpPorts = TargetParser.ParsePorts(Next(), out var e1); if (e1.Count > 0) throw new ArgumentException(L.F("porte non valide: {0}", string.Join(",", e1))); break;
                    case "--alive-udp": cfg.Alive.UdpPorts = TargetParser.ParsePorts(Next(), out var e2); if (e2.Count > 0) throw new ArgumentException(L.F("porte non valide: {0}", string.Join(",", e2))); break;
                    case "--alive-timeout": cfg.Alive.TimeoutMs = Int(Next(), a); break;
                    case "--alive-parallel": cfg.Alive.Parallel = Int(Next(), a); break;
                    case "--no-alive-retry": cfg.Alive.Retry = false; break;
                    case "--scan-not-alive": cfg.Alive.SkipIfNotAlive = false; break;
                    case "--no-level2": cfg.Level2 = false; break;
                    case "--no-waf": cfg.WafDetect = false; cfg.WafBehaviour = false; break;
                    case "--light": cfg.LightMode = true; break;
                    case "--threads": cfg.Threads = Int(Next(), a); break;
                    case "--connect-timeout": cfg.ConnectTimeoutMs = Int(Next(), a); break;
                    case "--read-timeout": cfg.ReadTimeoutMs = Int(Next(), a); break;
                    case "--resolver": cfg.ResolverIp = Next(); break;
                    case "--host-header": cfg.HostHeader = Next(); break;
                    case "--cycles": cfg.Cycles = Int(Next(), a); break;
                    case "--cycle-pause": cfg.CyclePauseSec = Int(Next(), a); break;
                    case "--separate-sessions": cfg.Consolidate = false; break;
                    case "--consolidate": cfg.Consolidate = true; break;
                    case "--random": cfg.RandomOrder = true; break;
                    case "--delay":
                        {
                            var parts = Next().Split('-', 2);
                            cfg.DelayMinMs = Int(parts[0], a);
                            cfg.DelayMaxMs = parts.Length > 1 ? Int(parts[1], a) : cfg.DelayMinMs;
                            break;
                        }
                    case "--rate": cfg.MaxRequestsPerSecond = Int(Next(), a); break;
                    case "--no-surface": cfg.SurfaceDiscovery = false; break;
                    case "--no-names": cfg.DiscoverNames = false; cfg.RescanDiscoveredNames = false; break;
                    case "--no-rescan-names": cfg.RescanDiscoveredNames = false; break;
                    case "--max-names": cfg.MaxNamesPerHost = Int(Next(), a); break;
                    case "--debug": cfg.DebugMode = true; break;
                    case "--report-unreachable": cfg.ReportUnreachableDetails = true; break;
                    case "--advanced": cfg.Advanced = AdvancedOptions.Parse(Next()); break;
                    case "--no-fold-names": cfg.FoldSameContentNames = false; break;
                    case "--no-fold-outcome": cfg.FoldSameOutcomeNames = false; break;
                    case "--inventory": cfg.InventoryPath = Next(); break;
                    case "--no-precheck": cfg.PortPrecheck = false; break;
                    case "--no-pure-version": cfg.PureVersionIsVulnerable = false; break;
                    case "--budget":
                        {
                            int sec = Int(Next(), a);
                            if (sec < 0) throw new ArgumentException(L.F("valore negativo per {0}: {1}", a, sec));
                            cfg.ServiceBudgetMs = sec * 1000;
                            break;
                        }
                    case "--merge": while (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal)) MergeFolders.Add(args[++i]); break;
                    case "--json": jsonCopy = Next(); break;
                    case "--csv": cfg.CsvDialect = Next().Equals("standard", StringComparison.OrdinalIgnoreCase) ? CsvDialect.Standard : CsvDialect.ExcelItalian; break;
                    case "--quiet": quiet = true; break;
                    case "--help": case "-h": case "/?": case "--version": break;
                    default: throw new ArgumentException(L.F("argomento sconosciuto: {0}", a));
                }
            }
            catch (ArgumentException ex) { error = ex.Message; return null; }
        }
        if (scan == null && MergeFolders.Count > 0) return cfg;   // fusione di sessioni: nessun bersaglio
        if (scan == null) { error = L.T("manca --scan"); return null; }
        if (File.Exists(scan)) cfg.TargetsText = File.ReadAllText(scan);
        else cfg.TargetsText = scan.Replace(',', '\n');
        var parsed = TargetParser.Parse(cfg.TargetsText);
        if (parsed.Targets.Count == 0) { error = L.T("nessun bersaglio valido") + (parsed.Errors.Count > 0 ? ": " + string.Join("; ", parsed.Errors) : ""); return null; }
        var ports = TargetParser.ParsePorts(cfg.PortsText, out var pe);
        if (ports.Count == 0 || pe.Count > 0) { error = L.F("porte non valide: {0}", cfg.PortsText); return null; }
        cfg.Clamp();
        return cfg;
    }

    private static int Int(string v, string opt) =>
        int.TryParse(v, out int n) ? n : throw new ArgumentException(L.F("valore non numerico per {0}: {1}", opt, v));

    /// <summary>Esegue la scansione e restituisce il codice di uscita. Le righe di log e il riepilogo vanno su <paramref name="out"/>.</summary>
    public static async Task<int> RunAsync(string[] args, string defaultOutput, TextWriter @out, CancellationToken ct)
    {
        if (args.Any(a => a is "--help" or "-h" or "/?")) { @out.WriteLine(Usage()); return ExitClean; }
        if (args.Any(a => a == "--version")) { @out.WriteLine(HttpProbe.AppVersion); return ExitClean; }
        var cfg = Parse(args, defaultOutput, out var error, out var jsonCopy, out bool quiet);
        if (cfg == null) { @out.WriteLine(L.F("Errore: {0}", error)); @out.WriteLine(); @out.WriteLine(Usage()); return ExitUsage; }
        if (MergeFolders.Count > 0) return await MergeAsync(MergeFolders.ToList(), cfg.OutputFolder, @out).ConfigureAwait(false);
        if (SaveConfigPath != null)
        {
            try { File.WriteAllText(SaveConfigPath, JsonSerializer.Serialize(cfg, ScanConfig.JsonOptions), new UTF8Encoding(false)); @out.WriteLine(L.F("Configurazione salvata: {0}", SaveConfigPath)); return ExitClean; }
            catch (Exception ex) { @out.WriteLine(L.F("Errore: {0}", ex.Message)); return ExitError; }
        }

        var engine = new ScanEngine();
        if (!quiet) engine.Log += m => @out.WriteLine($"{Stamp.LogNow()} {m}");
        var reports = new List<string>();
        bool separate = cfg.Cycles > 1 && !cfg.Consolidate;
        engine.CycleCompleted += s =>
        {
            if (!separate || s.Results.Count == 0) return;
            try { reports.Add(ReportGenerator.Generate(s)); }
            catch (Exception ex) { @out.WriteLine(L.F("Report non generato: {0}", ex.Message)); }
        };
        ScanSession session;
        try { session = await engine.RunAsync(cfg, ct).ConfigureAwait(false); }
        catch (Exception ex) { @out.WriteLine(L.F("Errore: {0}", ex.Message)); return ExitError; }

        string? report = null;
        if (!separate && session.Results.Count > 0)
        {
            try { report = ReportGenerator.Generate(session); }
            catch (Exception ex) { @out.WriteLine(L.F("Report non generato: {0}", ex.Message)); }
        }
        else if (reports.Count > 0) report = reports[^1];
        if (jsonCopy != null)
        {
            try { File.Copy(Path.Combine(session.Folder, SessionFiles.ResultsJson), jsonCopy, overwrite: true); }
            catch (Exception ex) { @out.WriteLine(L.F("Copia JSON non riuscita: {0}", ex.Message)); }
        }
        if (AnalysisBundleRequested)
        {
            try { @out.WriteLine(L.F("Pacchetto per analisi: {0}", AnalysisBundle.Build(session.Folder, Path.Combine(Path.GetDirectoryName(session.Folder.TrimEnd(Path.DirectorySeparatorChar)) ?? session.Folder, AnalysisBundle.DefaultName(session.Folder, session.AppVersion))))); }
            catch (Exception ex) { @out.WriteLine(L.F("Pacchetto per analisi non creato: {0}", ex.Message)); }
        }

        int Count(Verdict v) => session.Results.Count(r => r.Verdict == v);
        @out.WriteLine();
        @out.WriteLine(L.F("Risultati: {0} – vulnerabili per versione {1}, probabilmente vulnerabili {2}, non determinabili {3}, mitigati al perimetro {4}, corretti {5}, PHP non rilevato {6}, non raggiungibili {7}",
            session.Results.Count, Count(Verdict.VulnerableByVersion), Count(Verdict.LikelyVulnerable), Count(Verdict.Undetermined), Count(Verdict.MitigatedAtEdge), Count(Verdict.FixedByVersion), Count(Verdict.NoPhpDetected), Count(Verdict.NotReachable)));
        @out.WriteLine(L.F("Host attivi: {0} su {1}, con HTTP: {2}", session.HostsAlive, session.HostsTotal, session.HostsHttp) + (session.Cycles > 1 ? "; " + L.F("cicli eseguiti: {0} di {1}", session.Cycle, session.Cycles) : ""));
        foreach (var r in session.Results.Where(r => r.Verdict is Verdict.VulnerableByVersion or Verdict.LikelyVulnerable or Verdict.Undetermined or Verdict.MitigatedAtEdge).OrderByDescending(r => r.Priority))
            @out.WriteLine($"  [{Labels.Priority(r.Priority)}] {r.Display}:{r.Port} {Labels.Verdict(r.Verdict)} – {r.VerdictReason}");
        @out.WriteLine(L.F("Sessione: {0}", session.Folder));
        if (report != null) @out.WriteLine(L.F("Report HTML: {0}", report));

        if (session.Status != ScanStatus.Completed) return ExitError;
        if (Count(Verdict.VulnerableByVersion) + Count(Verdict.LikelyVulnerable) > 0) return ExitVulnerable;
        if (Count(Verdict.Undetermined) > 0) return ExitUndetermined;
        return ExitClean;
    }

    /// <summary>Fusione di sessioni (v1.4): legge le cartelle, controlla la sovrapposizione dei bersagli, scrive la sessione fusa con report e file degli host.</summary>
    public static Task<int> MergeAsync(IReadOnlyList<string> folders, string outputFolder, TextWriter @out)
    {
        try
        {
            if (folders.Count < 2) { @out.WriteLine(L.T("Errore: --merge richiede almeno due cartelle di sessione")); return Task.FromResult(ExitUsage); }
            var merged = SessionMergeRunner.Run(folders, outputFolder, m => @out.WriteLine(m));
            @out.WriteLine(L.F("Sessione fusa: {0}", merged.Folder));
            int vuln = merged.Results.Count(r => r.Verdict is Verdict.VulnerableByVersion or Verdict.LikelyVulnerable);
            return Task.FromResult(vuln > 0 ? ExitVulnerable : merged.Results.Any(r => r.Verdict == Verdict.Undetermined) ? ExitUndetermined : ExitClean);
        }
        catch (Exception ex) { @out.WriteLine(L.F("Errore: {0}", ex.Message)); return Task.FromResult(ExitError); }
    }
}
