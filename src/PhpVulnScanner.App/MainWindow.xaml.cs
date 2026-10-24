using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using Microsoft.Win32;
using PhpVulnScanner.Core;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.App;

/// <summary>Riga della tabella dei risultati.</summary>
public sealed record ResultRow(string Started, string Ip, string Name, string Port, string Alive, string Php, string Version, string Sapi, string App, string Surface, string Multipart, string Waf, string Verdict, string PriorityText, string Duration, string CycleText, string Reason, string Severity, ScanResult Result)
{
    /// <summary>v1.6: referente dall'inventario (vuoto senza inventario) e stato del certificato.</summary>
    public string Owner => Result.InventoryOwner.Length > 0 ? Result.InventoryOwner + (Result.InventoryStatus is "versione diversa" or "dichiarato, PHP non osservato" ? " ⚠" : "") : "";
    public string Certificate => Result.CertificateStatus;
    public long StartedTicks => Result.StartedLocal.Ticks;
    public string SortKey => Result.SortKey;
    public int PortNumber => Result.Port;
    public int PriorityOrder => (int)Result.Priority;
    public double DurationMs => Result.DurationMs;
    public int SurfaceCount => Result.PhpSurface.Count;
    public int CycleNumber => Result.Cycle;
    public string Key => Result.Key;
    public string NameSort => Name.ToLowerInvariant();
}

public partial class MainWindow : Window
{
    private static CultureInfo C => L.Culture;
    private readonly UiSettings _settings = UiSettings.Current;
    private readonly ObservableCollection<ResultRow> _rows = [];
    private readonly StringBuilder _logBuffer = new();
    private CancellationTokenSource? _cts;
    private ScanSession? _session;
    private bool _running;
    private ICollectionView? _view;
    private string _kpiFilter = "";
    private readonly List<string> _configWarnings = [];
    private readonly Dictionary<string, ResultRow> _rowsByKey = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<ScanResult> _pending = new();
    private readonly object _pendingLock = new();
    private readonly System.Windows.Threading.DispatcherTimer _flush = new() { Interval = TimeSpan.FromMilliseconds(300) };
    private ScanProgress? _progress;
    private bool _consolidateRows;
    private int _lastTotal;

    public MainWindow()
    {
        InitializeComponent();
        TxtVersion.Text = "v" + AppPaths.Version;
        TxtState.Text = L.T("Pronto");
        _view = CollectionViewSource.GetDefaultView(_rows);
        _view.Filter = RowPassesFilter;
        _view.SortDescriptions.Add(new SortDescription(nameof(ResultRow.SortKey), ListSortDirection.Ascending));
        _view.SortDescriptions.Add(new SortDescription(nameof(ResultRow.PortNumber), ListSortDirection.Ascending));
        GridResults.ItemsSource = _view;
        _flush.Tick += (_, _) => FlushPending();
        FillFilterCombos();
        if (_settings.WindowWidth > 400 && _settings.WindowHeight > 300) { Width = _settings.WindowWidth; Height = _settings.WindowHeight; }
        LoadConfig(_settings.Config);
        foreach (var m in App.LanguageMessages) AppendLog(m);
        Closing += (_, _) => { if (_running) _cts?.Cancel(); SaveSettings(); };
        AppendLog(L.F("PHP Vuln Scanner v{0}. Uso responsabile: scansionare solo sistemi propri o con autorizzazione scritta.", AppPaths.Version));
    }

    // =====================================================================================
    // Configurazione <-> interfaccia
    // =====================================================================================

    private void LoadConfig(ScanConfig c)
    {
        TxtTargets.Text = c.TargetsText;
        TxtPorts.Text = c.PortsText;
        TxtPaths.Text = c.PathsText.Replace("\n", " ").Replace("\r", "");
        TxtHostHeader.Text = c.HostHeader;
        TxtResolver.Text = c.ResolverIp;
        ChkAlive.IsChecked = c.Alive.Enabled;
        ChkIcmp.IsChecked = c.Alive.Icmp;
        TxtAliveTcp.Text = string.Join(",", c.Alive.TcpPorts);
        TxtAliveUdp.Text = string.Join(",", c.Alive.UdpPorts);
        TxtAliveTimeout.Text = c.Alive.TimeoutMs.ToString(C);
        TxtAliveParallel.Text = c.Alive.Parallel.ToString(C);
        ChkAliveRetry.IsChecked = c.Alive.Retry;
        ChkSkipNotAlive.IsChecked = c.Alive.SkipIfNotAlive;
        ChkInfoPages.IsChecked = c.Level1InfoPages;
        ChkEasterEgg.IsChecked = c.Level1EasterEgg;
        ChkLight.IsChecked = c.LightMode;
        ChkLevel2.IsChecked = c.Level2;
        TxtSizeKiB.Text = c.SizeProbeKiB.ToString(C);
        ChkWaf.IsChecked = c.WafDetect;
        ChkWafBehaviour.IsChecked = c.WafBehaviour;
        TxtConnectTimeout.Text = c.ConnectTimeoutMs.ToString(C);
        TxtReadTimeout.Text = c.ReadTimeoutMs.ToString(C);
        TxtThreads.Text = c.Threads.ToString(C);
        TxtLabel.Text = c.SessionLabel;
        CmbCsv.SelectedIndex = c.CsvDialect == CsvDialect.Standard ? 1 : 0;
        TxtOutput.Text = string.IsNullOrWhiteSpace(c.OutputFolder) ? AppPaths.DefaultSessionsFolder : c.OutputFolder;
        ChkSurface.IsChecked = c.SurfaceDiscovery;
        ChkNames.IsChecked = c.DiscoverNames;
        ChkRescanNames.IsChecked = c.RescanDiscoveredNames;
        TxtMaxNames.Text = c.MaxNamesPerHost.ToString(C);
        ChkDebug.IsChecked = c.DebugMode;
        ChkReportUnreachable.IsChecked = c.ReportUnreachableDetails;
        TxtCycles.Text = c.Cycles.ToString(C);
        TxtCyclePause.Text = c.CyclePauseSec.ToString(C);
        ChkConsolidate.IsChecked = c.Consolidate;
        ChkRandom.IsChecked = c.RandomOrder;
        TxtDelayMin.Text = c.DelayMinMs.ToString(C);
        TxtDelayMax.Text = c.DelayMaxMs.ToString(C);
        TxtRate.Text = c.MaxRequestsPerSecond.ToString(C);
        SetAdvanced(c.Advanced);
        ChkFoldNames.IsChecked = c.FoldSameContentNames;
        ChkFoldOutcome.IsChecked = c.FoldSameOutcomeNames;
        ChkPrecheck.IsChecked = c.PortPrecheck;
        TxtBudget.Text = (c.ServiceBudgetMs / 1000).ToString(C);
        TxtInventory.Text = c.InventoryPath;
        ChkPureVersion.IsChecked = c.PureVersionIsVulnerable;
        ChkAlive_Changed(this, new RoutedEventArgs());
        ChkNames_Changed(this, new RoutedEventArgs());
    }

    private void ChkNames_Changed(object sender, RoutedEventArgs e)
    {
        bool on = ChkNames.IsChecked == true;
        if (ChkRescanNames != null) ChkRescanNames.IsEnabled = on;
        if (TxtMaxNames != null) TxtMaxNames.IsEnabled = on;
    }

    private void ChkAlive_Changed(object sender, RoutedEventArgs e)
    {
        bool on = ChkAlive.IsChecked == true;
        if (PanelAlive != null) PanelAlive.IsEnabled = on;
        if (ChkSkipNotAlive != null) ChkSkipNotAlive.IsEnabled = on;
    }

    private ScanConfig ReadConfig()
    {
        _configWarnings.Clear();
        var c = new ScanConfig
        {
            TargetsText = TxtTargets.Text,
            PortsText = TxtPorts.Text.Trim(),
            PathsText = TxtPaths.Text.Trim(),
            HostHeader = TxtHostHeader.Text.Trim(),
            ResolverIp = TxtResolver.Text.Trim(),
            Level1InfoPages = ChkInfoPages.IsChecked == true,
            Level1EasterEgg = ChkEasterEgg.IsChecked == true,
            LightMode = ChkLight.IsChecked == true,
            Level2 = ChkLevel2.IsChecked == true,
            SizeProbeKiB = Int(TxtSizeKiB, 256),
            WafDetect = ChkWaf.IsChecked == true,
            WafBehaviour = ChkWafBehaviour.IsChecked == true,
            ConnectTimeoutMs = Int(TxtConnectTimeout, 3000),
            ReadTimeoutMs = Int(TxtReadTimeout, 8000),
            Threads = Int(TxtThreads, 8),
            SessionLabel = TxtLabel.Text.Trim(),
            CsvDialect = CmbCsv.SelectedIndex == 1 ? CsvDialect.Standard : CsvDialect.ExcelItalian,
            OutputFolder = string.IsNullOrWhiteSpace(TxtOutput.Text) ? AppPaths.DefaultSessionsFolder : TxtOutput.Text.Trim(),
            SurfaceDiscovery = ChkSurface.IsChecked == true,
            DiscoverNames = ChkNames.IsChecked == true,
            RescanDiscoveredNames = ChkNames.IsChecked == true && ChkRescanNames.IsChecked == true,
            MaxNamesPerHost = Int(TxtMaxNames, 10),
            DebugMode = ChkDebug.IsChecked == true,
            ReportUnreachableDetails = ChkReportUnreachable.IsChecked == true,
            Cycles = Int(TxtCycles, 1),
            CyclePauseSec = Int(TxtCyclePause, 60),
            Consolidate = ChkConsolidate.IsChecked == true,
            RandomOrder = ChkRandom.IsChecked == true,
            DelayMinMs = Int(TxtDelayMin, 0),
            DelayMaxMs = Int(TxtDelayMax, 0),
            MaxRequestsPerSecond = Int(TxtRate, 0),
            Advanced = ReadAdvanced(),
            FoldSameContentNames = ChkFoldNames.IsChecked == true,
            FoldSameOutcomeNames = ChkFoldOutcome.IsChecked == true,
            PortPrecheck = ChkPrecheck.IsChecked == true,
            ServiceBudgetMs = Math.Max(0, Int(TxtBudget, 120)) * 1000,
            InventoryPath = TxtInventory.Text.Trim(),
            PureVersionIsVulnerable = ChkPureVersion.IsChecked == true,
        };
        if (c.DelayMaxMs < c.DelayMinMs) _configWarnings.Add(L.F("pausa massima {0} ms inferiore alla minima {1} ms: uso la minima", c.DelayMaxMs, c.DelayMinMs));
        c.Alive.Enabled = ChkAlive.IsChecked == true;
        c.Alive.Icmp = ChkIcmp.IsChecked == true;
        c.Alive.TcpPorts = TargetParser.ParsePorts(TxtAliveTcp.Text, out var badTcp);
        if (badTcp.Count > 0) _configWarnings.Add(L.F("porte TCP dell'alive check ignorate: {0}", string.Join(", ", badTcp)));
        c.Alive.UdpPorts = TargetParser.ParsePorts(TxtAliveUdp.Text, out var badUdp);
        if (badUdp.Count > 0) _configWarnings.Add(L.F("porte UDP dell'alive check ignorate: {0}", string.Join(", ", badUdp)));
        c.Alive.TimeoutMs = Int(TxtAliveTimeout, 1500);
        c.Alive.Parallel = Int(TxtAliveParallel, 8);
        c.Alive.Retry = ChkAliveRetry.IsChecked == true;
        c.Alive.SkipIfNotAlive = ChkSkipNotAlive.IsChecked == true;
        c.Clamp();
        return c;
    }

    /// <summary>Numero intero dal campo; un valore non valido viene segnalato (mai ignorato in silenzio) e sostituito dal predefinito.</summary>
    private int Int(TextBox tb, int fallback)
    {
        if (int.TryParse(tb.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int v)) return v;
        if (tb.Text.Trim().Length > 0) _configWarnings.Add(L.F("valore non numerico \"{0}\" nel campo {1}: uso {2}", tb.Text.Trim(), tb.ToolTip as string ?? tb.Name, fallback));
        return fallback;
    }

    private void SaveSettings()
    {
        _settings.Config = ReadConfig();
        _settings.WindowWidth = Width;
        _settings.WindowHeight = Height;
        _settings.Save();
    }

    // =====================================================================================
    // Avvio / arresto
    // =====================================================================================

    private async void BtnStart_Click(object sender, RoutedEventArgs e)
    {
        if (_running) return;
        var cfg = ReadConfig();
        if (_configWarnings.Count > 0)
        {
            foreach (var w in _configWarnings) AppendLog(L.F("Avviso: {0}", w));
            if (MessageBox.Show(this, L.F("Alcuni valori non sono validi e verranno sostituiti o ignorati:\n\n{0}\n\nContinuare?", string.Join("\n", _configWarnings)),
                    "PHP Vuln Scanner", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        }
        var parsed = TargetParser.Parse(cfg.TargetsText);
        if (parsed.Targets.Count == 0)
        {
            Error(parsed.Errors.Count > 0 ? L.T("Nessun bersaglio valido.") + "\n" + string.Join("\n", parsed.Errors) : L.T("Inserire almeno un bersaglio."));
            return;
        }
        if (parsed.Errors.Count > 0 &&
            MessageBox.Show(this, L.F("{0} voci non valide saranno ignorate:\n{1}\n\nContinuare?", parsed.Errors.Count, string.Join("\n", parsed.Errors.Take(10))),
                "PHP Vuln Scanner", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        var ports = TargetParser.ParsePorts(cfg.PortsText, out var portErrors);
        if (ports.Count == 0) { Error(L.T("Indicare almeno una porta TCP valida (es. 443).")); return; }
        if (portErrors.Count > 0) AppendLog(L.F("Porte ignorate: {0}", string.Join(", ", portErrors)));
        int total = parsed.Targets.Count * ports.Count;
        if (total > 2000 &&
            MessageBox.Show(this, L.F("La scansione riguarda {0} coppie bersaglio/porta. Continuare?", total), "PHP Vuln Scanner", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;

        SaveSettings();
        ClearRows();
        _session = null;
        _progress = null;
        _consolidateRows = cfg.Cycles > 1 && cfg.Consolidate;
        bool separate = cfg.Cycles > 1 && !cfg.Consolidate;
        UpdateKpis();
        SetRunning(true);
        Progress.Value = 0;
        TxtEta.Text = "";
        TxtStatus.Text = L.F("{0} bersagli × {1} porte", parsed.Targets.Count, ports.Count) + (cfg.Cycles > 1 ? L.F(" × {0} cicli", cfg.Cycles) : "");
        KpiDone.Text = $"0 / {total}";
        _lastTotal = total;

        var engine = new ScanEngine();
        _engine = engine;
        engine.Log += m => Dispatcher.BeginInvoke(() => AppendLog(m));
        engine.ResultReady += r => { lock (_pendingLock) _pending.Enqueue(r); };
        engine.Progress += p => { _progress = p; };
        engine.CycleStarted += (c, n, sess) => Dispatcher.BeginInvoke(() =>
        {
            FlushPending();
            if (separate && c > 1) ClearRows();
            KpiDoneLabel.Text = n > 1 ? L.F("Completati (ciclo {0} di {1})", c, n) : L.T("Completati");
            UpdateKpis();
        });
        engine.CycleCompleted += sess => Dispatcher.BeginInvoke(() =>
        {
            if (!separate || sess.Results.Count == 0) return;
            try { AppendLog(L.F("Report HTML: {0}", ReportGenerator.Generate(sess))); }
            catch (Exception ex) { AppendLog(L.F("Report non generato: {0}", ex.Message)); }
        });
        _cts = new CancellationTokenSource();
        Native.KeepAwake(true);
        _flush.Start();
        try
        {
            _session = await engine.RunAsync(cfg, _cts.Token);
            FlushPending();
            switch (_session.Status)
            {
                case ScanStatus.Completed: TxtState.Text = L.T("Completata"); break;
                case ScanStatus.Stopped: TxtState.Text = L.T("Interrotta"); break;
                default: TxtState.Text = L.T("Errore"); break;
            }
            TxtStatus.Text = L.F("Sessione: {0}", _session.Folder);
            TxtEta.Text = "";
            if (!separate && _session.Results.Count > 0)
            {
                try
                {
                    var report = ReportGenerator.Generate(_session);
                    AppendLog(L.F("Report HTML: {0}", report));
                }
                catch (Exception ex) { AppendLog(L.F("Report non generato: {0}", ex.Message)); }
            }
        }
        catch (ArgumentException ex) { Error(ex.Message); TxtState.Text = L.T("Pronto"); }
        catch (Exception ex) { Error(L.F("Errore: {0}", ex.Message)); TxtState.Text = L.T("Errore"); }
        finally
        {
            _flush.Stop();
            FlushPending();
            Native.KeepAwake(false);
            SetRunning(false);
        }
    }

    private void ClearRows()
    {
        _rows.Clear();
        _rowsByKey.Clear();
        lock (_pendingLock) _pending.Clear();
    }

    /// <summary>Porta in tabella i risultati arrivati (a lotti, ogni 300 ms: con migliaia di righe un aggiornamento per risultato bloccherebbe l'interfaccia) e aggiorna avanzamento e stima.</summary>
    private void FlushPending()
    {
        List<ScanResult> batch;
        lock (_pendingLock) { if (_pending.Count == 0) batch = []; else { batch = [.. _pending]; _pending.Clear(); } }
        if (batch.Count > 0)
        {
            // Nessun DeferRefresh: una ListCollectionView ordinata rifiuta le modifiche alla collezione mentre il refresh è rinviato
            // (InvalidOperationException "Impossibile modificare … durante il rinvio di un Refresh", crash della v1.3 alla prima riga).
            // L'inserimento riga per riga su una vista ordinata è una ricerca binaria: la v1.2 reggeva così 16.000 righe.
            foreach (var r in batch)
            {
                var row = ToRow(r);
                if (_consolidateRows && _rowsByKey.TryGetValue(r.Key, out var old))
                {
                    int i = _rows.IndexOf(old);
                    if (i >= 0) _rows[i] = row; else _rows.Add(row);
                }
                else _rows.Add(row);
                _rowsByKey[r.Key] = row;
            }
            UpdateKpis();
        }
        var p = _progress;
        if (p != null)
        {
            Progress.Value = p.Total > 0 ? Math.Min(1, (double)p.Done / p.Total) : 0;
            KpiDone.Text = $"{p.Done} / {p.Total}";
            _lastTotal = p.Total;
            string eta;
            if (p.Done >= p.Total && p.Total > 0) eta = "";
            else if (!p.RateReliable) eta = L.F("{0:F1} coppie/s · stima in calcolo", p.RatePerSec);
            else
            {
                eta = L.F("{0:F1} coppie/s · fine ciclo {1:HH:mm} (+{2})", p.RatePerSec, p.CycleEtaLocal, ScanEstimator.Duration(p.CycleRemainingSec ?? 0));
                if (p.Cycles > 1 && p.LoopEtaLocal is DateTime l) eta += L.F(" · fine loop {0:HH:mm} (+{1})", l, ScanEstimator.Duration(p.LoopRemainingSec ?? 0));
            }
            TxtEta.Text = eta;
        }
    }

    private ScanEngine? _engine;

    private void BtnPause_Click(object sender, RoutedEventArgs e)
    {
        if (!_running || _engine == null) return;
        if (_engine.Pause.IsPaused)
        {
            var d = _engine.Pause.Resume();
            BtnPause.Content = L.T("❚❚  Pausa");
            TxtState.Text = L.T("In corso…");
            AppendLog(L.F("Ripresa dopo {0} di pausa", ScanEstimator.Duration(d.TotalSeconds)));
        }
        else
        {
            _engine.Pause.Pause();
            BtnPause.Content = L.T("▶  Riprendi");
            TxtState.Text = L.T("In pausa");
            AppendLog(L.T("Pausa richiesta: le richieste in volo finiscono, poi nessun nuovo host o richiesta fino alla ripresa"));
        }
    }

    private void BtnAdvDefaults_Click(object sender, RoutedEventArgs e) => SetAdvanced(new AdvancedOptions());   // predefiniti della v1.4: tutti tranne User-Agent da browser, CT e livello 2 su ogni .php
    private void BtnAdvNone_Click(object sender, RoutedEventArgs e) => SetAdvanced(new AdvancedOptions().Also(o => o.SetAll(false)));
    private void BtnAdvMax_Click(object sender, RoutedEventArgs e)
    {
        SetAdvanced(new AdvancedOptions().Also(o => o.SetAll(true)));
        ChkSurface.IsChecked = true; ChkNames.IsChecked = true; ChkRescanNames.IsChecked = true; ChkInfoPages.IsChecked = true; ChkEasterEgg.IsChecked = true; ChkLevel2.IsChecked = true; ChkWaf.IsChecked = true; ChkWafBehaviour.IsChecked = true; ChkLight.IsChecked = false;
        ExpAdvanced.IsExpanded = true;
    }

    private void SetAdvanced(AdvancedOptions o)
    {
        AdvHeadVsGet.IsChecked = o.HeadVsGet; AdvComposer.IsChecked = o.Composer; AdvStatus.IsChecked = o.StatusPages; AdvAppVersion.IsChecked = o.AppVersionFiles;
        AdvFastCgi.IsChecked = o.FastCgiProbe; AdvBehaviours.IsChecked = o.PhpBehaviours; AdvLevel2All.IsChecked = o.Level2AllPaths; TxtLevel2Max.Text = o.Level2MaxPaths.ToString(C);
        AdvBrowserUa.IsChecked = o.BrowserUserAgent; AdvComponents.IsChecked = o.Components; AdvExposures.IsChecked = o.Exposures; AdvPtr.IsChecked = o.ReverseDns; AdvCt.IsChecked = o.CertificateTransparency; AdvSessionId.IsChecked = o.SessionIdProbe;
    }

    private AdvancedOptions ReadAdvanced() => new()
    {
        HeadVsGet = AdvHeadVsGet.IsChecked == true, Composer = AdvComposer.IsChecked == true, StatusPages = AdvStatus.IsChecked == true, AppVersionFiles = AdvAppVersion.IsChecked == true,
        FastCgiProbe = AdvFastCgi.IsChecked == true, PhpBehaviours = AdvBehaviours.IsChecked == true, Level2AllPaths = AdvLevel2All.IsChecked == true, Level2MaxPaths = Int(TxtLevel2Max, 5),
        BrowserUserAgent = AdvBrowserUa.IsChecked == true, Components = AdvComponents.IsChecked == true, Exposures = AdvExposures.IsChecked == true, ReverseDns = AdvPtr.IsChecked == true, CertificateTransparency = AdvCt.IsChecked == true, SessionIdProbe = AdvSessionId.IsChecked == true,
    };

    private void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        if (!_running) return;
        AppendLog(L.T("Interruzione richiesta: i risultati già completati restano salvati…"));
        _cts?.Cancel();
        BtnStop.IsEnabled = false;
    }

    private void SetRunning(bool on)
    {
        _running = on;
        BtnStart.IsEnabled = !on;
        BtnStop.IsEnabled = on;
        BtnPause.IsEnabled = on;
        if (!on) BtnPause.Content = L.T("❚❚  Pausa");
        BtnMerge.IsEnabled = !on;
        BtnUpdateData.IsEnabled = !on;
        BtnOpenFolder.IsEnabled = _session != null && Directory.Exists(_session.Folder);
        BtnReport.IsEnabled = !on && _session is { Results.Count: > 0 };
        BtnExportLog.IsEnabled = !on && (_logBuffer.Length > 0 || _session != null);
        BtnOpenSession.IsEnabled = !on;
        if (on) { TxtState.Text = L.T("In corso…"); BtnOpenFolder.IsEnabled = false; }
    }

    // =====================================================================================
    // Risultati e log
    // =====================================================================================

    /// <summary>Colonna Nome: il nome della riga; altrimenti i nomi ripiegati (stesso contenuto, stesso esito) con la nota.</summary>
    private static string NameCell(ScanResult r)
    {
        if (r.DisplayName.Length > 0)
        {
            int folded = r.SameContentNames.Count + r.SameOutcomeNames.Count;
            return folded > 0 ? r.DisplayName + " " + L.F("(+{0} nomi)", folded) : r.DisplayName;
        }
        var parts = new List<string>();
        if (r.SameContentNames.Count > 0) parts.Add(string.Join(", ", r.SameContentNames) + " " + L.T("(= vhost predefinito)"));
        if (r.SameOutcomeNames.Count > 0) parts.Add(string.Join(", ", r.SameOutcomeNames) + " " + L.T("(= stesso esito)"));
        return string.Join("; ", parts);
    }

    private static ResultRow ToRow(ScanResult r) => new(
        Stamp.Local(r.StartedLocal),
        r.DisplayIp,
        NameCell(r),
        r.Port + (r.Scheme.Length > 0 ? " " + r.Scheme : ""),
        Labels.Alive(r.Alive) + (r.AliveMethod.Length > 0 ? " " + r.AliveMethod : ""),
        r.PhpDetected ? L.T("sì") : r.PhpPresence == "maybe" ? L.T("forse") : r.HttpReachable ? L.T("no") : "–",
        r.PhpVersionRaw.Length > 0 ? r.PhpVersionRaw : "–",
        r.Sapi.Length > 0 ? Labels.Sapi(r.Sapi) : "–",
        r.Application.Length > 0 ? r.Application + (r.ApplicationVersion.Length > 0 ? " " + r.ApplicationVersion : "") : "–",
        r.PhpSurface.Count > 0 ? r.PhpSurface.Count.ToString(C) : r.HttpReachable ? "0" : "–",
        Labels.Multipart(r.Multipart) + (r.VariantsBlocked >= 0 ? $" ({r.VariantsBlocked}/{r.VariantsTotal})" : ""),
        r.WafSummary.Length > 0 ? r.WafSummary : "–",
        Labels.Verdict(r.Verdict), Labels.Priority(r.Priority), r.DurationMs.ToString("F0", C),
        r.History.Count > 1 ? (ResultMerger.VerdictChanged(r) ? "Δ " : "") + r.Cycle.ToString(C) + "/" + r.History.Count.ToString(C) : r.Cycle.ToString(C),
        r.VerdictReason, r.PhpPresence == "maybe" && !r.PhpDetected && r.HttpReachable ? "maybe" : Labels.VerdictClass(r.Verdict), r);   // v1.7: riga "forse" in lilla

    /// <summary>Riga "attiva": host confermato dall'alive check o, con alive check spento, con una risposta.</summary>
    /// <summary>Riga "PHP forse" (v1.7): HTTP risponde, nessuna prova di PHP, indizi passivi sopra soglia (stessa regola del report compatto).</summary>
    private static bool IsMaybeRow(ScanResult r) => CompactReportGenerator.IsPhpSuspect(r);

    private static bool IsAliveRow(ScanResult r) => r.Alive == AliveState.Alive || (r.Alive == AliveState.NotTested && (r.HttpReachable || r.Tls is { Handshake: true }));

    private void UpdateKpis()
    {
        var counts = new int[Enum.GetValues<Verdict>().Length];
        var hostsBy = new HashSet<string>[counts.Length];
        for (int i = 0; i < hostsBy.Length; i++) hostsBy[i] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var alive = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var http = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int maybe = 0;
        var maybeHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var x in _rows)
        {
            if (IsMaybeRow(x.Result)) { maybe++; maybeHosts.Add(x.Result.DisplayIp); }
            counts[(int)x.Result.Verdict]++;
            hostsBy[(int)x.Result.Verdict].Add(x.Result.DisplayIp);
            hosts.Add(x.Result.DisplayIp);
            if (IsAliveRow(x.Result)) alive.Add(x.Result.DisplayIp);
            if (x.Result.HttpReachable) http.Add(x.Result.DisplayIp);
        }
        string Hosts(Verdict v) => counts[(int)v] > 0 ? L.F("su {0} host", hostsBy[(int)v].Count) : "";
        KpiVulnHosts.Text = Hosts(Verdict.VulnerableByVersion); KpiLikelyHosts.Text = Hosts(Verdict.LikelyVulnerable); KpiUndetHosts.Text = Hosts(Verdict.Undetermined);
        KpiMitigHosts.Text = Hosts(Verdict.MitigatedAtEdge); KpiFixedHosts.Text = Hosts(Verdict.FixedByVersion); KpiNoPhpHosts.Text = Hosts(Verdict.NoPhpDetected);
        KpiMaybe.Text = maybe.ToString(C); KpiMaybeHosts.Text = maybe > 0 ? L.F("su {0} host", maybeHosts.Count) : ""; KpiUnreachHosts.Text = Hosts(Verdict.NotReachable);
        KpiAliveSub.Text = alive.Count > 0 ? L.F("{0} con HTTP", http.Count) : "";
        KpiVuln.Text = counts[(int)Verdict.VulnerableByVersion].ToString(C);
        KpiLikely.Text = counts[(int)Verdict.LikelyVulnerable].ToString(C);
        KpiUndet.Text = counts[(int)Verdict.Undetermined].ToString(C);
        KpiMitig.Text = counts[(int)Verdict.MitigatedAtEdge].ToString(C);
        KpiFixed.Text = counts[(int)Verdict.FixedByVersion].ToString(C);
        KpiNoPhp.Text = counts[(int)Verdict.NoPhpDetected].ToString(C);
        KpiUnreach.Text = counts[(int)Verdict.NotReachable].ToString(C);
        KpiAlive.Text = alive.Count.ToString(C) + (hosts.Count > 0 ? " / " + hosts.Count.ToString(C) : "");
        UpdateFilterCount();
    }

    // =====================================================================================
    // Filtri (riquadri KPI e barra dei filtri) e ordinamento
    // =====================================================================================

    // v1.5: tendine a scelta multipla (OR dentro la tendina, AND tra tendine e con il testo libero) e linguaggio del filtro (ResultFilter).
    private readonly ObservableCollection<MultiSelectItem> _verdictItems = [];
    private readonly ObservableCollection<MultiSelectItem> _priorityItems = [];
    private readonly ObservableCollection<MultiSelectItem> _aliveItems = [];
    private readonly ObservableCollection<MultiSelectItem> _barrierItems = [];
    private ResultFilter _filter = ResultFilter.Parse("");
    private object? _filterTipDefault;
    private System.Windows.Media.Brush? _filterBgDefault;
    private bool _fillingFilters;

    private void FillFilterCombos()
    {
        _fillingFilters = true;
        try
        {
            Fill(CmbFilterVerdict, _verdictItems, Enum.GetValues<Verdict>().Select(v => new MultiSelectItem(v.ToString(), Labels.Verdict(v))).Append(new MultiSelectItem("maybe", L.T("PHP forse"))));   // v1.8: "forse" in OR con i verdetti
            Fill(CmbFilterPriority, _priorityItems, Enum.GetValues<Priority>().Reverse().Select(p => new MultiSelectItem(p.ToString(), Labels.Priority(p))));
            Fill(CmbFilterAlive, _aliveItems, Enum.GetValues<AliveState>().Select(a => new MultiSelectItem(a.ToString(), Labels.Alive(a))));
            Fill(CmbFilterBarrier, _barrierItems, Enum.GetValues<MultipartBarrier>().Select(m => new MultiSelectItem(m.ToString(), Labels.Multipart(m))));
        }
        finally { _fillingFilters = false; }
        _filterTipDefault = TxtFilter.ToolTip;
        _filterBgDefault = TxtFilter.Background;
        UpdateMultiSelectHeaders();

        void Fill(ComboBox cmb, ObservableCollection<MultiSelectItem> items, IEnumerable<MultiSelectItem> source)
        {
            items.Clear();
            foreach (var it in source) { it.PropertyChanged += MultiSelectItem_Changed; items.Add(it); }
            cmb.ItemsSource = items;
            cmb.SelectedIndex = -1;
        }
    }

    private void MultiSelectItem_Changed(object? sender, PropertyChangedEventArgs e)
    {
        if (_fillingFilters) return;
        UpdateMultiSelectHeaders();
        HighlightKpi();
        RefreshFilter();
    }

    /// <summary>Testo sopra la tendina: "Verdetto: (tutti)" oppure "Verdetto: Vulnerabile per versione, Probabilmente vulnerabile (2)".</summary>
    private void UpdateMultiSelectHeaders()
    {
        if (LblFilterVerdict == null) return;
        LblFilterVerdict.Text = Header(L.T("Verdetto"), _verdictItems);
        LblFilterPriority.Text = Header(L.T("Priorità"), _priorityItems);
        LblFilterAlive.Text = Header(L.T("Alive"), _aliveItems);
        LblFilterBarrier.Text = Header(L.T("Barriera"), _barrierItems);

        static string Header(string title, ObservableCollection<MultiSelectItem> items)
        {
            var on = items.Where(i => i.IsChecked).ToList();
            if (on.Count == 0) return title + ": " + L.T("(tutti)");
            return title + ": " + string.Join(", ", on.Select(i => i.Label)) + " (" + on.Count.ToString(C) + ")";
        }
    }

    /// <summary>Clic su una voce della tendina: inverte la spunta e ferma l'evento, così la tendina non seleziona né si chiude.</summary>
    private void MultiSelectItem_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is ComboBoxItem { DataContext: MultiSelectItem item }) { item.IsChecked = !item.IsChecked; e.Handled = true; }
    }

    /// <summary>La tendina non ha una "selezione": se qualcosa la imposta (tastiera), la si annulla e il testo di intestazione resta visibile.</summary>
    private void MultiSelect_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox cmb && cmb.SelectedIndex != -1) cmb.SelectedIndex = -1;
    }

    /// <summary>Gruppo Verdetto (v1.8): i verdetti selezionati in OR tra loro e con «PHP forse» (riga con indizi, verdetto "PHP non rilevato").</summary>
    private bool PassesVerdict(ScanResult r)
    {
        bool any = false;
        foreach (var i in _verdictItems)
        {
            if (!i.IsChecked) continue;
            any = true;
            if (i.Key == "maybe" ? IsMaybeRow(r) : i.Key == r.Verdict.ToString()) return true;
        }
        return !any;
    }

    private static bool Passes(ObservableCollection<MultiSelectItem> items, string key)
    {
        bool any = false;
        foreach (var i in items)
        {
            if (!i.IsChecked) continue;
            any = true;
            if (i.Key == key) return true;
        }
        return !any;
    }

    private static void Toggle(ObservableCollection<MultiSelectItem> items, string key)
    {
        foreach (var i in items) if (i.Key == key) { i.IsChecked = !i.IsChecked; return; }
    }

    private static bool AnyChecked(ObservableCollection<MultiSelectItem> items) => items.Any(i => i.IsChecked);
    private static void ClearChecked(ObservableCollection<MultiSelectItem> items) { foreach (var i in items) i.IsChecked = false; }

    private bool RowPassesFilter(object o)
    {
        if (o is not ResultRow row) return false;
        var r = row.Result;
        if (_kpiFilter == "alive" && !IsAliveRow(r)) return false;
        if (!PassesVerdict(r)) return false;
        if (!Passes(_priorityItems, r.Priority.ToString())) return false;
        if (!Passes(_aliveItems, r.Alive.ToString())) return false;
        if (!Passes(_barrierItems, r.Multipart.ToString())) return false;
        return _filter.Matches(r);
    }

    private void Filter_Changed(object sender, RoutedEventArgs e) => RefreshFilter();

    private void RefreshFilter()
    {
        if (_view == null) return;
        _filter = ResultFilter.Parse(TxtFilter.Text);
        if (_filter.IsValid)
        {
            TxtFilter.ToolTip = _filterTipDefault;
            if (_filterBgDefault != null) TxtFilter.Background = _filterBgDefault; else TxtFilter.ClearValue(BackgroundProperty);
        }
        else
        {
            TxtFilter.ToolTip = _filter.Error;
            TxtFilter.Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0xFD, 0xE8, 0xE8));
        }
        _view.Refresh();
        UpdateFilterCount();
    }

    private void UpdateFilterCount()
    {
        if (_view == null || TxtFilterCount == null) return;
        int shown = _view.Cast<object>().Count();
        TxtFilterCount.Text = shown == _rows.Count ? L.F("{0} righe", _rows.Count) : L.F("{0} di {1} righe", shown, _rows.Count);
    }

    private void BtnClearFilters_Click(object sender, RoutedEventArgs e)
    {
        _fillingFilters = true;      // un solo aggiornamento della vista alla fine, non uno per casella
        try
        {
            _kpiFilter = "";
            TxtFilter.Text = "";
            ClearChecked(_verdictItems); ClearChecked(_priorityItems); ClearChecked(_aliveItems); ClearChecked(_barrierItems);
        }
        finally { _fillingFilters = false; }
        UpdateMultiSelectHeaders();
        HighlightKpi();
        RefreshFilter();
    }

    /// <summary>Clic su un riquadro di verdetto: aggiunge o toglie quel verdetto nella tendina Verdetto (più riquadri = OR). «Host attivi»: filtro proprio, secondo clic: tutti.</summary>
    private void Kpi_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is not Border b || b.Tag is not string tag) return;
        if (tag == "alive")
        {
            _kpiFilter = _kpiFilter == "alive" ? "" : "alive";
            HighlightKpi();
            RefreshFilter();
            return;
        }
        Toggle(_verdictItems, tag);     // MultiSelectItem_Changed aggiorna intestazione, riquadri e vista
    }

    private void HighlightKpi()
    {
        var accent = (System.Windows.Media.Brush)FindResource("Accent");
        var line = (System.Windows.Media.Brush)FindResource("Line");
        foreach (var b in FindKpis())
        {
            string tag = (string?)b.Tag ?? "";
            bool on = tag == "alive" ? _kpiFilter == "alive" : _verdictItems.Any(i => i.IsChecked && i.Key == tag);
            b.BorderBrush = on ? accent : line;
        }
    }

    private IEnumerable<Border> FindKpis()
    {
        if (KpiVuln.Parent is StackPanel sp && sp.Parent is Border first && first.Parent is Panel panel)
            foreach (var child in panel.Children) if (child is Border b && b.Tag is string) yield return b;
    }

    /// <summary>Ordinamento per colonna: "Bersaglio" per valore numerico dell'IP (SortKey), le altre per il valore reale.</summary>
    private void GridResults_Sorting(object sender, DataGridSortingEventArgs e)
    {
        if (_view == null) return;
        e.Handled = true;
        var dir = e.Column.SortDirection == ListSortDirection.Ascending ? ListSortDirection.Descending : ListSortDirection.Ascending;
        e.Column.SortDirection = dir;
        foreach (var col in GridResults.Columns) if (col != e.Column) col.SortDirection = null;
        string member = e.Column.SortMemberPath;
        if (string.IsNullOrEmpty(member)) member = (e.Column as DataGridBoundColumn)?.Binding is Binding bd ? bd.Path.Path : nameof(ResultRow.SortKey);
        _view.SortDescriptions.Clear();
        _view.SortDescriptions.Add(new SortDescription(member, dir));
        if (member != nameof(ResultRow.PortNumber)) _view.SortDescriptions.Add(new SortDescription(nameof(ResultRow.PortNumber), ListSortDirection.Ascending));
        _view.Refresh();
    }

    private void AppendLog(string message)
    {
        string line = $"{Stamp.LogNow()} {message}";
        _logBuffer.AppendLine(line);
        TxtLog.AppendText(line + Environment.NewLine);
        if (TxtLog.LineCount > 5000)
        {
            // il log completo resta in scan.log: a video si tengono le ultime righe
            TxtLog.Text = string.Join(Environment.NewLine, TxtLog.Text.Split(Environment.NewLine).Skip(1000));
        }
        TxtLog.ScrollToEnd();
    }

    private void BtnClearLog_Click(object sender, RoutedEventArgs e) => TxtLog.Clear();

    /// <summary>Doppio clic su una riga: tutte le evidenze del bersaglio in una finestra di testo copiabile.</summary>
    private void GridResults_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (GridResults.SelectedItem is not ResultRow row) return;
        var r = row.Result;
        var sb = new StringBuilder();
        sb.AppendLine($"{r.Display}:{r.Port} {r.Scheme}");
        sb.AppendLine($"{L.T("Verdetto")}: {Labels.Verdict(r.Verdict)}");
        sb.AppendLine($"{L.T("Motivazione")}: {r.VerdictReason}");
        sb.AppendLine($"{L.T("Avvio")}: {Stamp.Local(r.StartedLocal)}");
        sb.AppendLine($"{L.T("Durata")}: {r.DurationMs:F0} ms ({r.PhaseSummary})");
        sb.AppendLine($"{L.T("Priorità")}: {Labels.Priority(r.Priority)}");
        if (r.AliveMethods.Length > 0) sb.AppendLine($"{L.T("Alive check")}: {Labels.Alive(r.Alive)}: {r.AliveMethods}");
        if (r.SapiEvidence.Length > 0) sb.AppendLine($"SAPI: {(r.Sapi.Length > 0 ? Labels.Sapi(r.Sapi) + ": " : "")}{r.SapiEvidence}");
        if (r.OsHint.Length > 0) sb.AppendLine($"{L.T("Sistema operativo dichiarato")}: {r.OsHint}");
        if (r.Application.Length > 0) sb.AppendLine($"{L.T("Applicazione")}: {r.Application}{(r.ApplicationVersion.Length > 0 ? " " + r.ApplicationVersion : "")} ({r.ApplicationEvidence}) – {r.ApplicationReference}");
        if (r.NcscStatus.Length > 0) sb.AppendLine($"{L.T("Stato NCSC-NL per CVE")}: {r.NcscStatus} – {r.NcscReference}");
        if (r.Technologies.Count > 0) sb.AppendLine($"{L.T("Tecnologie riconosciute")}: {string.Join(", ", r.Technologies)}");
        if (r.ResolvedIps.Count > 0) sb.AppendLine($"{L.T("Indirizzi")}: {string.Join(", ", r.ResolvedIps)}");
        if (r.PhpVersionRaw.Length > 0) sb.AppendLine($"{L.T("Versione PHP")}: {r.PhpVersionRaw} ({r.PhpVersionSource}; {Labels.VersionStatus(r.VersionStatus)})");
        if (r.PhpEvidence.Length > 0) sb.AppendLine($"{L.T("Indizi di PHP")}: {r.PhpEvidence}");
        if (r.Tls is { Handshake: true }) sb.AppendLine($"TLS: {r.Tls.Summary}");
        if (r.DiscoveredNames.Count > 0) sb.AppendLine($"{L.T("Nomi scoperti")}: {string.Join(", ", r.DiscoveredNames)}");
        if (r.PhpSurface.Count > 0) sb.AppendLine($"{L.T("Superficie PHP")}: {string.Join(", ", r.PhpSurface)}");
        if (r.History.Count > 0) sb.AppendLine($"{L.T("Storia dei cicli")}: {string.Join(" → ", r.History)}");
        if (r.Multipart != MultipartBarrier.NotTested) sb.AppendLine($"{L.T("Barriera multipart")}: {Labels.Multipart(r.Multipart)}: {r.MultipartDetail}");
        foreach (var f in r.Waf) sb.AppendLine($"{Labels.WafCategory(f.Category)}: {f.Name} ({Labels.Confidence(f.Confidence)}) – {f.Evidence}");
        sb.AppendLine();
        sb.AppendLine(L.T("Test eseguiti:"));
        foreach (var t in r.Tests)
            sb.AppendLine($"  [{Labels.Outcome(t.Outcome)}] {t.Name}: {t.Detail}{(t.Request.Length > 0 ? $"  ({t.Request} → {t.Response})" : "")}");
        var win = new Window
        {
            Title = $"{r.Display}:{r.Port}", Owner = this, Width = 900, Height = 600, WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = new TextBox { Text = sb.ToString(), IsReadOnly = true, FontFamily = new System.Windows.Media.FontFamily("Consolas"), TextWrapping = TextWrapping.Wrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, Margin = new Thickness(8), BorderThickness = new Thickness(0) },
        };
        win.ShowDialog();
    }

    // =====================================================================================
    // Esportazioni, report, sessioni
    // =====================================================================================

    private void BtnExportLog_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new SaveFileDialog
        {
            Filter = L.T("Log esteso (*.txt)|*.txt|Risultati CSV (*.csv)|*.csv|Risultati JSON (*.json)|*.json|Test eseguiti CSV (*.csv)|*.csv|Host attivi, un IP per riga (*.txt)|*.txt|Host con HTTP, un IP per riga (*.txt)|*.txt|Nomi scoperti (*.txt)|*.txt"),
            FileName = $"phpscan_{DateTime.Now:yyyyMMdd_HHmm}_v{AppPaths.Version}",
            InitialDirectory = _session?.Folder is { Length: > 0 } f && Directory.Exists(f) ? f : TxtOutput.Text,
        };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            switch (dlg.FilterIndex)
            {
                case 1:
                    File.WriteAllText(dlg.FileName, _logBuffer.ToString(), SessionFiles.Utf8Bom);
                    break;
                case 2:
                    if (_session == null) throw new InvalidOperationException(L.T("Nessuna sessione da esportare."));
                    File.WriteAllText(dlg.FileName, SessionFiles.ResultsToCsv(_session.Results, new CsvFormat(_session.Config.CsvDialect)), SessionFiles.Utf8Bom);
                    break;
                case 3:
                    if (_session == null) throw new InvalidOperationException(L.T("Nessuna sessione da esportare."));
                    File.WriteAllText(dlg.FileName, SessionFiles.ResultsToJson(_session), new UTF8Encoding(false));
                    break;
                case 4:
                    if (_session == null) throw new InvalidOperationException(L.T("Nessuna sessione da esportare."));
                    File.WriteAllText(dlg.FileName, SessionFiles.TestsToCsv(_session.Results, new CsvFormat(_session.Config.CsvDialect)), SessionFiles.Utf8Bom);
                    break;
                case 5:
                    if (_session == null) throw new InvalidOperationException(L.T("Nessuna sessione da esportare."));
                    File.WriteAllText(dlg.FileName, HostLists.AliveHostsText(_session.Results), new UTF8Encoding(false));
                    break;
                case 6:
                    if (_session == null) throw new InvalidOperationException(L.T("Nessuna sessione da esportare."));
                    File.WriteAllText(dlg.FileName, HostLists.HttpHostsText(_session.Results), new UTF8Encoding(false));
                    break;
                case 7:
                    if (_session == null) throw new InvalidOperationException(L.T("Nessuna sessione da esportare."));
                    File.WriteAllText(dlg.FileName, HostLists.DiscoveredNamesText(_session.Results), new UTF8Encoding(false));
                    break;
            }
            AppendLog(L.F("Esportato: {0}", dlg.FileName));
        }
        catch (Exception ex) { Error(L.F("Esportazione non riuscita: {0}", ex.Message)); }
    }

    private void BtnReport_Click(object sender, RoutedEventArgs e)
    {
        if (_session is not { Results.Count: > 0 }) return;
        try
        {
            string folder = Directory.Exists(_session.Folder) ? _session.Folder : TxtOutput.Text;
            Directory.CreateDirectory(folder);
            var path = ReportGenerator.Generate(_session, folder);
            AppendLog(L.F("Report HTML: {0}", path));
            OpenPath(path);
        }
        catch (Exception ex) { Error(L.F("Report non generato: {0}", ex.Message)); }
    }

    private void BtnOpenSession_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "results.json|results.json|JSON (*.json)|*.json", InitialDirectory = TxtOutput.Text };
        if (dlg.ShowDialog(this) != true) return;
        try
        {
            var s = SessionFiles.ReadSession(Path.GetDirectoryName(dlg.FileName)!) ?? throw new InvalidDataException(L.T("results.json non trovato o non valido."));
            s.Folder = Path.GetDirectoryName(dlg.FileName)!;
            foreach (var r in s.Results) VerdictEngineReapply(r);
            _session = s;
            ClearRows();
            _consolidateRows = s.Consolidated;
            foreach (var r in s.Results) { var row = ToRow(r); _rows.Add(row); _rowsByKey[r.Key] = row; }
            UpdateKpis();
            KpiDone.Text = $"{s.Results.Count} / {Math.Max(s.Results.Count, s.TargetCount * s.PortCount)}";
            KpiDoneLabel.Text = s.Cycles > 1 ? L.F("Completati (ciclo {0} di {1})", s.Cycle, s.Cycles) : L.T("Completati");
            TxtEta.Text = "";
            TxtState.Text = L.T("Sessione caricata");
            TxtStatus.Text = L.F("Sessione: {0}", s.Folder);
            AppendLog(L.F("Sessione caricata: {0} risultati da {1}", s.Results.Count, dlg.FileName));
            SetRunning(false);
        }
        catch (Exception ex) { Error(L.F("Impossibile aprire la sessione: {0}", ex.Message)); }
    }

    // =====================================================================================
    // v1.4: fusione di sessioni, aggiornamento dei dati
    // =====================================================================================

    private void BtnMerge_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { Multiselect = true, Title = L.T("Scegli due o più cartelle di sessione da fondere (stessi range)"), InitialDirectory = Directory.Exists(TxtOutput.Text) ? TxtOutput.Text : AppPaths.ExeFolder };
        if (dlg.ShowDialog(this) != true) return;
        var folders = dlg.FolderNames.ToList();
        if (folders.Count < 2) { Error(L.T("Servono almeno due cartelle di sessione (tieni premuto Ctrl per sceglierne più di una).")); return; }
        try
        {
            string outFolder = string.IsNullOrWhiteSpace(TxtOutput.Text) ? AppPaths.DefaultSessionsFolder : TxtOutput.Text.Trim();
            var merged = SessionMergeRunner.Run(folders, outFolder, AppendLog);
            _session = merged;
            ClearRows();
            _consolidateRows = true;
            foreach (var r in merged.Results) { var row = ToRow(r); _rows.Add(row); _rowsByKey[r.Key] = row; }
            UpdateKpis();
            KpiDone.Text = merged.Results.Count.ToString(C);
            KpiDoneLabel.Text = L.F("Fusione di {0} sessioni", folders.Count);
            TxtState.Text = L.T("Sessione fusa");
            TxtStatus.Text = L.F("Sessione: {0}", merged.Folder);
            SetRunning(false);
            var report = Directory.GetFiles(merged.Folder, SessionFiles.CompactReportPrefix + "_v*.html").OrderBy(f => f).FirstOrDefault();
            if (report != null) OpenPath(report);
        }
        catch (Exception ex) { Error(L.F("Fusione non riuscita: {0}", ex.Message)); }
    }

    private async void BtnUpdateData_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, L.T("Scarico da GitHub le firme delle tecnologie (enthec/webappanalyzer) e l'inventario NCSC-NL e li converto nella cartella data\\ accanto al programma. Serve accesso a internet; i file attuali vengono sostituiti solo a scaricamento riuscito. Procedo?"),
                            L.T("Aggiorna dati"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        BtnUpdateData.IsEnabled = false;
        string folder = Path.Combine(AppPaths.ExeFolder, "data");
        try
        {
            var progress = new Progress<string>(m => AppendLog(L.F("Aggiornamento dati: {0}", m)));
            var res = await PhpVulnScanner.Core.Apps.AppDbUpdater.UpdateAsync(folder, progress, CancellationToken.None);
            PhpVulnScanner.Core.Apps.TechnologyDatabase.Default = PhpVulnScanner.Core.Apps.TechnologyDatabase.TryLoad(folder);
            string summary = L.F("{0} tecnologie, {1} categorie, {2} pacchetti NCSC-NL con {3} asserzioni VEX ({4})", res.Technologies, res.Categories, res.Packages, res.Vex, res.DataVersion.Replace("\n", " | "));
            AppendLog(L.F("Dati aggiornati: {0}", summary));
            MessageBox.Show(this, summary, L.T("Aggiorna dati"), MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) { Error(L.F("Aggiornamento dei dati non riuscito (i file attuali restano): {0}", ex.Message)); }
        finally { BtnUpdateData.IsEnabled = !_running; }
    }

    /// <summary>I testi salvati restano nella lingua in cui sono stati scritti; il verdetto si ricalcola per averlo coerente con le regole attuali.</summary>
    private static void VerdictEngineReapply(ScanResult r) => VerdictEngine.Apply(r);

    private void BtnBrowseInventory_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Filter = "CSV, JSON (*.csv;*.json;*.txt)|*.csv;*.json;*.txt|" + L.T("Tutti i file") + "|*.*", Title = L.T("Scegli il file di inventario (CSV o JSON)") };
        if (dlg.ShowDialog(this) == true) TxtInventory.Text = dlg.FileName;
    }

    private void BtnBrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog { InitialDirectory = Directory.Exists(TxtOutput.Text) ? TxtOutput.Text : AppPaths.ExeFolder };
        if (dlg.ShowDialog(this) == true) TxtOutput.Text = dlg.FolderName;
    }

    // =====================================================================================
    // Lingua, guida, cartelle (stesso schema di DNS Load Tester)
    // =====================================================================================

    private void BtnLanguage_Click(object sender, RoutedEventArgs e)
    {
        var menu = new ContextMenu { PlacementTarget = BtnLanguage, Placement = PlacementMode.Bottom };
        foreach (var lang in L.Available())
        {
            var mi = new MenuItem { Header = lang.Name, IsCheckable = true, IsChecked = lang.Code.Equals(L.Code, StringComparison.OrdinalIgnoreCase) };
            mi.Click += (_, _) => ChangeLanguage(lang);
            menu.Items.Add(mi);
        }
        menu.Items.Add(new Separator());
        var folder = new MenuItem { Header = L.T("Apri la cartella delle traduzioni") };
        folder.Click += (_, _) => { Directory.CreateDirectory(L.LangDirectory); OpenPath(L.LangDirectory); };
        menu.Items.Add(folder);
        menu.IsOpen = true;
    }

    private void ChangeLanguage(LanguageInfo lang)
    {
        if (lang.Code.Equals(L.Code, StringComparison.OrdinalIgnoreCase) && _settings.Language.Length > 0) return;
        _settings.Language = lang.Code;
        SaveSettings();
        if (_running)
        {
            MessageBox.Show(this, L.F("La lingua «{0}» sarà usata al prossimo avvio del programma.", lang.Name), L.T("Lingua"), MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show(this, L.F("La lingua «{0}» sarà usata al riavvio del programma. Riavviare ora?", lang.Name), L.T("Lingua"), MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false });
            Application.Current.Shutdown();
        }
        catch (Exception ex) { Error(L.F("Riavvio non riuscito: {0}", ex.Message)); }
    }

    private void Help_Executed(object sender, ExecutedRoutedEventArgs e)
    {
        try
        {
            bool en = L.Code.Equals("en", StringComparison.OrdinalIgnoreCase);
            var path = Path.Combine(AppPaths.DataFolder, en ? $"Guide_PhpVulnScanner_v{AppPaths.Version}.html" : $"Guida_PhpVulnScanner_v{AppPaths.Version}.html");
            using var res = typeof(MainWindow).Assembly.GetManifestResourceStream(en ? "Guide.html" : "Guida.html")
                ?? throw new FileNotFoundException(L.T("Guida non presente nell'eseguibile."));
            using var ms = new MemoryStream();
            res.CopyTo(ms);
            var bytes = ms.ToArray();
            if (!File.Exists(path) || new FileInfo(path).Length != bytes.Length)
            {
                Directory.CreateDirectory(AppPaths.DataFolder);
                File.WriteAllBytes(path, bytes);
            }
            OpenPath(path);
        }
        catch (Exception ex) { Error(L.F("Impossibile aprire la guida: {0}", ex.Message)); }
    }

    private void BtnOpenFolder_Click(object sender, RoutedEventArgs e)
    {
        if (_session?.Folder is { Length: > 0 } d && Directory.Exists(d)) OpenPath(d);
    }

    private void OpenPath(string path)
    {
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch (Exception ex) { Error(L.F("Impossibile aprire {0}: {1}", path, ex.Message)); }
    }

    private void Error(string msg) => MessageBox.Show(this, msg, "PHP Vuln Scanner", MessageBoxButton.OK, MessageBoxImage.Warning);
}

/// <summary>Voce di una tendina a scelta multipla (v1.5): chiave stabile (nome dell'enum), etichetta nella lingua attiva, spunta.</summary>
public sealed class MultiSelectItem(string key, string label) : INotifyPropertyChanged
{
    private bool _isChecked;
    public string Key { get; } = key;
    public string Label { get; } = label;
    public bool IsChecked
    {
        get => _isChecked;
        set { if (_isChecked == value) return; _isChecked = value; PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsChecked))); }
    }
    public event PropertyChangedEventHandler? PropertyChanged;
    public override string ToString() => Label;
}

/// <summary>Piccola estensione per configurare un oggetto in linea.</summary>
internal static class ObjectExtensions
{
    public static T Also<T>(this T o, Action<T> f) { f(o); return o; }
}
