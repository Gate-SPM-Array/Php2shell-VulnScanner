namespace PhpVulnScanner.Core.Engine;

/// <summary>Fotografia dell'avanzamento, con le stime; viene pubblicata dal motore e mostrata nella barra di stato e nel log.</summary>
public sealed record ScanProgress(
    int Cycle, int Cycles, int Done, int Total, double ElapsedSec, double RatePerSec, bool RateReliable,
    double? CycleRemainingSec, double? LoopRemainingSec, int HostsAlive, int HostsDone, int HostsTotal)
{
    public DateTime? CycleEtaLocal => CycleRemainingSec is double s ? DateTime.Now.AddSeconds(s) : null;
    public DateTime? LoopEtaLocal => LoopRemainingSec is double s ? DateTime.Now.AddSeconds(s) : null;
}

/// <summary>
/// Stima di fine ciclo e di fine loop sul ritmo recente (finestra mobile di 5 minuti), non sulla media dall'inizio:
/// una rete alterna zone lente (host muti che costano il timeout) e zone veloci (RST immediati), e la media dall'inizio
/// nasconderebbe il cambio. Sotto un minuto di campioni la stima è "in calcolo". Il loop proietta il ciclo corrente più
/// i cicli restanti con la durata dell'ultimo ciclo completato (o della proiezione corrente) più le pause.
/// </summary>
public sealed class ScanEstimator
{
    public const double WindowSec = 300;
    public const double MinSampleSec = 60;

    private readonly List<(double T, int Done)> _samples = [];
    private readonly object _lock = new();

    public int Cycles { get; set; } = 1;
    public int Cycle { get; set; } = 1;
    public double CyclePauseSec { get; set; }
    /// <summary>Durata dell'ultimo ciclo completato, se c'è.</summary>
    public double? LastCycleSec { get; set; }

    /// <summary>Nuovo ciclo: si riparte con campioni vuoti.</summary>
    public void Reset(int cycle)
    {
        lock (_lock) { _samples.Clear(); Cycle = cycle; }
    }

    /// <summary>Registra un campione (secondi dall'avvio del ciclo, completati finora).</summary>
    public void Add(double elapsedSec, int done)
    {
        lock (_lock)
        {
            _samples.Add((elapsedSec, done));
            // la finestra tiene i campioni degli ultimi WindowSec più uno precedente, come riferimento
            while (_samples.Count > 2 && _samples[1].T < elapsedSec - WindowSec) _samples.RemoveAt(0);
        }
    }

    /// <summary>Ritmo recente in coppie al secondo e se è affidabile (almeno un minuto di campioni).</summary>
    public (double Rate, bool Reliable) Rate()
    {
        lock (_lock)
        {
            if (_samples.Count < 2) return (0, false);
            var first = _samples[0];
            var last = _samples[^1];
            double dt = last.T - first.T;
            if (dt <= 0) return (0, false);
            double rate = (last.Done - first.Done) / dt;
            return (rate, dt >= MinSampleSec);
        }
    }

    public ScanProgress Snapshot(int done, int total, double elapsedSec, int hostsAlive, int hostsDone, int hostsTotal)
    {
        var (rate, reliable) = Rate();
        double? cycleRemaining = null, loopRemaining = null;
        if (reliable && rate > 0)
        {
            cycleRemaining = Math.Max(0, (total - done) / rate);
            double projectedCycle = elapsedSec + cycleRemaining.Value;
            int remainingCycles = Math.Max(0, Cycles - Cycle);
            double perCycle = LastCycleSec ?? projectedCycle;
            loopRemaining = cycleRemaining.Value + remainingCycles * (perCycle + CyclePauseSec);
        }
        return new ScanProgress(Cycle, Cycles, done, total, elapsedSec, rate, reliable, cycleRemaining, loopRemaining, hostsAlive, hostsDone, hostsTotal);
    }

    /// <summary>"1 h 02 min", "12 min", "45 s".</summary>
    public static string Duration(double seconds)
    {
        if (seconds < 0) seconds = 0;
        var t = TimeSpan.FromSeconds(seconds);
        if (t.TotalHours >= 1) return L.F("{0} h {1:00} min", (int)t.TotalHours, t.Minutes);
        if (t.TotalMinutes >= 1) return L.F("{0} min", (int)Math.Round(t.TotalMinutes));
        return L.F("{0} s", (int)t.TotalSeconds);
    }
}
