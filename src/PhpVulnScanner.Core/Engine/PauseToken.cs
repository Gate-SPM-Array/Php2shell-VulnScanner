namespace PhpVulnScanner.Core.Engine;

/// <summary>
/// Pausa della scansione (v1.4): il motore si ferma prima del prossimo host e prima della prossima richiesta HTTP; le richieste
/// in volo finiscono e i loro risultati restano. Il tempo in pausa non entra nella stima (l'orologio della passata viene fermato).
/// </summary>
public sealed class PauseToken
{
    private readonly object _lock = new();
    private TaskCompletionSource _resume = Completed();
    private DateTime? _since;
    private TimeSpan _total;

    private static TaskCompletionSource Completed() { var t = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); t.SetResult(); return t; }

    public bool IsPaused { get { lock (_lock) return _since != null; } }
    /// <summary>Tempo complessivo passato in pausa (pausa corrente inclusa).</summary>
    public TimeSpan TotalPaused { get { lock (_lock) return _total + (_since is DateTime s ? DateTime.UtcNow - s : TimeSpan.Zero); } }
    public event Action<bool>? Changed;

    public void Pause()
    {
        lock (_lock)
        {
            if (_since != null) return;
            _since = DateTime.UtcNow;
            _resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        Changed?.Invoke(true);
    }

    /// <summary>Riprende; restituisce la durata della pausa appena conclusa.</summary>
    public TimeSpan Resume()
    {
        TimeSpan d;
        lock (_lock)
        {
            if (_since is not DateTime s) return TimeSpan.Zero;
            d = DateTime.UtcNow - s;
            _total += d;
            _since = null;
            _resume.TrySetResult();
        }
        Changed?.Invoke(false);
        return d;
    }

    /// <summary>Attende la ripresa se in pausa; l'interruzione (ct) esce subito anche durante la pausa.</summary>
    public async Task WaitAsync(CancellationToken ct)
    {
        Task t;
        lock (_lock) { if (_since == null) return; t = _resume.Task; }
        await t.WaitAsync(ct).ConfigureAwait(false);
    }
}
