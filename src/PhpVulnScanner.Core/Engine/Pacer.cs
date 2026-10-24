using System.Diagnostics;

namespace PhpVulnScanner.Core.Engine;

/// <summary>
/// Ritmo delle richieste HTTP: pausa casuale tra una richiesta e l'altra verso lo stesso host (min…max ms) e tetto
/// globale di richieste al secondo (token bucket). Serve a non assomigliare a un attacco agli occhi di un IDS/IPS,
/// anche quando l'indirizzo di chi scansiona è in white list. Nessun effetto sui risultati.
/// </summary>
public sealed class Pacer
{
    private readonly int _minMs, _maxMs, _perSecond;
    private readonly Random _rng;
    private readonly object _lock = new();
    private double _tokens;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private double _lastRefill;
    private long _requests;

    public Pacer(int delayMinMs, int delayMaxMs, int maxRequestsPerSecond, int? seed = null)
    {
        _minMs = Math.Max(0, delayMinMs);
        _maxMs = Math.Max(_minMs, delayMaxMs);
        _perSecond = Math.Max(0, maxRequestsPerSecond);
        _rng = seed is int s ? new Random(s) : new Random();
        _tokens = _perSecond;
        _lastRefill = 0;
    }

    public bool Active => _maxMs > 0 || _perSecond > 0;
    public long Requests => Interlocked.Read(ref _requests);

    /// <summary>Attende la pausa casuale e un token del tetto globale, poi conta la richiesta.</summary>
    public async Task WaitAsync(CancellationToken ct)
    {
        if (_maxMs > 0)
        {
            int ms;
            lock (_lock) ms = _rng.Next(_minMs, _maxMs + 1);
            if (ms > 0) await Task.Delay(ms, ct).ConfigureAwait(false);
        }
        if (_perSecond > 0)
        {
            while (true)
            {
                double waitMs;
                lock (_lock)
                {
                    double now = _clock.Elapsed.TotalSeconds;
                    _tokens = Math.Min(_perSecond, _tokens + (now - _lastRefill) * _perSecond);
                    _lastRefill = now;
                    if (_tokens >= 1) { _tokens -= 1; break; }
                    waitMs = (1 - _tokens) / _perSecond * 1000;
                }
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(1, waitMs)), ct).ConfigureAwait(false);
            }
        }
        Interlocked.Increment(ref _requests);
    }
}
