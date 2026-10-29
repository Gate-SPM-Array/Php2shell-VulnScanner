using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace PhpVulnScanner.Core.Net;

/// <summary>Parametri del controllo preliminare di raggiungibilità ("alive check").</summary>
public sealed class AliveConfig
{
    public bool Enabled { get; set; } = true;
    /// <summary>Ping ICMP echo (su Windows non richiede privilegi: usa l'API IcmpSendEcho).</summary>
    public bool Icmp { get; set; } = true;
    /// <summary>Porte TCP su cui tentare una connessione (vuoto = nessun test TCP). Di solito le stesse della scansione.</summary>
    public List<int> TcpPorts { get; set; } = [443, 80];
    /// <summary>Porte UDP su cui inviare un datagramma (vuoto = nessun test UDP).</summary>
    public List<int> UdpPorts { get; set; } = [];
    /// <summary>Compatibilità con le impostazioni della v1.1 (campo singolo): in lettura si riversa in <see cref="UdpPorts"/>.</summary>
    [System.Text.Json.Serialization.JsonInclude]
    public int UdpPort { get => 0; set { if (value > 0 && !UdpPorts.Contains(value)) UdpPorts.Add(value); } }
    public int TimeoutMs { get; set; } = 1500;
    /// <summary>Se vero, i bersagli non confermati attivi non vengono scansionati.</summary>
    public bool SkipIfNotAlive { get; set; } = true;
    /// <summary>v1.8: host in alive check contemporaneamente (0 = quanti i thread). Indipendente dai thread HTTP: ogni host apre ICMP + TCP + UDP insieme.</summary>
    public int Parallel { get; set; } = 8;
    /// <summary>v1.8: a fine ciclo gli host non confermati vengono riprovati (v1.11: sweeper continuo per tutto il ciclo, ICMP + TCP sulle porte della scansione, timeout 1,5×).</summary>
    public bool Retry { get; set; } = true;
    /// <summary>v1.11: corsie dello sweeper (host non confermati riprovati insieme), indipendenti dai thread HTTP.</summary>
    public int SweepLanes { get; set; } = 4;
}

/// <summary>Esito del controllo: Attivo (almeno un metodo ha ricevuto una risposta), Nessuna risposta, Non eseguito.</summary>
public enum AliveState { NotTested, Alive, NoResponse }

/// <summary>Esito di un singolo metodo dell'alive check, con la sua durata.</summary>
public sealed record AliveMethodResult(string Method, bool Confirmed, string Detail, double ElapsedMs);

public sealed record AliveResult(AliveState State, string Method, string Details, double ElapsedMs, IReadOnlyList<AliveMethodResult> Methods)
{
    public static readonly AliveResult Skipped = new(AliveState.NotTested, "", "", 0, []);

    /// <summary>Tutti i metodi configurati, nell'ordine configurato, con esito e durata: "ICMP: risposta echo … [13 ms]; TCP/443: timeout [1500 ms]".</summary>
    public string MethodsSummary => string.Join("; ", Methods.Select(m => $"{m.Method}: {m.Detail} [{m.ElapsedMs:F0} ms]"));
}

/// <summary>
/// Controllo di raggiungibilità configurabile. I metodi si provano nell'ordine ICMP, TCP, UDP e ci si ferma alla prima
/// conferma. Limite dichiarato: l'UDP conferma un host solo se questo risponde con ICMP "port unreachable" o con dati;
/// il silenzio non significa host spento.
/// </summary>
public static class AliveChecker
{
    /// <summary>
    /// I metodi scelti partono tutti insieme: appena uno conferma l'host gli altri vengono annullati, così un host
    /// muto costa il timeout più lungo, non la somma dei timeout. Esito "nessuna risposta" solo se nessuno conferma.
    /// </summary>
    public static async Task<AliveResult> CheckAsync(string host, AliveConfig cfg, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var tasks = new List<(string Method, Stopwatch Sw, Task<(bool Ok, string Detail)> Task)>();
        if (cfg.Icmp) tasks.Add(("ICMP", Stopwatch.StartNew(), IcmpAsync(host, cfg.TimeoutMs, cts.Token)));
        foreach (int port in cfg.TcpPorts) tasks.Add(($"TCP/{port}", Stopwatch.StartNew(), TcpAsync(host, port, cfg.TimeoutMs, cts.Token)));
        foreach (int port in cfg.UdpPorts) tasks.Add(($"UDP/{port}", Stopwatch.StartNew(), UdpAsync(host, port, cfg.TimeoutMs, cts.Token)));
        if (tasks.Count == 0) return new AliveResult(AliveState.NoResponse, "", L.T("nessun metodo"), sw.Elapsed.TotalMilliseconds, []);

        var outcomes = new Dictionary<string, AliveMethodResult>();
        var pending = tasks.ToList();
        AliveResult? confirmed = null;
        while (pending.Count > 0)
        {
            var done = await Task.WhenAny(pending.Select(t => t.Task)).ConfigureAwait(false);
            var entry = pending.First(t => t.Task == done);
            pending.Remove(entry);
            (bool ok, string detail) = (false, "");
            try { (ok, detail) = await done.ConfigureAwait(false); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { detail = ex.GetBaseException().Message; }
            outcomes[entry.Method] = new AliveMethodResult(entry.Method, ok, detail, entry.Sw.Elapsed.TotalMilliseconds);
            if (ok)
            {
                confirmed = new AliveResult(AliveState.Alive, entry.Method, detail, sw.Elapsed.TotalMilliseconds, []);
                cts.Cancel();   // gli altri metodi non servono più
                // v1.8: non si aspetta la fine delle sonde annullate (sulla /20 costava 1,2 s per host attivo: un ping annullato non torna subito);
                // vengono registrate come annullate con il tempo trascorso finora e lasciate morire in sfondo
                foreach (var p in pending)
                {
                    outcomes[p.Method] = new AliveMethodResult(p.Method, false, L.T("annullato (host già confermato)"), p.Sw.Elapsed.TotalMilliseconds);
                    _ = p.Task.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
                }
                break;
            }
        }
        var ordered = tasks.Select(t => outcomes[t.Method]).ToList();
        if (confirmed != null) return confirmed with { Methods = ordered };
        return new AliveResult(AliveState.NoResponse, "", string.Join("; ", ordered.Select(o => $"{o.Method}: {o.Detail}")), sw.Elapsed.TotalMilliseconds, ordered);
    }

    private static async Task<(bool, string)> IcmpAsync(string host, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            using var reg = ct.Register(() => { try { ping.SendAsyncCancel(); } catch { } });
            var reply = await ping.SendPingAsync(host, timeoutMs).ConfigureAwait(false);
            if (reply.Status == IPStatus.Success) return (true, L.F("risposta echo in {0} ms da {1}", reply.RoundtripTime, reply.Address));
            return (false, reply.Status.ToString());
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return (false, L.T("timeout")); }
        catch (Exception ex) { return (false, ex.GetBaseException().Message); }
    }

    /// <summary>Connessione TCP: anche un rifiuto esplicito (RST) prova che l'host è attivo.</summary>
    private static async Task<(bool, string)> TcpAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var sock = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await sock.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            return (true, L.T("connessione riuscita"));
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
        {
            return (true, L.T("porta chiusa (RST): host attivo"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return (false, L.T("timeout")); }
        catch (Exception ex) { return (false, ex.GetBaseException().Message); }
    }

    /// <summary>
    /// Datagramma UDP: una risposta con dati o un ICMP "port unreachable" (ConnectionReset su Windows, ConnectionRefused
    /// su Linux, segnalato alla ricezione o all'invio successivo) provano che l'host è attivo. Nessuna risposta = esito
    /// sconosciuto, mai "spento".
    /// </summary>
    private static async Task<(bool, string)> UdpAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            IPAddress[] addrs = IPAddress.TryParse(host, out var ip) ? [ip] : await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            if (addrs.Length == 0) return (false, L.T("nome non risolto"));
            using var udp = new UdpClient(addrs[0].AddressFamily);
            udp.Connect(addrs[0], port);
            int half = Math.Max(100, timeoutMs / 2);
            for (int attempt = 0; attempt < 2; attempt++)
            {
                await udp.SendAsync(new byte[] { 0 }, ct).ConfigureAwait(false);
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(half);
                try
                {
                    var r = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                    return (true, L.F("risposta UDP di {0} byte", r.Buffer.Length));
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { /* nessuna risposta: secondo invio, poi esito sconosciuto */ }
            }
            return (false, L.T("nessuna risposta (esito sconosciuto)"));
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
        {
            return (true, L.T("ICMP port unreachable: host attivo"));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return (false, L.T("nessuna risposta (esito sconosciuto)")); }
        catch (Exception ex) { return (false, ex.GetBaseException().Message); }
    }
}
