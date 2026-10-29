using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Tests;

/// <summary>v1.9: seconda chance dell'alive check più leggera (corsie = metà dei thread, timeout 1,5×) e anticipata (parte con la coda degli host vuota).</summary>
public class V19Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v19_" + Guid.NewGuid().ToString("N"));
    public V19Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string targets) => new()
    {
        TargetsText = targets, PortsText = srv.Port.ToString(), PathsText = "/ /index.php", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 4, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 1500, SkipIfNotAlive = true, Retry = true, SweepTcpPorts = [srv.Port] },
        Level1InfoPages = false, Level1EasterEgg = false, Level2 = false, WafDetect = false, WafBehaviour = false, SizeProbeKiB = 4,
        SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false, PortPrecheck = false, RandomOrder = false,
        Advanced = new AdvancedOptions().Also(o => o.SetAll(false)), ServiceBudgetMs = 0,
    };

    [Fact]
    public async Task SecondChance_UsesTimeoutOneAndAHalf_AndRecoversEveryHost()
    {
        using var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/7.4.33" };
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        // quattro host loopback, nessuno confermato al primo giro (nessun metodo), tutti recuperati dalla seconda chance (TCP sulla porta della scansione)
        var s = await engine.RunAsync(Cfg(srv, "127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4"), CancellationToken.None);
        Assert.Equal(4, s.Results.Count);
        Assert.All(s.Results, r => Assert.Equal(Verdict.VulnerableByVersion, r.Verdict));
        Assert.Equal(4, s.HostsAlive);
        Assert.Contains(log, l => l.Contains("timeout 2250 ms"));                     // 1500 × 1,5
        Assert.Contains(log, l => l.Contains("Sweeper dell'alive check: 4 host recuperati"));   // v1.11
        Assert.Single(log, l => l.Contains("Sweeper dell'alive check: "));             // il totale una volta sola
    }

    [Fact]
    public async Task SecondChance_StartsWhenTheHostQueueIsEmpty_LateHostRetriedInTheFinalDrain()
    {
        // 1 thread: la seconda chance parte quando la coda è vuota, cioè mentre l'ultimo host è ancora in corso: quello finisce in coda alla fine
        using var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/7.4.33" };
        var cfg = Cfg(srv, "127.0.0.1 127.0.0.2 127.0.0.3");
        cfg.Threads = 1;
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(3, s.Results.Count);
        Assert.All(s.Results, r => Assert.Equal(Verdict.VulnerableByVersion, r.Verdict));
        Assert.Contains(log, l => l.Contains("Sweeper dell'alive check: 3 host recuperati"));
        Assert.Equal(3, log.Count(l => l.Contains("risponde allo sweeper")));
        // nessun host contato due volte: le righe per host sono 3, i completamenti 3
        Assert.Equal(3, SessionFiles_ResultCount(s.Folder));
    }

    private static int SessionFiles_ResultCount(string folder) => PhpVulnScanner.Core.Output.SessionFiles.ReadSession(folder)!.Results.Count;

    [Fact]
    public void Lanes_HalfTheThreads_AtLeastFour_NeverMoreThanThreads()
    {
        static int Lanes(int threads) => Math.Max(1, Math.Min(threads, Math.Max(4, threads / 2)));
        Assert.Equal(4, Lanes(4)); Assert.Equal(4, Lanes(6)); Assert.Equal(8, Lanes(16)); Assert.Equal(18, Lanes(36)); Assert.Equal(1, Lanes(1)); Assert.Equal(2, Lanes(2));
    }
}
