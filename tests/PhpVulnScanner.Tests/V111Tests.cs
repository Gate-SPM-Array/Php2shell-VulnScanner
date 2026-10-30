using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Tests;

/// <summary>v1.11: sweeper continuo dell'alive check, host noti dalle sessioni precedenti, nomi dirottati ricordati tra i cicli, conteggio dei recuperati.</summary>
public class V111Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v111_" + Guid.NewGuid().ToString("N"));
    public V111Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string targets) => new()
    {
        TargetsText = targets, PortsText = srv.Port.ToString(), PathsText = "/ /index.php", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 2, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 1000, SkipIfNotAlive = true, Retry = true, SweepLanes = 2, SweepTcpPorts = [srv.Port] },
        Level1InfoPages = false, Level1EasterEgg = false, Level2 = false, WafDetect = false, WafBehaviour = false, SizeProbeKiB = 4,
        SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false, PortPrecheck = false, RandomOrder = false,
        Advanced = new AdvancedOptions().Also(o => o.SetAll(false)), ServiceBudgetMs = 0,
    };

    [Fact]
    public async Task Sweeper_RecoversHostsDuringTheCycle_AndCountsOnlyThem()
    {
        // 6 host loopback non confermati dall'alive check (nessun metodo): lo sweeper li recupera via TCP mentre il ciclo gira
        using var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/7.4.33", DelayMs = 100 };
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var s = await engine.RunAsync(Cfg(srv, "127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4 127.0.0.5 127.0.0.6"), CancellationToken.None);
        Assert.Equal(6, s.Results.Count);
        Assert.All(s.Results, r => Assert.Equal(Verdict.VulnerableByVersion, r.Verdict));
        Assert.Equal(6, s.HostsAlive);
        Assert.Contains(log, l => l.Contains("Sweeper dell'alive check attivo: 2 corsie"));
        Assert.Equal(6, log.Count(l => l.Contains("risponde allo sweeper")));
        Assert.Contains(log, l => l.Contains("Sweeper dell'alive check: 6 host recuperati, 6 tentativi"));   // conteggio esatto, non "7 su 6"
        // la seconda chance a fine ciclo non esiste più: nessuna riga della vecchia forma
        Assert.DoesNotContain(log, l => l.Contains("Seconda chance"));
    }

    [Fact]
    public async Task Sweeper_Off_LeavesHostsUnreachable()
    {
        using var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/7.4.33" };
        var cfg = Cfg(srv, "127.0.0.1 127.0.0.2"); cfg.Alive.Retry = false;
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.All(s.Results, r => Assert.Equal(Verdict.NotReachable, r.Verdict));
        Assert.DoesNotContain(log, l => l.Contains("Sweeper"));
    }

    [Fact]
    public async Task KnownHosts_SilentHostGetsTheKnownHostTest_AndIsRetriedEveryCycle()
    {
        string known = Path.Combine(_dir, "host_attivi_v1.10.txt");
        File.WriteAllText(known, "# attivi ieri\n203.0.113.250\n203.0.113.251 commento\n");
        var cfg = new ScanConfig
        {
            TargetsText = "203.0.113.250", PortsText = "9", PathsText = "/", ConnectTimeoutMs = 300, ReadTimeoutMs = 300, Threads = 2, OutputFolder = _dir,
            Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 300, SkipIfNotAlive = true, Retry = true, SweepLanes = 2 },
            Level2 = false, WafDetect = false, SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false, PortPrecheck = false,
            Advanced = new AdvancedOptions().Also(o => o.SetAll(false)), Cycles = 2, CyclePauseSec = 0, Consolidate = true, KnownHostsPath = known,
        };
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.Equal(Verdict.NotReachable, r.Verdict);
        Assert.Contains(r.Tests, t => t.Id == "KNOWN-HOST");
        Assert.Contains(log, l => l.Contains("Host noti: 2 host attivi in sessioni precedenti"));
        Assert.Equal(2, log.Count(l => l.Contains("Sweeper dell'alive check: 0 host recuperati, 1 tentativi")));   // riprovato in entrambi i cicli
    }

    [Fact]
    public void Cli_SweepLanesAndKnownHosts()
    {
        var cfg = CliRunner.Parse(["--scan", "192.0.2.1", "--sweep-lanes", "6", "--known-hosts", "noti.txt"], _dir, out _, out _, out _)!;
        Assert.Equal(6, cfg.Alive.SweepLanes); Assert.Equal("noti.txt", cfg.KnownHostsPath);
        Assert.Equal(4, new AliveConfig().SweepLanes);
    }
}
