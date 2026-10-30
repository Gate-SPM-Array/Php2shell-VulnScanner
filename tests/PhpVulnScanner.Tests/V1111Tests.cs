using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Report;

namespace PhpVulnScanner.Tests;

/// <summary>v1.11.1: lo sweeper usa le porte dell'alive check (mai quelle della scansione); avviso "porta del perimetro".</summary>
public class V1111Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v1111_" + Guid.NewGuid().ToString("N"));
    public V1111Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public async Task Sweeper_DoesNotUseScanPorts()
    {
        // porta della scansione aperta, nessuna porta TCP nell'alive check: nella v1.11 lo sweeper "recuperava" l'host via porta di scansione; ora no
        using var srv = new FakePhpServer { PoweredBy = "PHP/7.4.33" };
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.1", PortsText = srv.Port.ToString(), PathsText = "/", ConnectTimeoutMs = 1000, ReadTimeoutMs = 1000, Threads = 2, OutputFolder = _dir,
            Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [], UdpPorts = [], TimeoutMs = 300, SkipIfNotAlive = true, Retry = true },
            Level2 = false, WafDetect = false, SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false, PortPrecheck = false,
            Advanced = new AdvancedOptions().Also(o => o.SetAll(false)),
        };
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(Verdict.NotReachable, Assert.Single(s.Results).Verdict);
        Assert.Contains(log, l => l.Contains("Sweeper dell'alive check attivo") && l.Contains("TCP –"));
        Assert.Contains(log, l => l.Contains("Sweeper dell'alive check: 0 host recuperati"));
        // con le porte dello sweeper esplicite l'host rientra
        cfg.Alive.SweepTcpPorts = [srv.Port];
        s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(Verdict.VulnerableByVersion, Assert.Single(s.Results).Verdict);
        Assert.Equal([srv.Port], new AliveConfig { TcpPorts = [443], SweepTcpPorts = [srv.Port] }.EffectiveSweepTcpPorts);
        Assert.Equal([443], new AliveConfig { TcpPorts = [443] }.EffectiveSweepTcpPorts);
        Assert.Equal([443, 80], CliRunner.Parse(["--scan", "192.0.2.1", "--sweep-tcp", "443,80"], _dir, out _, out _, out _)!.Alive.SweepTcpPorts);
    }

    [Fact]
    public void PerimeterPortNotes_FlagsAPortConfirmingMostHosts()
    {
        var counts = new Dictionary<string, int> { ["TCP/1720"] = 3556, ["TCP/443"] = 250, ["ICMP"] = 2100 };
        var notes = ScanEngine.PerimeterPortNotes(counts, 4094);
        var n = Assert.Single(notes);
        Assert.Contains("TCP/1720", n); Assert.Contains("3556 host su 4094", n);
        Assert.Empty(ScanEngine.PerimeterPortNotes(new Dictionary<string, int> { ["TCP/443"] = 250 }, 4094));   // 6%: normale
        Assert.Empty(ScanEngine.PerimeterPortNotes(new Dictionary<string, int> { ["TCP/443"] = 20 }, 30));     // rete troppo piccola per dirlo
        Assert.Empty(ScanEngine.PerimeterPortNotes(new Dictionary<string, int> { ["ICMP"] = 4000 }, 4094));     // solo TCP
        // nel report compatto la nota compare come avviso
        var s = new ScanSession { AppVersion = "1.11.1", StartLocal = DateTime.Now, EndLocal = DateTime.Now, Status = ScanStatus.Completed, Folder = "", Ports = ["443"], Paths = ["/"], Config = new ScanConfig(), Notes = notes };
        Assert.Contains("Porta del perimetro: TCP/1720", CompactReportGenerator.Build(s, "x.html"));
    }
}
