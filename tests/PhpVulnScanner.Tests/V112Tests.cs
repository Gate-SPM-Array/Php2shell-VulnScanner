using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Tests;

/// <summary>v1.12: nomi assegnati localmente (file hosts, nome@IP): riga per nome su quell'IP con SNI e Host = nome, nessuna query DNS, nessun ripiegamento.</summary>
public class V112Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v112_" + Guid.NewGuid().ToString("N"));
    public V112Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private ScanConfig Cfg(FakePhpServer srv, string targets) => new()
    {
        TargetsText = targets, PortsText = srv.Port.ToString(), PathsText = "/", ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, Threads = 2, OutputFolder = _dir,
        Alive = new AliveConfig { Enabled = false }, Level1InfoPages = false, Level1EasterEgg = false, Level2 = false, WafDetect = false, WafBehaviour = false,
        SurfaceDiscovery = false, DiscoverNames = false, RescanDiscoveredNames = false, PortPrecheck = false,
        Advanced = new AdvancedOptions().Also(o => o.SetAll(false)), ServiceBudgetMs = 0,
    };

    [Fact]
    public void TargetParser_AcceptsNameAtIp()
    {
        var p = TargetParser.Parse("app.example.org@192.0.2.10\nintranet.example.org@192.0.2.10, 192.0.2.11\nhttps://shop.example.org@192.0.2.11:443/\nbad@\n@192.0.2.1\nname@notanip\n");
        Assert.Equal(["192.0.2.10", "192.0.2.11"], p.Targets.Select(t => t.Host));
        Assert.All(p.Targets, t => Assert.True(t.IsIpLiteral));
        Assert.Equal([("app.example.org", "192.0.2.10"), ("intranet.example.org", "192.0.2.10"), ("shop.example.org", "192.0.2.11")], p.LocalNames.Select(e => (e.Name, e.Ip)));
        Assert.Equal(3, p.Errors.Count);
        // un nome vale una sola assegnazione: la prima vince
        Assert.Single(TargetParser.Parse("a.example.org@192.0.2.1 a.example.org@192.0.2.2").LocalNames);
    }

    [Fact]
    public void HostsFile_ParsesTheSystemFormat()
    {
        var errors = new List<string>();
        var list = HostsFile.Parse("# copia del file di sistema\n127.0.0.1 localhost\n::1 localhost ip6-localhost\n192.0.2.10\tapp.example.org  www.example.org # vhost\n2001:db8::5 v6.example.org\nnon-un-ip nome.example.org\n192.0.2.11\n", errors);
        Assert.Equal([("app.example.org", "192.0.2.10"), ("www.example.org", "192.0.2.10"), ("v6.example.org", "2001:db8::5")], list.Select(e => (e.Name, e.Ip)));
        Assert.Equal(2, errors.Count);
        Assert.Contains(errors, e => e.Contains("riga 6"));
        Assert.Empty(HostsFile.Load(Path.Combine(_dir, "manca.txt"), errors));
        Assert.Equal(3, errors.Count);
    }

    [Fact]
    public void Prepare_LocalNamesBecomeIpTargets_WithoutDns()
    {
        string hosts = Path.Combine(_dir, "hosts");
        File.WriteAllText(hosts, "192.0.2.20 hidden.example.org\n192.0.2.21 other.example.org\n");
        // il nome della lista è assegnato nel file: diventa il suo IP (nessuna risoluzione); l'IP del file che manca entra tra i bersagli
        var cfg = new ScanConfig { TargetsText = "hidden.example.org\n192.0.2.21\napp.example.org@192.0.2.22", HostsFilePath = hosts };
        var s = ScanEngine.Prepare(cfg, out var targets, out _, out _, out var local);
        Assert.Equal(["192.0.2.20", "192.0.2.21", "192.0.2.22"], targets.Select(t => t.Host));
        Assert.All(targets, t => Assert.True(t.IsIpLiteral));
        Assert.Equal("hidden.example.org", targets[0].Input);
        Assert.Equal(3, local.Count);
        Assert.Equal(3, s.HostsTotal);
        Assert.Empty(s.ParseErrors);
    }

    [Fact]
    public async Task LocalName_GetsItsOwnRow_WithHostAndSni_AndIsNeverFolded()
    {
        // vhost per nome: senza Host giusto il server dichiara PHP 7.4, con Host = app.example.org PHP 8.3.40 (corretta)
        using var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/7.4.33", VhostName = "app.example.org", VhostPoweredBy = "PHP/8.3.40" };
        var cfg = Cfg(srv, "app.example.org@127.0.0.1\nsame.example.org@127.0.0.1");
        var engine = new ScanEngine();
        var log = new List<string>();
        engine.Log += l => { lock (log) log.Add(l); };
        var s = await engine.RunAsync(cfg, CancellationToken.None);
        Assert.Equal(3, s.Results.Count);
        var ip = Assert.Single(s.Results, r => !r.NameRescan);
        Assert.Equal(Verdict.VulnerableByVersion, ip.Verdict);
        Assert.Contains(ip.Tests, t => t.Id == "HOSTS" && t.Detail.Contains("2 nomi"));
        var app = Assert.Single(s.Results, r => r.HostHeader == "app.example.org");
        Assert.True(app.NameRescan); Assert.True(app.LocalName);
        Assert.Equal("127.0.0.1", app.Host);
        Assert.Equal(Verdict.FixedByVersion, app.Verdict);
        Assert.Equal("8.3.40", app.PhpVersionRaw);
        Assert.Contains(app.Tests, t => t.Id == "HOSTS" && t.Detail.Contains("nessuna query DNS"));
        Assert.DoesNotContain(app.Tests, t => t.Id == "DNS");
        // stesso contenuto del vhost predefinito: un nome scoperto ripiegherebbe, un nome assegnato resta una riga
        var same = Assert.Single(s.Results, r => r.HostHeader == "same.example.org");
        Assert.True(same.LocalName);
        Assert.Equal(Verdict.VulnerableByVersion, same.Verdict);
        Assert.Empty(ip.SameContentNames); Assert.Empty(ip.SameOutcomeNames);
        Assert.Contains(log, l => l.Contains("Nomi assegnati localmente: 2 nomi su 1 IP"));
        Assert.Contains(log, l => l.Contains("127.0.0.1: 2 nomi scoperti"));
        // report compatto: il nome è marcato come assegnato; CSV con la colonna local_name; report completo con la nota nella scheda
        string compact = CompactReportGenerator.Build(s, "x.html");
        Assert.Contains("app.example.org <span", compact); Assert.Contains("(hosts)", compact);
        Assert.Contains("local_name", SessionFiles.ResultsToCsv(s.Results, new CsvFormat(CsvDialect.Standard)));
        Assert.Contains("nome assegnato localmente", ReportGenerator.Build(s, "y.html"));
    }

    [Fact]
    public async Task HostsFile_DrivesTheScan_WithNameDiscoveryOff()
    {
        string hosts = Path.Combine(_dir, "hosts.txt");
        File.WriteAllText(hosts, "127.0.0.1 app.example.org\n");
        using var srv = new FakePhpServer(anyHost: true) { PoweredBy = "PHP/7.4.33", VhostName = "app.example.org", VhostPoweredBy = "PHP/8.3.40" };
        // lista vuota: i bersagli vengono dal file hosts; il nome scritto nella lista è assegnato nel file (nessuna risoluzione DNS)
        var cfg = Cfg(srv, "app.example.org");
        cfg.HostsFilePath = hosts;
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(2, s.Results.Count);
        var app = Assert.Single(s.Results, r => r.NameRescan);
        Assert.Equal("app.example.org", app.HostHeader); Assert.Equal("8.3.40", app.PhpVersionRaw); Assert.True(app.LocalName);
        Assert.True(srv.VhostRequests > 0);
        Assert.Equal(hosts, s.Config.HostsFilePath);
    }

    [Fact]
    public void Cli_HostsFile()
    {
        var cfg = CliRunner.Parse(["--scan", "app.example.org@192.0.2.1", "--hosts-file", "hosts.txt"], _dir, out _, out _, out _)!;
        Assert.Equal("hosts.txt", cfg.HostsFilePath);
        Assert.Equal("app.example.org@192.0.2.1", cfg.TargetsText.Trim());
    }
}
