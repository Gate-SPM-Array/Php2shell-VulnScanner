using System.Text.Json;
using PhpVulnScanner.Core.Cli;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Tests;

/// <summary>Funzioni introdotte nella v1.2: ordinamento IP, marche temporali, porte UDP, SAPI/OS/applicazione, priorità, riga di comando, modalità leggera.</summary>
public class V12Tests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "phpvs_v12_" + Guid.NewGuid().ToString("N"));
    public V12Tests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    [Fact]
    public void SortKey_FollowsIpNumbering_ThenNames()
    {
        var hosts = new[] { "203.0.113.100", "203.0.113.1", "www.example.org", "203.0.113.10", "2001:db8::1", "203.0.113.101", "alpha.example.org", "10.0.0.1" };
        var sorted = hosts.OrderBy(TargetParser.SortKey, StringComparer.Ordinal).ToArray();
        Assert.Equal(["10.0.0.1", "203.0.113.1", "203.0.113.10", "203.0.113.100", "203.0.113.101", "2001:db8::1", "alpha.example.org", "www.example.org"], sorted);
    }

    [Fact]
    public void Stamp_IsoWithCommaMilliseconds_AndUtcInLog()
    {
        var t = new DateTime(2026, 10, 22, 16, 7, 12, 243, DateTimeKind.Local);
        Assert.Equal("2026-10-22 16:07:12,243", Stamp.Local(t));
        string log = Stamp.Log(t);
        Assert.StartsWith("2026-10-22 16:07:12,243 (", log);
        Assert.EndsWith("Z)", log);
        Assert.Contains(t.ToUniversalTime().ToString("HH:mm:ss"), log);
    }

    [Fact]
    public void AliveConfig_UdpPortsList_AndLegacySingleField()
    {
        var legacy = JsonSerializer.Deserialize<AliveConfig>("{\"UdpPort\": 53, \"TcpPorts\": [443]}", ScanConfig.JsonOptions)!;
        Assert.Equal([53], legacy.UdpPorts);
        var cfg = new ScanConfig();
        cfg.Alive.UdpPorts = TargetParser.ParsePorts("53, 1, 123, 37", out var errors);
        Assert.Empty(errors);
        Assert.Equal([53, 1, 123, 37], cfg.Alive.UdpPorts);
        var round = JsonSerializer.Deserialize<ScanConfig>(JsonSerializer.Serialize(cfg, ScanConfig.JsonOptions), ScanConfig.JsonOptions)!;
        Assert.Equal([53, 1, 123, 37], round.Alive.UdpPorts);
    }

    private static HttpSnapshot Snap(string body, params (string, string)[] headers) =>
        new() { Status = 200, Reason = "OK", Method = "GET", Url = "http://h/", Body = body, Headers = headers.Select(h => new KeyValuePair<string, string>(h.Item1, h.Item2)).ToList() };

    [Fact]
    public void StackFingerprint_Sapi_Os_Application()
    {
        var r = new ScanResult { ServerHeader = "Apache/2.4.62 (Debian) PHP/8.2.26", PoweredBy = "PHP/8.2.26", PhpDetected = true };
        StackFingerprint.Apply(r, [Snap("<html><meta name=\"generator\" content=\"WordPress 6.6\"></html>", ("Server", r.ServerHeader))]);
        Assert.Equal("mod_php", r.Sapi);
        Assert.Equal("Debian", r.OsHint);
        Assert.Equal("WordPress", r.Application);
        Assert.EndsWith("software_list_w.md", r.ApplicationReference);

        r = new ScanResult { ServerHeader = "nginx/1.26.0", PoweredBy = "PHP/8.3.1", PhpDetected = true };
        StackFingerprint.Apply(r, [Snap("<html>ok</html>", ("Set-Cookie", "laravel_session=abc; path=/"))]);
        Assert.Equal("fpm", r.Sapi);
        Assert.Equal("Laravel", r.Application);
        Assert.Equal("", r.OsHint);

        r = new ScanResult { ServerHeader = "Apache", PoweredBy = "PHP/7.4.33-1ubuntu2", PhpDetected = true, PhpVersionRaw = "7.4.33-1ubuntu2" };
        StackFingerprint.Apply(r, [Snap("<html>ok</html>", ("X-Generator", "Drupal 10 (https://www.drupal.org)"))]);
        Assert.Equal("", r.Sapi);                      // Apache senza PHP nel banner: non distinguibile
        Assert.Contains("mod_php", r.SapiEvidence);
        Assert.Equal("Ubuntu", r.OsHint);              // dal suffisso di pacchetto
        Assert.Equal("Drupal", r.Application);
    }

    [Fact]
    public void Priority_Rules()
    {
        static ScanResult R(Verdict v, string sapi, MultipartBarrier mp, VersionStatus vs = VersionStatus.Unknown) =>
            new() { Verdict = v, Sapi = sapi, Multipart = mp, VersionStatus = vs };
        Assert.Equal(Priority.Critical, VerdictEngine.Prioritize(R(Verdict.VulnerableByVersion, "mod_php", MultipartBarrier.Accepted)));
        Assert.Equal(Priority.High, VerdictEngine.Prioritize(R(Verdict.VulnerableByVersion, "fpm", MultipartBarrier.Accepted)));
        Assert.Equal(Priority.High, VerdictEngine.Prioritize(R(Verdict.LikelyVulnerable, "", MultipartBarrier.NotTested)));
        Assert.Equal(Priority.Medium, VerdictEngine.Prioritize(R(Verdict.MitigatedAtEdge, "mod_php", MultipartBarrier.Blocked, VersionStatus.VulnerableSupported)));
        Assert.Equal(Priority.Low, VerdictEngine.Prioritize(R(Verdict.MitigatedAtEdge, "", MultipartBarrier.Blocked)));
        Assert.Equal(Priority.Medium, VerdictEngine.Prioritize(R(Verdict.Undetermined, "", MultipartBarrier.Accepted)));
        Assert.Equal(Priority.Low, VerdictEngine.Prioritize(R(Verdict.Undetermined, "", MultipartBarrier.Blocked)));
        Assert.Equal(Priority.None, VerdictEngine.Prioritize(R(Verdict.FixedByVersion, "mod_php", MultipartBarrier.Accepted)));
        Assert.Equal(Priority.Low, VerdictEngine.Prioritize(R(Verdict.FixedByVersion, "", MultipartBarrier.PartiallyBlocked)));
        Assert.Equal(Priority.None, VerdictEngine.Prioritize(R(Verdict.NotReachable, "", MultipartBarrier.NotTested)));
    }

    [Fact]
    public async Task Engine_AliveMethodsListed_SapiAndApp_InResultsAndCsv()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", Server = "Apache/2.4.58 (Debian) PHP/8.3.20", HomeBody = "<html><meta name=\"generator\" content=\"WordPress 6.6\"></html>" };
        int closed = FakePhpServer.FreePort();
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.1", PortsText = srv.Port.ToString(), ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, OutputFolder = _dir,
            Alive = new AliveConfig { Enabled = true, Icmp = false, TcpPorts = [srv.Port, closed], UdpPorts = [FakePhpServer.FreePort()], TimeoutMs = 1500 },
        };
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        Assert.True(r.Sapi == "mod_php", $"sapi={r.Sapi} server={r.ServerHeader} ev={r.SapiEvidence} hdrs={string.Join("|", r.Requests[0].Headers.Select(h => h.Key + "=" + h.Value))}");
        Assert.Equal("Debian", r.OsHint);
        Assert.Equal("WordPress", r.Application);
        Assert.Equal(Priority.Critical, r.Priority);
        Assert.Contains($"TCP/{srv.Port}", r.AliveMethods);
        Assert.Contains($"TCP/{closed}", r.AliveMethods);
        Assert.Contains("UDP/", r.AliveMethods);
        Assert.Contains(r.Tests, t => t.Id == "ALIVE" && t.Detail.Contains("UDP/") && t.Detail.Contains("ms]"));
        Assert.Contains(r.Tests, t => t.Id == "L1-SAPI" && t.Outcome == TestOutcome.Warn);
        Assert.Contains(r.Tests, t => t.Id == "L1-APP" && t.Detail.Contains("NCSC-NL"));
        var csv = File.ReadAllLines(Path.Combine(s.Folder, SessionFiles.ResultsCsv));
        Assert.Contains("priority;sapi;os_hint;application", csv[0]);
        Assert.Contains(";Critical;mod_php;Debian;WordPress;", csv[1]);
        Assert.Matches(@";\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3};", csv[1]);
        var log = File.ReadAllText(Path.Combine(s.Folder, SessionFiles.ScanLog));
        Assert.Matches(@"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} \(\d\d:\d\d:\d\d,\d{3}Z\) ", log);
    }

    [Fact]
    public async Task Engine_ResultsSortedByIp()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.36" };
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.100\n127.0.0.2\n127.0.0.10\n127.0.0.1", PortsText = srv.Port.ToString(), ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, OutputFolder = _dir, Threads = 4,
            Alive = new AliveConfig { Enabled = false },
        };
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        Assert.Equal(["127.0.0.1", "127.0.0.2", "127.0.0.10", "127.0.0.100"], s.Results.Select(r => r.Host).ToArray());
    }

    [Fact]
    public async Task LightMode_UsesHeadFirst()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.1", PortsText = srv.Port.ToString(), ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000, OutputFolder = _dir,
            Alive = new AliveConfig { Enabled = false }, LightMode = true, Level2 = false, WafDetect = false, Level1InfoPages = false, SurfaceDiscovery = false, DiscoverNames = false, Advanced = AdvancedOptions.Parse("none"),
        };
        var s = await new ScanEngine().RunAsync(cfg, CancellationToken.None);
        var r = Assert.Single(s.Results);
        Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        Assert.True(srv.HeadRequests >= 2, $"HEAD {srv.HeadRequests}");
        Assert.All(r.Requests, q => Assert.Equal("HEAD", q.Method));
    }

    [Fact]
    public async Task Cli_ExitCodes_AndOutput()
    {
        using var vuln = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        using var fixedSrv = new FakePhpServer { PoweredBy = "PHP/8.4.27" };
        using var hidden = new FakePhpServer { Server = "nginx", SessionCookie = true };

        var sw = new StringWriter();
        int code = await CliRunner.RunAsync(["--scan", "127.0.0.1", "--ports", vuln.Port.ToString(), "--no-alive", "--out", _dir, "--quiet", "--json", Path.Combine(_dir, "copy.json")], _dir, sw, CancellationToken.None);
        Assert.Equal(CliRunner.ExitVulnerable, code);
        Assert.Contains("Report HTML", sw.ToString());
        Assert.Contains("Vulnerabile per versione", sw.ToString());
        Assert.True(File.Exists(Path.Combine(_dir, "copy.json")));

        sw = new StringWriter();
        code = await CliRunner.RunAsync(["--scan", "127.0.0.1", "--ports", fixedSrv.Port.ToString(), "--no-alive", "--out", _dir, "--quiet"], _dir, sw, CancellationToken.None);
        Assert.Equal(CliRunner.ExitClean, code);

        sw = new StringWriter();
        code = await CliRunner.RunAsync(["--scan", "127.0.0.1", "--ports", hidden.Port.ToString(), "--no-alive", "--out", _dir, "--quiet"], _dir, sw, CancellationToken.None);
        Assert.Equal(CliRunner.ExitUndetermined, code);

        // file di bersagli
        string file = Path.Combine(_dir, "targets_v1.0.txt");
        File.WriteAllText(file, "# commento\n127.0.0.1\n");
        sw = new StringWriter();
        code = await CliRunner.RunAsync(["--scan", file, "--ports", vuln.Port.ToString(), "--no-alive", "--out", _dir, "--quiet", "--light", "--no-waf", "--no-level2"], _dir, sw, CancellationToken.None);
        Assert.Equal(CliRunner.ExitVulnerable, code);

        // argomenti non validi
        sw = new StringWriter();
        Assert.Equal(CliRunner.ExitUsage, await CliRunner.RunAsync(["--scan", "nonsense!!"], _dir, sw, CancellationToken.None));
        Assert.Contains("Uso:", sw.ToString());
        Assert.Equal(CliRunner.ExitUsage, await CliRunner.RunAsync(["--ports", "443"], _dir, new StringWriter(), CancellationToken.None));
        Assert.Equal(CliRunner.ExitUsage, await CliRunner.RunAsync(["--scan", "127.0.0.1", "--threads", "abc"], _dir, new StringWriter(), CancellationToken.None));
        Assert.Equal(CliRunner.ExitClean, await CliRunner.RunAsync(["--help"], _dir, new StringWriter(), CancellationToken.None));
        Assert.True(CliRunner.IsCliInvocation(["--scan", "x"]));
        Assert.False(CliRunner.IsCliInvocation([]));
    }
}
