using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using PhpVulnScanner.Core.Apps;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Tests;

/// <summary>v1.4, sezione Avanzate: HEAD/OPTIONS, Composer, pagine di stato, file di versione, FastCGI, comportamenti PHP, livello 2 sugli altri percorsi, UA da browser, componenti, esposizioni, PTR, crt.sh.</summary>
// Collection "AppDbDefault": TechnologyDatabase.Default è uno stato statico del processo; i test che lo impostano (qui, AppDbTests,
// AppDbFixtureTests) devono girare in sequenza, altrimenti il "ripristino" di uno cancella il database dell'altro mentre gira (v1.6: test intermittente).
[Collection("AppDbDefault")]
public class AdvancedProbesTests : IDisposable
{
    private readonly HttpProbe _http = new(2000, 5000);
    public void Dispose() => _http.Dispose();

    /// <summary>Contesto come lo costruisce il motore dopo il livello 1: Baseline e PrimaryPath impostati da PhpFingerprint, poi i test avanzati.</summary>
    private async Task<ScanContext> RunAsync(FakePhpServer srv, Action<AdvancedOptions> adv, string paths = "/index.php /", bool surface = false, bool level2 = false)
    {
        var cfg = new ScanConfig
        {
            TargetsText = "127.0.0.1", PortsText = srv.Port.ToString(), PathsText = paths, ConnectTimeoutMs = 2000, ReadTimeoutMs = 5000,
            Level1InfoPages = false, Level1EasterEgg = false, Level2 = level2, WafDetect = false, SurfaceDiscovery = surface, DiscoverNames = false, SizeProbeKiB = 4,
        };
        cfg.Advanced.SetAll(false);
        adv(cfg.Advanced);
        var r = new ScanResult { Input = "127.0.0.1", Host = "127.0.0.1", IsIpLiteral = true, Port = srv.Port, Scheme = "http", HostHeader = "127.0.0.1" };
        var ctx = new ScanContext
        {
            Config = cfg, Http = _http, Endpoint = new HttpEndpoint("http", "127.0.0.1", srv.Port), Result = r,
            Paths = paths.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList(), Log = _ => { }, Ct = CancellationToken.None,
        };
        await PhpFingerprint.RunAsync(ctx);
        Assert.True(r.HttpReachable);
        if (level2) await MitigationProbe.RunAsync(ctx);
        await AdvancedProbes.RunAsync(ctx);
        return ctx;
    }

    private static void OnlyReadOnlyMethods(FakePhpServer srv) =>
        Assert.All(srv.Requests, q => Assert.True(q.StartsWith("GET ") || q.StartsWith("HEAD ") || q.StartsWith("OPTIONS "), q));

    // ---------- interruttori ----------

    [Fact]
    public async Task AllSwitchesOff_NoAdvancedLines()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var ctx = await RunAsync(srv, _ => { });
        Assert.DoesNotContain(ctx.Result.Tests, t => t.Id.StartsWith("ADV-"));
        Assert.Equal("", ctx.Result.HeadVsGet);
        Assert.Null(ctx.Result.FastCgiExposed);
    }

    [Fact]
    public void Defaults_CtOff_FastCgiOn_KeysRoundTrip()
    {
        var o = new AdvancedOptions();
        Assert.False(o.CertificateTransparency);
        Assert.True(o.FastCgiProbe);
        Assert.Equal("sessionid", AdvancedOptions.Keys[^1]);   // v1.6: ultima chiave
        Assert.True(AdvancedOptions.Parse("headvsget,ct").CertificateTransparency);
    }

    // ---------- 1. HEAD contro GET, OPTIONS ----------

    [Fact]
    public async Task HeadVsGet_FindsHeadersOnlyOnHead_AndTraceInAllow()
    {
        using var srv = new FakePhpServer { Server = "nginx", AllowHeader = "GET, HEAD, POST, OPTIONS, TRACE" };
        srv.HeadOnlyHeaders.Add(new("X-Powered-By", "PHP/8.1.2"));
        var ctx = await RunAsync(srv, o => o.HeadVsGet = true);
        var r = ctx.Result;
        Assert.Contains("X-Powered-By", r.HeadVsGet);
        Assert.NotEqual("uguali", r.HeadVsGet);
        Assert.True(r.PhpDetected);
        Assert.Contains("X-Powered-By (HEAD)", r.PhpEvidence);
        Assert.Equal("8.1.2", r.PhpVersionRaw);
        Assert.Equal("GET, HEAD, POST, OPTIONS, TRACE", r.AllowedMethods);
        Assert.Contains(r.Exposures, e => e.StartsWith("/index.php (204): ") && e.Contains("TRACE"));
        Assert.Contains(r.Tests, t => t.Id == "ADV-HEAD" && t.Outcome == TestOutcome.Warn && t.Request == "HEAD /index.php");
        Assert.Contains(r.Tests, t => t.Id == "ADV-OPTIONS" && t.Outcome == TestOutcome.Warn && t.Request == "OPTIONS /index.php");
        Assert.Contains(srv.Requests, q => q.StartsWith("OPTIONS /index.php"));
        OnlyReadOnlyMethods(srv);
    }

    [Fact]
    public async Task HeadVsGet_SameResponses_IsEqual_NoAllow()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var ctx = await RunAsync(srv, o => o.HeadVsGet = true);
        Assert.Equal("uguali", ctx.Result.HeadVsGet);
        Assert.Equal("", ctx.Result.AllowedMethods);
        Assert.Empty(ctx.Result.Exposures);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-HEAD" && t.Outcome == TestOutcome.Info);
    }

    // ---------- 2. Composer ----------

    [Fact]
    public async Task Composer_PhpFloor_Libraries_AndVendorExposure()
    {
        using var srv = new FakePhpServer { Server = "nginx" };
        srv.PathBodies["/composer.json"] = (200, """{"name":"acme/site","require":{"php":">=8.1","monolog/monolog":"^3.0"}}""", "application/json");
        srv.PathBodies["/vendor/composer/installed.json"] = (200, """{"packages":[{"name":"monolog/monolog","version":"3.5.0"},{"name":"symfony/console","version":"v6.4.1"}],"dev":false}""", "application/json");
        srv.ExistingPaths["/vendor/autoload.php"] = 200;
        var ctx = await RunAsync(srv, o => o.Composer = true);
        var r = ctx.Result;
        Assert.Equal(">=8.1", r.PhpVersionFloor);
        Assert.Equal("/composer.json", r.PhpVersionFloorSource);
        Assert.Contains("monolog/monolog 3.5.0", r.Libraries);
        Assert.Contains("symfony/console 6.4.1", r.Libraries);
        Assert.True(r.PhpDetected);
        Assert.Contains(r.Exposures, e => e.StartsWith("/composer.json (200)"));
        Assert.Contains(r.Exposures, e => e.StartsWith("/vendor/composer/installed.json (200)"));
        Assert.Contains(r.Exposures, e => e.StartsWith("/vendor/autoload.php (200)"));
        Assert.Contains(r.Tests, t => t.Id == "ADV-COMPOSER" && t.Detail.Contains(">=8.1"));
        Assert.Contains(r.Tests, t => t.Id == "ADV-INSTALLED" && t.Outcome == TestOutcome.Fail);
        Assert.Contains(srv.Requests, q => q.StartsWith("HEAD /vendor/autoload.php"));
        OnlyReadOnlyMethods(srv);
    }

    [Fact]
    public async Task Composer_Html200_IsNotAManifest()
    {
        // server che risponde 200 HTML a composer.json: nessun vincolo, nessuna libreria
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        srv.PathBodies["/composer.json"] = (200, "<html>not json</html>", null);
        var ctx = await RunAsync(srv, o => o.Composer = true);
        Assert.Equal("", ctx.Result.PhpVersionFloor);
        Assert.Empty(ctx.Result.Libraries);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-COMPOSER" && t.Outcome == TestOutcome.Info);
    }

    [Fact]
    public void InstalledJson_Composer1List_IsRead()
    {
        using var doc = JsonDocument.Parse("""[{"name":"a/b","version":"1.2.3"},{"name":"c/d"}]""");
        var libs = AdvancedProbes.ReadInstalledPackages(doc.RootElement);
        Assert.Equal(["a/b 1.2.3", "c/d"], libs);
    }

    // ---------- 3. pagine di stato ----------

    private const string ServerInfoModPhp = """
        <html><head><title>Server Information</title></head><body>
        <h1>Apache Server Information</h1>
        <dl><dt><strong>Server Version:</strong> <font size="+1"><tt>Apache/2.4.58 (Debian) PHP/8.2.20</tt></font></dt>
        <dt><strong>Server Settings</strong></dt></dl>
        <h2>Loaded Modules</h2>
        <dl><dt><a href="#core.c"><tt>core.c</tt></a></dt><dt><a href="#mod_php.c"><tt>mod_php.c</tt></a></dt><dt><a href="#mod_ssl.c"><tt>mod_ssl.c</tt></a></dt></dl>
        </body></html>
        """;

    [Fact]
    public async Task ServerInfo_LoadedModules_GiveSapiAndVersion()
    {
        using var srv = new FakePhpServer { Server = "Apache" };
        srv.PathBodies["/server-info"] = (200, ServerInfoModPhp, null);
        var ctx = await RunAsync(srv, o => o.StatusPages = true);
        var r = ctx.Result;
        Assert.Equal("mod_php", r.Sapi);
        Assert.Contains("/server-info", r.SapiEvidence);
        Assert.True(r.PhpDetected);
        Assert.Equal("8.2.20", r.PhpVersionRaw);
        Assert.Equal("/server-info", r.PhpVersionSource);
        Assert.Contains(r.Exposures, e => e.StartsWith("/server-info (200)") && e.Contains("3 "));
        Assert.Contains(r.Tests, t => t.Id == "ADV-STATUS-INFO" && t.Outcome == TestOutcome.Fail);
        OnlyReadOnlyMethods(srv);
    }

    [Fact]
    public void SapiFromModules_RecognisesFcgiModules()
    {
        Assert.Equal("fpm", AdvancedProbes.SapiFromModules("<tt>core.c</tt> <tt>mod_proxy_fcgi.c</tt>"));
        Assert.Equal("cgi", AdvancedProbes.SapiFromModules("fcgid_module (shared)"));
        Assert.Equal("mod_php", AdvancedProbes.SapiFromModules("php7_module (shared)"));
        Assert.Equal("", AdvancedProbes.SapiFromModules("core.c mod_ssl.c"));
    }

    [Fact]
    public async Task FpmStatusPage_ProvesFpm_AndIsAnExposure()
    {
        using var srv = new FakePhpServer { Server = "nginx" };
        srv.PathBodies["/fpm-status"] = (200, "pool:                 www\nprocess manager:      dynamic\nstart time:           23/Oct/2026:10:00:00 +0200\naccepted conn:        12\n", "text/plain");
        srv.PathBodies["/status"] = (200, "<html>generic 200, not fpm</html>", null);
        var ctx = await RunAsync(srv, o => o.StatusPages = true);
        var r = ctx.Result;
        Assert.Equal("fpm", r.Sapi);
        Assert.True(r.PhpDetected);
        Assert.Contains(r.Exposures, e => e.StartsWith("/fpm-status (200)") && e.Contains("www"));
        Assert.DoesNotContain(r.Exposures, e => e.StartsWith("/status "));
        Assert.Contains(r.Tests, t => t.Id == "ADV-STATUS-FPM" && t.Outcome == TestOutcome.Fail && t.Detail.Contains("dynamic"));
    }

    [Fact]
    public async Task StatusPages_Generic200_IsNotCounted()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        foreach (var p in new[] { "/server-info", "/server-status", "/nginx_status", "/status", "/fpm-status", "/php-fpm/status" }) srv.PathBodies[p] = (200, "<html>welcome</html>", null);
        var ctx = await RunAsync(srv, o => o.StatusPages = true);
        Assert.Empty(ctx.Result.Exposures);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-STATUS" && t.Outcome == TestOutcome.Info);
    }

    // ---------- 4. file di versione ----------

    [Fact]
    public async Task WordPressReadme_SetsApplicationVersion_AndChecksInventory()
    {
        var old = TechnologyDatabase.Default;
        TechnologyDatabase.Default = TechnologyDatabase.Load(Path.Combine(LocalizationTests.RepoRoot(), "data"));
        try
        {
            using var srv = new FakePhpServer { Server = "nginx", HomeBody = "<html><head><link rel=\"stylesheet\" href=\"/wp-content/themes/x/style.css\"></head><body>wp</body></html>" };
            srv.PathBodies["/readme.html"] = (200, "<html><body><h1 id=\"logo\"><a href=\"https://wordpress.org/\">WordPress</a><br /> Version 6.4.2</h1></body></html>", null);
            var ctx = await RunAsync(srv, o => o.AppVersionFiles = true);
            var r = ctx.Result;
            Assert.Equal("WordPress", r.Application);
            Assert.Equal("6.4.2", r.ApplicationVersion);
            Assert.Contains(r.Exposures, e => e.StartsWith("/readme.html (200)") && e.Contains("6.4.2"));
            Assert.Contains(r.Tests, t => t.Id == "ADV-APPVERSION" && t.Outcome == TestOutcome.Warn && t.Detail.Contains("6.4.2"));
            // WordPress è "Affected" senza versione corretta nell'inventario: nessun confronto possibile, nessuna invenzione
            Assert.NotNull(TechnologyDatabase.Default.Inventory.Find("WordPress"));
            Assert.Equal("", r.AppVersionCheck);
            // solo il file di WordPress è stato chiesto (applicazione già riconosciuta)
            Assert.DoesNotContain(srv.Requests, q => q.Contains("joomla.xml"));
            OnlyReadOnlyMethods(srv);
        }
        finally { TechnologyDatabase.Default = old; }
    }

    [Fact]
    public async Task VersionFiles_Blind_RecogniseJoomla()
    {
        using var srv = new FakePhpServer { Server = "nginx" };
        srv.PathBodies["/administrator/manifests/files/joomla.xml"] = (200, "<?xml version=\"1.0\"?><extension type=\"file\" method=\"upgrade\"><name>files_joomla</name><version>4.4.3</version></extension>", "text/xml");
        var ctx = await RunAsync(srv, o => o.AppVersionFiles = true);
        Assert.Equal("Joomla", ctx.Result.Application);
        Assert.Equal("4.4.3", ctx.Result.ApplicationVersion);
        Assert.True(ctx.Result.PhpDetected);
        Assert.Contains(srv.Requests, q => q.StartsWith("GET /readme.html"));   // alla cieca prova tutti
    }

    [Fact]
    public void CompareAppVersion_AgainstFixedVersions()
    {
        NcscPackage Pkg(string fixedVersion) => new("X", [], "cat", "", "", new Dictionary<string, NcscVex>
        {
            ["CVE-2026-109618"] = new("Fixed", fixedVersion, "", ""),
            ["CVE-2026-109619"] = new("Fixed", fixedVersion, "", ""),
        });
        Assert.Equal("6.4.2 < corretto in 6.4.3", AdvancedProbes.CompareAppVersion("6.4.2", Pkg("6.4.3")));
        Assert.Equal("6.4.3 ≥ corretto in 6.4.3", AdvancedProbes.CompareAppVersion("6.4.3", Pkg("6.4.3")));
        Assert.Equal("6.5 ≥ corretto in 6.4.3", AdvancedProbes.CompareAppVersion("6.5", Pkg("6.4.3")));
        // più rami: conta quello con lo stesso major.minor
        Assert.Equal("8.3.30 < corretto in 8.3.36", AdvancedProbes.CompareAppVersion("8.3.30", Pkg("8.5.12, 8.4.27, 8.3.36, 8.2.35")));
        Assert.Equal("8.4.27 ≥ corretto in 8.4.27", AdvancedProbes.CompareAppVersion("8.4.27", Pkg("8.5.12, 8.4.27, 8.3.36, 8.2.35")));
        Assert.Equal("7.4.33 < corretto in 8.2.35", AdvancedProbes.CompareAppVersion("7.4.33", Pkg("8.5.12, 8.4.27, 8.3.36, 8.2.35")));
        Assert.Equal("9.0.1 ≥ corretto in 8.5.12", AdvancedProbes.CompareAppVersion("9.0.1", Pkg("8.5.12, 8.4.27, 8.3.36, 8.2.35")));
        // tra due rami corretti senza il proprio: ambiguo
        Assert.Equal("", AdvancedProbes.CompareAppVersion("8.3.1", Pkg("8.4.27, 8.2.35")));
        // affetto senza versione corretta, o versione non numerica: niente
        var affected = new NcscPackage("X", [], "cat", "", "", new Dictionary<string, NcscVex> { ["CVE-2026-109618"] = new("Affected", "", "", "") });
        Assert.Equal("", AdvancedProbes.CompareAppVersion("6.4.2", affected));
        Assert.Equal("", AdvancedProbes.CompareAppVersion("latest", Pkg("6.4.3")));
    }

    [Fact]
    public async Task SymfonyProfilerPhpinfo_IsExposure_AndVersionSource()
    {
        using var srv = new FakePhpServer { Server = "nginx" };
        srv.PathBodies["/_profiler/phpinfo"] = (200, "<html><h1 class=\"p\">PHP Version 8.2.10</h1>phpinfo()</html>", null);
        var ctx = await RunAsync(srv, o => o.AppVersionFiles = true);
        Assert.Equal("8.2.10", ctx.Result.PhpVersionRaw);
        Assert.Equal("/_profiler/phpinfo", ctx.Result.PhpVersionSource);
        Assert.Equal("Symfony", ctx.Result.Application);
        Assert.Contains(ctx.Result.Exposures, e => e.StartsWith("/_profiler/phpinfo (200)"));
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-DEBUGPAGE" && t.Outcome == TestOutcome.Fail);
    }

    // ---------- 5. FastCGI ----------

    /// <summary>Server FastCGI finto: risponde a FCGI_GET_VALUES con FCGI_GET_VALUES_RESULT e registra tutto ciò che riceve.</summary>
    private sealed class FakeFastCgi : IDisposable
    {
        private readonly TcpListener _l = new(IPAddress.Loopback, 0);
        public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;
        public readonly List<byte[]> Received = [];
        public FakeFastCgi()
        {
            _l.Start();
            _ = Task.Run(async () =>
            {
                while (true)
                {
                    TcpClient c;
                    try { c = await _l.AcceptTcpClientAsync(); } catch { return; }
                    _ = Task.Run(async () =>
                    {
                        using var client = c;
                        var ns = client.GetStream();
                        var hdr = new byte[8];
                        int got = 0;
                        while (got < 8) { int n = await ns.ReadAsync(hdr.AsMemory(got)); if (n <= 0) return; got += n; }
                        int len = BinaryPrimitives.ReadUInt16BigEndian(hdr.AsSpan(4)) + hdr[6];
                        var body = new byte[len];
                        got = 0;
                        while (got < len) { int n = await ns.ReadAsync(body.AsMemory(got)); if (n <= 0) return; got += n; }
                        lock (Received) Received.Add([.. hdr, .. body]);
                        if (hdr[1] != FastCgiProbe.TypeGetValues) return;
                        var content = new List<byte>();
                        foreach (var (k, v) in new[] { ("FCGI_MAX_CONNS", "10"), ("FCGI_MAX_REQS", "50"), ("FCGI_MPXS_CONNS", "0") })
                        {
                            content.Add((byte)k.Length); content.Add((byte)v.Length);
                            content.AddRange(Encoding.ASCII.GetBytes(k)); content.AddRange(Encoding.ASCII.GetBytes(v));
                        }
                        int pad = (8 - content.Count % 8) % 8;
                        var resp = new byte[8 + content.Count + pad];
                        resp[0] = 1; resp[1] = FastCgiProbe.TypeGetValuesResult;
                        BinaryPrimitives.WriteUInt16BigEndian(resp.AsSpan(4), (ushort)content.Count);
                        resp[6] = (byte)pad;
                        content.CopyTo(resp, 8);
                        await ns.WriteAsync(resp);
                        await ns.FlushAsync();
                    });
                }
            });
        }
        public void Dispose() { try { _l.Stop(); } catch { } }
    }

    [Fact]
    public async Task FastCgi_GetValues_IsAnswered_AndNothingElseIsSent()
    {
        using var fcgi = new FakeFastCgi();
        var res = await FastCgiProbe.ProbeAsync("127.0.0.1", fcgi.Port, 2000, CancellationToken.None);
        Assert.True(res.Exposed);
        Assert.Contains(res.Values, v => v.Key == "FCGI_MPXS_CONNS" && v.Value == "0");
        Assert.Contains("FCGI_MAX_CONNS=10", res.Detail);
        // un solo record, di tipo FCGI_GET_VALUES, requestId 0: nessun BEGIN_REQUEST, nessun parametro, nessuno script
        var rec = Assert.Single(fcgi.Received);
        Assert.Equal(FastCgiProbe.BuildGetValues(), rec);
        Assert.Equal(9, rec[1]);
        Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(rec.AsSpan(2)));
        Assert.Equal(0, rec.Length % 8);
    }

    [Fact]
    public async Task FastCgi_ClosedPort_IsFalse()
    {
        int port = FakePhpServer.FreePort();
        var res = await FastCgiProbe.ProbeAsync("127.0.0.1", port, 2000, CancellationToken.None);
        Assert.False(res.Exposed);
        Assert.Equal("connect", res.ErrorKind);
    }

    [Fact]
    public async Task FastCgi_HttpServerOnPort_IsNotFastCgi()
    {
        using var srv = new FakePhpServer();
        var res = await FastCgiProbe.ProbeAsync("127.0.0.1", srv.Port, 3000, CancellationToken.None);
        Assert.False(res.Exposed);
    }

    [Fact]
    public async Task HostLevel_FastCgiExposed_FillsResultAndExposure()
    {
        using var fcgi = new FakeFastCgi();
        int oldPort = AdvancedProbes.FastCgiPort;
        AdvancedProbes.FastCgiPort = fcgi.Port;
        try
        {
            var cfg = new ScanConfig();
            cfg.Advanced.SetAll(false);
            cfg.Advanced.FastCgiProbe = true;
            var r = new ScanResult { Host = "127.0.0.1", IsIpLiteral = true, Port = 80 };
            await AdvancedProbes.RunHostLevelAsync(cfg, r, CancellationToken.None);
            Assert.True(r.FastCgiExposed);
            Assert.Contains("FCGI_MPXS_CONNS=0", r.FastCgiDetail);
            Assert.Equal("fpm", r.Sapi);
            Assert.True(r.PhpDetected);
            Assert.Contains(r.Exposures, e => e.StartsWith($"tcp/{fcgi.Port}:"));
            Assert.Contains(r.Tests, t => t.Id == "ADV-HOST-FASTCGI" && t.Outcome == TestOutcome.Fail);

            // porta chiusa → false, nessuna esposizione
            fcgi.Dispose();
            var r2 = new ScanResult { Host = "127.0.0.1", IsIpLiteral = true, Port = 80 };
            await AdvancedProbes.RunHostLevelAsync(cfg, r2, CancellationToken.None);
            Assert.False(r2.FastCgiExposed);
            Assert.Empty(r2.Exposures);
            Assert.Contains(r2.Tests, t => t.Id == "ADV-HOST-FASTCGI" && t.Outcome == TestOutcome.Info);
        }
        finally { AdvancedProbes.FastCgiPort = oldPort; }
    }

    // ---------- 6. comportamenti PHP ----------

    [Fact]
    public async Task PathInfo_AndXmlrpc_AreEvidence()
    {
        using var srv = new FakePhpServer { Server = "nginx", PathInfo = true };
        srv.PathBodies["/xmlrpc.php"] = (405, "XML-RPC server accepts POST requests only.", "text/plain");
        var ctx = await RunAsync(srv, o => o.PhpBehaviours = true);
        var r = ctx.Result;
        Assert.True(r.PhpDetected);
        Assert.Contains("PATH_INFO", r.PhpEvidence);
        Assert.Contains(r.Tests, t => t.Id == "ADV-PATHINFO" && t.Outcome == TestOutcome.Warn && t.Request == "GET /index.php/x");
        Assert.Equal("WordPress", r.Application);
        Assert.Contains(r.Exposures, e => e.StartsWith("/xmlrpc.php (405)"));
        Assert.Contains(r.Tests, t => t.Id == "ADV-XMLRPC" && t.Outcome == TestOutcome.Warn);
        OnlyReadOnlyMethods(srv);
    }

    [Fact]
    public async Task PathInfo_NotActive_IsInfo()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };   // /index.php/x → 404
        var ctx = await RunAsync(srv, o => o.PhpBehaviours = true);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-PATHINFO" && t.Outcome == TestOutcome.Info);
        Assert.DoesNotContain("PATH_INFO", ctx.Result.PhpEvidence);
    }

    [Fact]
    public async Task SourceLeak_Phps_HeadOnly()
    {
        using var srv = new FakePhpServer { Server = "nginx" };
        srv.ExistingPaths["/index.phps"] = 200;
        var ctx = await RunAsync(srv, o => o.PhpBehaviours = true);
        var r = ctx.Result;
        Assert.Contains(r.Exposures, e => e.StartsWith("/index.phps (200)"));
        Assert.DoesNotContain(r.Exposures, e => e.StartsWith("/index.php~"));
        Assert.True(r.PhpDetected);
        Assert.Contains(r.Tests, t => t.Id == "ADV-SOURCE" && t.Outcome == TestOutcome.Fail && t.Detail.Contains("/index.phps"));
        Assert.Contains(srv.Requests, q => q.StartsWith("HEAD /index.phps"));
        Assert.DoesNotContain(srv.Requests, q => q.StartsWith("GET /index.phps"));
        Assert.Contains(srv.Requests, q => q.StartsWith("HEAD /index.php.bak"));
    }

    [Fact]
    public async Task ExtraPhpinfoPage_IsVersionSource()
    {
        using var srv = new FakePhpServer { Server = "nginx" };
        srv.PathBodies["/pi.php"] = (200, "<html><h1 class=\"p\">PHP Version 7.4.33</h1>phpinfo()</html>", null);
        var ctx = await RunAsync(srv, o => o.PhpBehaviours = true);
        Assert.Equal("7.4.33", ctx.Result.PhpVersionRaw);
        Assert.Equal("/pi.php", ctx.Result.PhpVersionSource);
        Assert.Equal(VersionStatus.EndOfLife, ctx.Result.VersionStatus);
        Assert.Contains(ctx.Result.Exposures, e => e.StartsWith("/pi.php (200)"));
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-PHPINFO" && t.Outcome == TestOutcome.Fail);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-VERSION");
    }

    // ---------- 7. livello 2 sugli altri percorsi ----------

    [Fact]
    public async Task Level2AllPaths_TestsOtherPhpPaths_AndSummarises()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", Multipart = FakePhpServer.MultipartPolicy.BlockAll };
        srv.ExistingPaths["/login.php"] = 200;
        srv.ExistingPaths["/admin.php"] = 200;
        srv.ExistingPaths["/third.php"] = 200;
        var ctx = await RunAsync(srv, o => { o.Level2AllPaths = true; o.Level2MaxPaths = 2; }, level2: true);
        // il motore valorizza SurfacePhpPaths dalla scoperta della superficie: qui si simula
        ctx.SurfacePhpPaths = ["/index.php", "/login.php", "/admin.php", "/third.php"];
        await AdvancedProbes.RunAsync(ctx);
        var r = ctx.Result;
        Assert.Equal(MultipartBarrier.Blocked, r.Multipart);
        Assert.Contains("altri percorsi: 2 bloccati su 2", r.MultipartDetail);
        Assert.Contains(r.Tests, t => t.Id == "ADV-L2-/login.php" && t.Outcome == TestOutcome.Pass && t.Request == "POST /login.php");
        Assert.Contains(r.Tests, t => t.Id == "ADV-L2-/admin.php" && t.Outcome == TestOutcome.Pass);
        Assert.DoesNotContain(r.Tests, t => t.Id == "ADV-L2-/third.php");     // oltre il massimo
        Assert.DoesNotContain(r.Tests, t => t.Id == "ADV-L2-/index.php");     // il principale è già coperto dal livello 2
        Assert.Equal(2, srv.Requests.Count(q => q.StartsWith("POST /login.php")));   // url-encoded + multipart minimo, nient'altro
    }

    [Fact]
    public async Task Level2AllPaths_SkippedWhenLevel2Off()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var ctx = await RunAsync(srv, o => o.Level2AllPaths = true, level2: false);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-L2-ALL" && t.Outcome == TestOutcome.Skipped);
        OnlyReadOnlyMethods(srv);
    }

    // ---------- 8. User-Agent da browser ----------

    [Fact]
    public async Task BrowserUserAgent_RevealsTheRealPage_AndKeepsToolName()
    {
        using var srv = new FakePhpServer
        {
            Server = "nginx", HomeBody = "<html><head><title>Access denied</title></head><body>bot</body></html>",
            BrowserUaBody = "<html><head><title>Il mio sito</title><meta name=\"generator\" content=\"WordPress 6.5.2\"></head><body>" + new string('x', 3000) + "</body></html>",
        };
        var ctx = await RunAsync(srv, o => o.BrowserUserAgent = true);
        var r = ctx.Result;
        Assert.NotEqual("uguale", r.BrowserUaResult);
        Assert.Contains("titolo", r.BrowserUaResult);
        Assert.Equal("WordPress", r.Application);
        Assert.True(r.PhpDetected);
        Assert.Contains(r.Tests, t => t.Id == "ADV-BROWSERUA" && t.Outcome == TestOutcome.Warn && t.Detail.Contains("WordPress"));
        Assert.Contains("Mozilla/5.0", srv.LastUserAgent);
        Assert.Contains("PhpVulnScanner/", srv.LastUserAgent);
        Assert.Contains("PhpVulnScanner/", AdvancedProbes.BrowserUserAgent);
    }

    [Fact]
    public async Task BrowserUserAgent_SameResponse_IsEqual()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var ctx = await RunAsync(srv, o => o.BrowserUserAgent = true);
        Assert.Equal("uguale", ctx.Result.BrowserUaResult);
    }

    // ---------- 9. componenti ----------

    [Fact]
    public void Components_FromBodies()
    {
        string body = """
            <link rel="stylesheet" href="https://example.org/wp-content/plugins/woocommerce/assets/css/woocommerce.css?ver=8.5.1" />
            <script src="/wp-content/themes/astra/assets/js/minified/style.min.js?ver=4.6.0"></script>
            <script src="/wp-content/plugins/contact-form-7/includes/js/index.js"></script>
            <img src="/wp-content/plugins/woocommerce/assets/images/placeholder.png">
            <a href="/index.php?option=com_content&amp;view=article&amp;id=5">x</a>
            <script src="/media/com_hikashop/js/hikashop.js"></script>
            <script src="/modules/contrib/webform/js/webform.js?v=6"></script>
            <link href="/typo3conf/ext/news/Resources/Public/Css/news.css">
            """;
        var comps = AdvancedProbes.ExtractComponents([body]);
        Assert.Contains("plugin:woocommerce 8.5.1", comps);
        Assert.Contains("theme:astra 4.6.0", comps);
        Assert.Contains("plugin:contact-form-7", comps);
        Assert.Contains("component:com_content", comps);
        Assert.Contains("component:com_hikashop", comps);
        Assert.Contains("module:webform", comps);
        Assert.Contains("extension:news", comps);
        Assert.Equal(comps.Count, comps.Distinct().Count());
        Assert.Single(comps, c => c.StartsWith("plugin:woocommerce"));
    }

    [Fact]
    public async Task Components_NoExtraRequests()
    {
        using var srv = new FakePhpServer { Server = "nginx", HomeBody = "<html><script src=\"/wp-content/plugins/akismet/akismet.js?ver=5.3\"></script></html>" };
        var ctx = await RunAsync(srv, o => o.Components = true);
        int before = srv.Requests.Count;
        Assert.Contains("plugin:akismet 5.3", ctx.Result.Components);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-COMPONENTS");
        Assert.Equal(2, before);   // solo le due GET del livello 1
    }

    // ---------- 10. esposizioni ----------

    [Fact]
    public async Task Exposures_GitHead_AndEnv_HeadOnly()
    {
        using var srv = new FakePhpServer { Server = "nginx" };
        srv.PathBodies["/.git/HEAD"] = (200, "ref: refs/heads/main\n", "text/plain");
        srv.ExistingPaths["/.env"] = 200;
        srv.ExistingPaths["/.svn/entries"] = 403;
        srv.ExistingPaths["/composer.lock"] = 200;
        var ctx = await RunAsync(srv, o => o.Exposures = true);
        var r = ctx.Result;
        Assert.Contains(r.Exposures, e => e.StartsWith("/.git/HEAD (200)"));
        Assert.Contains(r.Exposures, e => e.StartsWith("/.env (200)"));
        Assert.Contains(r.Exposures, e => e.StartsWith("/.svn/entries (403)") && e.Contains("403"));
        Assert.Contains(r.Exposures, e => e.StartsWith("/composer.lock (200)"));
        Assert.DoesNotContain(r.Exposures, e => e.StartsWith("/backup.zip"));
        Assert.True(r.PhpDetected);   // composer.lock e .env sono file di un'applicazione PHP
        Assert.Contains(r.Tests, t => t.Id == "ADV-EXPOSURES" && t.Outcome == TestOutcome.Fail);
        Assert.Contains(srv.Requests, q => q.StartsWith("GET /.git/HEAD"));
        Assert.Contains(srv.Requests, q => q.StartsWith("HEAD /.env"));
        Assert.DoesNotContain(srv.Requests, q => q.StartsWith("GET /.env"));
        Assert.DoesNotContain(srv.Requests, q => q.StartsWith("GET /composer.lock"));
        Assert.DoesNotContain(srv.Requests, q => q.StartsWith("GET /phpinfo.php"));
        OnlyReadOnlyMethods(srv);
    }

    [Fact]
    public async Task Exposures_GitHead_Html200_IsNotGit()
    {
        using var srv = new FakePhpServer { Server = "nginx" };
        srv.PathBodies["/.git/HEAD"] = (200, "<html>soft 404</html>", null);
        var ctx = await RunAsync(srv, o => o.Exposures = true);
        Assert.DoesNotContain(ctx.Result.Exposures, e => e.StartsWith("/.git/HEAD"));
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-EXPOSURES" && t.Outcome == TestOutcome.Info);
    }

    [Fact]
    public async Task Exposures_CatchAllServer_IsSkipped()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20", MissingPhp = (200, "<html>home for everything</html>") };
        srv.ExistingPaths["/.env"] = 200;
        var ctx = await RunAsync(srv, o => { o.Exposures = true; o.PhpBehaviours = true; });
        Assert.Empty(ctx.Result.Exposures);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-EXPOSURES" && t.Outcome == TestOutcome.Skipped);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-PATHINFO" && t.Outcome == TestOutcome.Skipped);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-SOURCE" && t.Outcome == TestOutcome.Skipped);
        Assert.DoesNotContain(srv.Requests, q => q.StartsWith("HEAD /.env"));
    }

    // ---------- 11. PTR e ServerName ----------

    [Fact]
    public async Task Ptr_OnLoopback_DoesNotCrash_AndFiltersLocalhost()
    {
        var cfg = new ScanConfig();
        cfg.Advanced.SetAll(false);
        cfg.Advanced.ReverseDns = true;
        var r = new ScanResult { Host = "127.0.0.1", IsIpLiteral = true, Port = 443 };
        await AdvancedProbes.RunHostLevelAsync(cfg, r, CancellationToken.None);
        Assert.Contains(r.Tests, t => t.Id == "ADV-HOST-PTR" && t.Detail.Contains("127.0.0.1"));
        Assert.DoesNotContain(r.DiscoveredNames, n => n.Contains("localhost"));
        Assert.All(r.DiscoveredNames, n => Assert.True(NameDiscovery.IsValidHostName(n)));
        Assert.DoesNotContain(r.Tests, t => t.Id == "ADV-HOST-CT");
        Assert.DoesNotContain(r.Tests, t => t.Id == "ADV-HOST-FASTCGI");
    }

    [Fact]
    public async Task ApacheErrorPage_ServerName_IsDiscovered()
    {
        using var srv = new FakePhpServer { Server = "Apache/2.4.58 (Debian)", HomeBody = "<html><body><h1>Not Found</h1><hr>\n<address>Apache/2.4.58 (Debian) Server at www.example.org Port 443</address>\n</body></html>" };
        var ctx = await RunAsync(srv, o => o.ReverseDns = true);
        Assert.Contains("www.example.org", ctx.Result.DiscoveredNames);
        Assert.Contains(ctx.Result.Tests, t => t.Id == "ADV-SERVERNAME" && t.Detail.Contains("www.example.org"));
    }

    // ---------- 12. Certificate Transparency ----------

    [Fact]
    public void CrtSh_Json_IsParsed_WithoutNetwork()
    {
        string json = """
            [{"issuer_name":"C=US, O=Let's Encrypt","common_name":"www.example.org","name_value":"example.org\nwww.example.org","id":1},
             {"common_name":"*.example.org","name_value":"*.example.org\nmail.Example.org.","id":2},
             {"common_name":"192.0.2.1","name_value":"bad host\nx.example.orgindex.php","id":3}]
            """;
        var names = CertificateTransparency.ParseCrtSh(json);
        Assert.Equal(3, names.Count);
        Assert.Equal(["example.org", "mail.example.org", "www.example.org"], names.OrderBy(n => n, StringComparer.Ordinal).ToList());
        Assert.Empty(CertificateTransparency.ParseCrtSh("{}"));
        Assert.Empty(CertificateTransparency.ParseCrtSh(""));
    }

    [Fact]
    public void RegistrableDomain_HandlesPublicSuffixes()
    {
        Assert.Equal("example.org", CertificateTransparency.RegistrableDomain("www.shop.example.org"));
        Assert.Equal("example.co.uk", CertificateTransparency.RegistrableDomain("www.example.co.uk"));
        Assert.Equal("example.org", CertificateTransparency.RegistrableDomain("*.example.org"));
        Assert.Null(CertificateTransparency.RegistrableDomain("192.0.2.1"));
        Assert.Null(CertificateTransparency.RegistrableDomain("localhost"));
    }

    [Fact]
    public async Task CertificateTransparency_OffByDefault_NoDomains_IsSkipped()
    {
        // spenta: nessuna riga; accesa senza domini: "saltata" senza alcuna richiesta esterna
        var cfg = new ScanConfig();
        var r = new ScanResult { Host = "192.0.2.10", IsIpLiteral = true, Port = 443 };
        Assert.False(cfg.Advanced.CertificateTransparency);
        cfg.Advanced.SetAll(false);
        await AdvancedProbes.RunHostLevelAsync(cfg, r, CancellationToken.None);
        Assert.DoesNotContain(r.Tests, t => t.Id == "ADV-HOST-CT");
        cfg.Advanced.CertificateTransparency = true;
        await AdvancedProbes.RunHostLevelAsync(cfg, r, CancellationToken.None);
        Assert.Contains(r.Tests, t => t.Id == "ADV-HOST-CT" && t.Outcome == TestOutcome.Skipped);
    }

    // ---------- robustezza ----------

    [Fact]
    public async Task Probes_StopInsisting_WhenTheServerGoesAway()
    {
        var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = new ScanConfig { PathsText = "/index.php", ConnectTimeoutMs = 1000, ReadTimeoutMs = 2000, Level1InfoPages = false, Level2 = false, WafDetect = false, SurfaceDiscovery = false };
        cfg.Advanced.SetAll(true);
        cfg.Advanced.CertificateTransparency = false;
        var r = new ScanResult { Input = "127.0.0.1", Host = "127.0.0.1", IsIpLiteral = true, Port = srv.Port, Scheme = "http", HostHeader = "127.0.0.1" };
        var ctx = new ScanContext { Config = cfg, Http = _http, Endpoint = new HttpEndpoint("http", "127.0.0.1", srv.Port), Result = r, Paths = ["/index.php"], Log = _ => { }, Ct = CancellationToken.None };
        await PhpFingerprint.RunAsync(ctx);
        Assert.True(r.HttpReachable);
        srv.Dispose();   // il server sparisce prima dei test avanzati
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await AdvancedProbes.RunAsync(ctx);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(20), sw.Elapsed.ToString());
        Assert.Equal("", r.Error);
        Assert.DoesNotContain(r.Tests, t => t.Outcome == TestOutcome.Error && t.Detail.Contains("errore interno"));
        // le sonde con tutto acceso lasciano al massimo poche righe: la connessione persa ferma le successive
        Assert.True(r.Tests.Count(t => t.Id.StartsWith("ADV-")) <= 6, string.Join(" | ", r.Tests.Select(t => t.Id)));
    }

    [Fact]
    public async Task Cancellation_Propagates()
    {
        using var srv = new FakePhpServer { PoweredBy = "PHP/8.3.20" };
        var cfg = new ScanConfig { PathsText = "/index.php", Level1InfoPages = false, Level2 = false, WafDetect = false, SurfaceDiscovery = false };
        cfg.Advanced.SetAll(true);
        var r = new ScanResult { Input = "127.0.0.1", Host = "127.0.0.1", IsIpLiteral = true, Port = srv.Port, Scheme = "http", HostHeader = "127.0.0.1" };
        var ctx = new ScanContext { Config = cfg, Http = _http, Endpoint = new HttpEndpoint("http", "127.0.0.1", srv.Port), Result = r, Paths = ["/index.php"], Log = _ => { }, Ct = CancellationToken.None };
        await PhpFingerprint.RunAsync(ctx);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        var ctx2 = new ScanContext { Config = cfg, Http = _http, Endpoint = ctx.Endpoint, Result = r, Paths = ctx.Paths, Log = _ => { }, Ct = cts.Token, Baseline = ctx.Baseline, PrimaryPath = ctx.PrimaryPath };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AdvancedProbes.RunAsync(ctx2));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => AdvancedProbes.RunHostLevelAsync(cfg, r, cts.Token));
    }
}
