using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Targets;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Tests;

public class TargetParserTests
{
    [Fact]
    public void ParsesIpsNamesCidrAndRanges()
    {
        var r = TargetParser.Parse("192.0.2.1, example.com\n198.51.100.0/30 # commento\n203.0.113.10-203.0.113.12\n203.0.113.20-22\n# solo commento\nhttps://www.example.org:8443/path\n[2001:db8::1]:443");
        Assert.Empty(r.Errors);
        var hosts = r.Targets.Select(t => t.Host).ToList();
        Assert.Equal(["192.0.2.1", "example.com", "198.51.100.1", "198.51.100.2", "203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.20", "203.0.113.21", "203.0.113.22", "www.example.org", "2001:db8::1"], hosts);
        Assert.True(r.Targets[0].IsIpLiteral);
        Assert.False(r.Targets[1].IsIpLiteral);
    }

    [Fact]
    public void Cidr24SkipsNetworkAndBroadcast_AndDeduplicates()
    {
        var r = TargetParser.Parse("10.0.0.0/24\n10.0.0.5");
        Assert.Equal(254, r.Targets.Count);
        Assert.DoesNotContain(r.Targets, t => t.Host is "10.0.0.0" or "10.0.0.255");
    }

    [Fact]
    public void RejectsInvalidEntries_AndTooLargeNetworks()
    {
        var r = TargetParser.Parse("nonsense!!\n10.0.0.0/8\n1.2.3.4-1.2.3.1\n300.1.1.1");
        Assert.Empty(r.Targets);
        Assert.Equal(4, r.Errors.Count);
    }

    [Fact]
    public void ParsesPortsAndPaths()
    {
        var ports = TargetParser.ParsePorts("443, 8443 80\n8000-8002 x 70000", out var errors);
        Assert.Equal([443, 8443, 80, 8000, 8001, 8002], ports);
        Assert.Equal(["x", "70000"], errors);
        Assert.Equal(["/", "/index.php", "/admin/"], TargetParser.ParsePaths("/ index.php\n/admin/"));
    }
}

public class PhpVersionTests
{
    [Theory]
    [InlineData("PHP/8.3.36", VersionStatus.Fixed, "8.3.36")]
    [InlineData("PHP/8.3.40", VersionStatus.Fixed, "8.3.36")]
    [InlineData("PHP/8.3.35", VersionStatus.VulnerableSupported, "8.3.36")]
    [InlineData("PHP/8.2.35", VersionStatus.Fixed, "8.2.35")]
    [InlineData("PHP/8.2.34", VersionStatus.VulnerableSupported, "8.2.35")]
    [InlineData("PHP/8.4.27", VersionStatus.Fixed, "8.4.27")]
    [InlineData("PHP/8.5.11", VersionStatus.VulnerableSupported, "8.5.12")]
    [InlineData("PHP/8.1.34", VersionStatus.EndOfLife, null)]
    [InlineData("PHP/7.4.33-1+deb11u1", VersionStatus.EndOfLife, null)]
    [InlineData("PHP/5.6.40", VersionStatus.EndOfLife, null)]
    [InlineData("PHP/5.3.29", VersionStatus.Ancient, null)]
    [InlineData("PHP/8.6.0", VersionStatus.Newer, null)]
    [InlineData("PHP/8.3", VersionStatus.VulnerableSupported, "8.3.36")]
    public void StatusAgainstFixedReleases(string banner, VersionStatus expected, string? fixedRelease)
    {
        var v = PhpVersion.Parse(banner)!;
        Assert.Equal(expected, v.Status());
        Assert.Equal(fixedRelease, v.FixedRelease);
    }

    [Fact]
    public void ParsesFromServerHeaderAndPhpinfo_AndKeepsPackageSuffix()
    {
        var a = PhpVersion.Parse("Apache/2.4.62 (Debian) OpenSSL/3.0.15 PHP/8.2.26")!;
        Assert.Equal("8.2.26", a.Normalized);
        Assert.False(a.HasPackageSuffix);
        var b = PhpVersion.Parse("PHP Version 7.4.33-1ubuntu2")!;
        Assert.Equal("7.4.33", b.Normalized);
        Assert.Equal("1ubuntu2", b.Suffix);
        Assert.True(b.HasPackageSuffix);
        Assert.Null(PhpVersion.Parse("Apache/2.4"));
        Assert.Null(PhpVersion.Parse(""));
    }

    [Fact]
    public void SessionIdFormat()
    {
        Assert.True(PhpFingerprint.SidLooksNormal("abcdefghijklmnopqrstuvwxyz012345"));   // 32 caratteri base-32 (default 7.1+)
        Assert.True(PhpFingerprint.SidLooksNormal("0123456789abcdef0123456789"));         // 26 caratteri hex
        Assert.False(PhpFingerprint.SidLooksNormal("abc"));
        Assert.False(PhpFingerprint.SidLooksNormal(new string('a', 40) + "\u0001ÿ"));
    }
}

public class VerdictTests
{
    private static ScanResult Php(string version, MultipartBarrier mp = MultipartBarrier.Accepted)
    {
        var r = new ScanResult { Input = "h", Host = "h", Port = 443, HttpReachable = true, PhpDetected = true, PhpEvidence = "X-Powered-By", Multipart = mp };
        if (version.Length > 0)
        {
            var v = PhpVersion.Parse(version)!;
            r.PhpVersionRaw = v.Raw; r.PhpVersionSource = "X-Powered-By"; r.VersionStatus = v.Status(); r.FixedRelease = v.FixedRelease ?? ""; r.PackageSuffix = v.HasPackageSuffix;
        }
        return r;
    }

    [Fact]
    public void Rules()
    {
        var r = Php("8.3.10"); VerdictEngine.Apply(r); Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        r = Php("8.3.36"); VerdictEngine.Apply(r); Assert.Equal(Verdict.FixedByVersion, r.Verdict);
        r = Php("7.4.33-1+deb"); VerdictEngine.Apply(r); Assert.Equal(Verdict.LikelyVulnerable, r.Verdict); Assert.Contains("backport", r.VerdictReason);
        r = Php("8.3.10", MultipartBarrier.Blocked); VerdictEngine.Apply(r); Assert.Equal(Verdict.MitigatedAtEdge, r.Verdict); Assert.Contains("8.3.10", r.VerdictReason);
        r = Php("8.3.10", MultipartBarrier.PartiallyBlocked); VerdictEngine.Apply(r); Assert.Equal(Verdict.VulnerableByVersion, r.Verdict);
        r = Php(""); VerdictEngine.Apply(r); Assert.Equal(Verdict.Undetermined, r.Verdict);
        r = Php(""); r.PhpDetected = false; r.PhpEvidence = ""; VerdictEngine.Apply(r); Assert.Equal(Verdict.NoPhpDetected, r.Verdict);
        r = new ScanResult { HttpReachable = false, Alive = AliveState.NoResponse }; VerdictEngine.Apply(r); Assert.Equal(Verdict.NotReachable, r.Verdict);
        // multipart bloccato senza alcun indizio di PHP: resta "PHP non rilevato", non "mitigato"
        r = Php("", MultipartBarrier.Blocked); r.PhpDetected = false; r.PhpEvidence = ""; VerdictEngine.Apply(r); Assert.Equal(Verdict.NoPhpDetected, r.Verdict);
    }
}

public class WafDetectorTests
{
    private static HttpSnapshot Snap(int status, params (string, string)[] headers) =>
        new() { Status = status, Reason = "x", Headers = headers.Select(h => new KeyValuePair<string, string>(h.Item1, h.Item2)).ToList(), Body = status >= 400 ? "<html>Attention Required! | Cloudflare Ray ID: 1</html>" : "<html>ok</html>" };

    [Fact]
    public void RecognisesSignaturesFromHeadersCookiesAndBody()
    {
        var f = WafDetector.FromSnapshot(Snap(200, ("Server", "cloudflare"), ("cf-ray", "abc-FCO"), ("Set-Cookie", "BIGipServerpool=1.2.3; path=/"), ("Via", "1.1 varnish")));
        Assert.Contains(f, x => x.Name == "Cloudflare" && x.Category == WafCategory.Cdn && x.Confidence == Confidence.High);
        Assert.Contains(f, x => x.Name.StartsWith("F5 BIG-IP") && x.Category == WafCategory.LoadBalancer);
        Assert.Contains(f, x => x.Name == "Varnish");
        // il corpo conta solo con stato di errore
        Assert.DoesNotContain(WafDetector.FromSnapshot(Snap(200, ("Server", "nginx"))), x => x.Name.Contains("Cloudflare"));
        Assert.Contains(WafDetector.FromSnapshot(Snap(403, ("Server", "nginx"))), x => x.Name.StartsWith("Cloudflare") && x.Category == WafCategory.Waf);
    }

    [Fact]
    public void BehaviourDifferenceMeansFilter()
    {
        var b = WafDetector.FromBehaviour(Snap(200, ("Server", "Apache")), Snap(403, ("Server", "Apache")));
        Assert.NotNull(b);
        Assert.Equal(WafCategory.Waf, b!.Category);
        Assert.Null(WafDetector.FromBehaviour(Snap(200, ("Server", "Apache")), Snap(200, ("Server", "Apache"))));
    }

    [Fact]
    public void RepetitionAndDnsHintsLoadBalancing()
    {
        var f = WafDetector.FromRepetition(["1.1.1.1", "1.1.1.2"], [Snap(200, ("Server", "a"), ("X-Backend", "n1")), Snap(200, ("Server", "a"), ("X-Backend", "n2"))]);
        Assert.Equal(2, f.Count);
        Assert.All(f, x => Assert.Equal(WafCategory.LoadBalancer, x.Category));
    }
}
