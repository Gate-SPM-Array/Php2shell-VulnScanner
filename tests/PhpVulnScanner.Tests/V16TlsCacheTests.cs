using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Tests;

/// <summary>v1.6: stato del certificato (CertificateStatus, TlsProbe.Describe), cache/intermediario (PhpHints.CacheHint),
/// versione di PHP dichiarata nel corpo, scarti dell'header Date rispetto all'ora di ricezione.</summary>
public class V16TlsCacheTests
{
    private static readonly DateTime Now = new(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc);

    private static TlsInfo Cert(DateTime? notAfter = null, DateTime? notBefore = null, bool selfSigned = false, bool? chain = true, string chainError = "",
                                bool nameOk = true, int keyBits = 2048, string sig = "sha256RSA", bool handshake = true) => new()
    {
        Handshake = handshake, Protocol = "Tls13", Subject = "www.example.org", Issuer = selfSigned ? "www.example.org" : "Example CA",
        NotAfter = notAfter ?? Now.AddDays(300), NotBefore = notBefore ?? Now.AddDays(-30), SelfSigned = selfSigned, ChainTrusted = chain, ChainError = chainError,
        NameMatches = nameOk, KeyBits = keyBits, SignatureAlgorithm = sig,
    };

    private static HttpSnapshot Snap(string body = "<html><body>ok</body></html>", string method = "GET", DateTime? received = null, params (string, string)[] headers) => new()
    {
        Method = method, Url = "https://192.0.2.1/", Status = 200, Reason = "OK", Body = body, BodyLength = body.Length, ReceivedUtc = received,
        Headers = headers.Select(h => new KeyValuePair<string, string>(h.Item1, h.Item2)).ToList(),
    };

    // ---------- CertificateStatus.Status ----------

    [Fact]
    public void Status_NoHandshake_IsEmpty()
    {
        Assert.Equal("", CertificateStatus.Status(null, "www.example.org", Now));
        Assert.Equal("", CertificateStatus.Status(new TlsInfo { Handshake = false, Error = "x" }, "www.example.org", Now));
    }

    [Fact]
    public void Status_Valid()
    {
        Assert.Equal("valido", CertificateStatus.Status(Cert(), "www.example.org", Now));
        Assert.False(CertificateStatus.IsWarning(Cert(), "www.example.org", Now));
    }

    [Fact]
    public void Status_Expired()
    {
        string s = CertificateStatus.Status(Cert(notAfter: new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc)), "www.example.org", Now);
        Assert.Equal("scaduto il 01/09/2026", s);
    }

    [Fact]
    public void Status_NotYetValid()
    {
        string s = CertificateStatus.Status(Cert(notBefore: new DateTime(2026, 12, 1, 0, 0, 0, DateTimeKind.Utc)), "www.example.org", Now);
        Assert.Equal("non ancora valido (dal 01/12/2026)", s);
    }

    [Fact]
    public void Status_ExpiringSoon_IsInfoNotWarn()
    {
        var t = Cert(notAfter: Now.AddDays(10));
        Assert.Equal("scade tra 10 giorni", CertificateStatus.Status(t, "www.example.org", Now));
        Assert.False(CertificateStatus.IsWarning(t, "www.example.org", Now));
        Assert.Equal("valido", CertificateStatus.Status(Cert(notAfter: Now.AddDays(31)), "www.example.org", Now));
    }

    [Fact]
    public void Status_SelfSigned_HidesChainError()
    {
        var t = Cert(selfSigned: true, chain: false, chainError: "UntrustedRoot");
        Assert.Equal("autofirmato", CertificateStatus.Status(t, "www.example.org", Now));
        Assert.True(CertificateStatus.IsWarning(t, "www.example.org", Now));
    }

    [Fact]
    public void Status_UntrustedChain()
    {
        Assert.Equal("catena non attendibile (PartialChain)", CertificateStatus.Status(Cert(chain: false, chainError: "PartialChain"), "www.example.org", Now));
        Assert.Equal("valido", CertificateStatus.Status(Cert(chain: null), "www.example.org", Now));   // non verificata: nessun giudizio
    }

    [Fact]
    public void Status_NameMismatch_OnlyForNames()
    {
        Assert.Equal("nome non corrispondente (www.example.org)", CertificateStatus.Status(Cert(nameOk: false), "www.example.org", Now));
        Assert.Equal("valido", CertificateStatus.Status(Cert(nameOk: false), "192.0.2.1", Now));
        Assert.Equal("valido", CertificateStatus.Status(Cert(nameOk: false), "2001:db8::1", Now));
        Assert.Equal("valido", CertificateStatus.Status(Cert(nameOk: false), "", Now));
    }

    [Fact]
    public void Status_WeakKeyAndSignature()
    {
        Assert.Equal("chiave RSA di 1024 bit", CertificateStatus.Status(Cert(keyBits: 1024), "www.example.org", Now));
        Assert.Equal("firma sha1RSA", CertificateStatus.Status(Cert(sig: "sha1RSA"), "www.example.org", Now));
        Assert.Equal("valido", CertificateStatus.Status(Cert(keyBits: 256, sig: "sha256ECDSA"), "www.example.org", Now));   // ECDSA P-256 non è una chiave debole
    }

    [Fact]
    public void Status_MultipleIssues_JoinedInOrder()
    {
        var t = Cert(notAfter: new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc), selfSigned: true, nameOk: false, keyBits: 1024, sig: "sha1RSA");
        Assert.Equal("scaduto il 01/01/2025; autofirmato; nome non corrispondente (www.example.org); chiave RSA di 1024 bit; firma sha1RSA",
            CertificateStatus.Status(t, "www.example.org", Now));
    }

    [Fact]
    public void Apply_SetsFieldAndTestLine_Idempotent()
    {
        var r = new ScanResult { Host = "www.example.org", Port = 443, Scheme = "https", HttpReachable = true, Tls = Cert(selfSigned: true) };
        CertificateStatus.Apply(r);
        CertificateStatus.Apply(r);
        Assert.Equal("autofirmato", r.CertificateStatus);
        var ev = Assert.Single(r.Tests, t => t.Id == "TLS-CERT");
        Assert.Equal(TestOutcome.Warn, ev.Outcome);
        Assert.Equal("autofirmato", ev.Detail);

        // riga per IP con nome non corrispondente: nessun problema
        var ip = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, Tls = Cert(nameOk: false) };
        CertificateStatus.Apply(ip);
        Assert.Equal("valido", ip.CertificateStatus);
        Assert.Equal(TestOutcome.Info, Assert.Single(ip.Tests, t => t.Id == "TLS-CERT").Outcome);

        // riga del nome scoperto: conta il nome dell'Host header
        var name = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, HostHeader = "shop.example.org", NameRescan = true, Port = 443, Tls = Cert(nameOk: false) };
        CertificateStatus.Apply(name);
        Assert.Equal("nome non corrispondente (shop.example.org)", name.CertificateStatus);

        // senza TLS: niente
        var plain = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 80 };
        CertificateStatus.Apply(plain);
        Assert.Equal("", plain.CertificateStatus);
        Assert.DoesNotContain(plain.Tests, t => t.Id == "TLS-CERT");
    }

    [Fact]
    public void VerdictEngine_Apply_FillsCertificateStatus()
    {
        var r = new ScanResult { Host = "www.example.org", Port = 443, Scheme = "https", HttpReachable = true, Tls = Cert(nameOk: false) };
        VerdictEngine.Apply(r);
        Assert.Equal("nome non corrispondente (www.example.org)", r.CertificateStatus);
    }

    // ---------- TlsProbe.Describe con un certificato reale ----------

    [Fact]
    public void Describe_RealSelfSignedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=www.example.org", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("www.example.org");
        san.AddDnsName("example.org");
        req.CertificateExtensions.Add(san.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));

        var t = TlsProbe.Describe(cert, "www.example.org", "Tls13", 12.5);
        Assert.True(t.Handshake);
        Assert.True(t.SelfSigned);
        Assert.Equal(2048, t.KeyBits);
        Assert.Contains("sha256", t.SignatureAlgorithm, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(2, t.SubjectAltNames.Count);
        Assert.Contains("example.org", t.SubjectAltNames);
        Assert.True(t.NameMatches);
        Assert.NotNull(t.NotBefore);
        Assert.InRange(t.DaysToExpiry ?? -1, 88, 90);
        Assert.Equal("autofirmato", CertificateStatus.Status(t, "www.example.org"));

        var other = TlsProbe.Describe(cert, "mail.example.org");
        Assert.False(other.NameMatches);
        Assert.Equal("autofirmato; nome non corrispondente (mail.example.org)", CertificateStatus.Status(other, "mail.example.org"));
    }

    [Fact]
    public void Describe_WeakRsaKey_IsReported()
    {
        using var rsa = RSA.Create(1024);
        var req = new CertificateRequest("CN=weak.example.org", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("weak.example.org");
        req.CertificateExtensions.Add(san.Build());
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        var t = TlsProbe.Describe(cert, "weak.example.org");
        Assert.Equal(1024, t.KeyBits);
        Assert.Equal("autofirmato; chiave RSA di 1024 bit", CertificateStatus.Status(t, "weak.example.org"));
    }

    // ---------- CacheHint ----------

    [Fact]
    public void CacheHint_Empty_WithoutHeaders()
    {
        Assert.Equal("", PhpHints.CacheHint([Snap(headers: [("Server", "Apache"), ("Cache-Control", "max-age=600")])]));
        Assert.Equal("", PhpHints.CacheHint([Snap(headers: [("Age", "0")])]));   // Age: 0 = appena generata
    }

    [Fact]
    public void CacheHint_Hit_FromAgeAndXCache()
    {
        string h = PhpHints.CacheHint([Snap(headers: [("Age", "1234"), ("X-Cache", "HIT from cache.example.org")])]);
        Assert.StartsWith("risposta servita da una cache (", h);
        Assert.Contains("Age: 1234", h);
        Assert.Contains("X-Cache: HIT", h);
    }

    [Fact]
    public void CacheHint_Intermediary_WithoutHit()
    {
        string h = PhpHints.CacheHint([Snap(headers: [("Via", "1.1 varnish"), ("CF-Cache-Status", "DYNAMIC")])]);
        Assert.StartsWith("intermediario dichiarato (", h);
        Assert.Contains("Via: 1.1 varnish", h);
        Assert.Contains("CF-Cache-Status: DYNAMIC", h);

        Assert.StartsWith("risposta servita da una cache (", PhpHints.CacheHint([Snap(headers: [("CF-Cache-Status", "HIT")])]));
        Assert.StartsWith("intermediario dichiarato (", PhpHints.CacheHint([Snap(headers: [("X-Cache", "MISS")])]));
        Assert.StartsWith("risposta servita da una cache (", PhpHints.CacheHint([Snap(headers: [("X-Varnish", "123456 654321"), ("X-Cache-Hits", "3")])]));
        Assert.StartsWith("cache condivisa prevista dall'origine (", PhpHints.CacheHint([Snap(headers: [("Cache-Control", "public, s-maxage=300")])]));
    }

    [Fact]
    public void Compute_SetsCacheHint_AndCacheTestLine_Idempotent()
    {
        var r = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, Scheme = "https", HttpReachable = true };
        r.Requests.Add(Snap(headers: [("Age", "60"), ("X-Cache", "HIT"), ("X-Pingback", "https://192.0.2.1/xmlrpc.php")]));
        PhpHints.Compute(r);
        PhpHints.Compute(r);
        Assert.StartsWith("risposta servita da una cache", r.CacheHint);
        var cache = Assert.Single(r.Tests, t => t.Id == "L1-CACHE");
        Assert.Equal(TestOutcome.Info, cache.Outcome);
        Assert.Contains("le intestazioni dell'origine (X-Powered-By, Set-Cookie) possono mancare", cache.Detail);
        var hints = Assert.Single(r.Tests, t => t.Id == "L1-HINTS");
        Assert.Contains("risposta servita da una cache", hints.Detail);
        Assert.Equal(2, r.PhpHintScore);   // la cache non pesa

        var miss = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 443, HttpReachable = true };
        miss.Requests.Add(Snap(headers: [("X-Cache", "MISS")]));
        PhpHints.Compute(miss);
        Assert.DoesNotContain("possono mancare", Assert.Single(miss.Tests, t => t.Id == "L1-CACHE").Detail);
    }

    // ---------- versione dichiarata nel corpo ----------

    [Fact]
    public void BodyDeclaredVersions_Extracted_WithoutTouchingVerdict()
    {
        var r = new ScanResult { Host = "192.0.2.1", IsIpLiteral = true, Port = 80, Scheme = "http", HttpReachable = true };
        r.Requests.Add(Snap(body: "<footer>Powered by PHP/8.1.2-1ubuntu2.14 on Apache. Also PHP 7.4.33 and PHP 8.2.0 and again PHP/8.1.2-1ubuntu2.14</footer>"));
        r.Requests.Add(Snap(body: "PHP/5.6.40", method: "POST"));   // non GET: ignorato
        PhpHints.Compute(r);
        Assert.Equal(new[] { "8.1.2-1ubuntu2.14", "7.4.33", "8.2.0" }, r.BodyDeclaredVersions);
        Assert.Contains(r.PhpHints, h => h.StartsWith("2: ") && h.Contains("versione di PHP dichiarata nel corpo (non verificata): 8.1.2-1ubuntu2.14, 7.4.33, 8.2.0"));
        Assert.Equal("", r.PhpVersionRaw);
        Assert.Equal(VersionStatus.Unknown, r.VersionStatus);
        VerdictEngine.Apply(r);
        Assert.Equal("", r.PhpVersionRaw);
        Assert.Equal(Verdict.NoPhpDetected, r.Verdict);
    }

    [Fact]
    public void BodyDeclaredVersions_SkipsPhpInfo_AndCapsAtFive()
    {
        var phpinfo = "<html><h1 class=\"p\">PHP Version 8.3.1</h1><table><tr><td>System</td></tr></table>phpinfo()</html>";
        Assert.Empty(PhpHints.BodyDeclaredVersions([Snap(body: phpinfo)]));
        var many = string.Join(" ", Enumerable.Range(0, 8).Select(i => $"PHP/7.{i}.0"));
        var list = PhpHints.BodyDeclaredVersions([Snap(body: many)]);
        Assert.Equal(PhpHints.MaxBodyVersions, list.Count);
        Assert.Equal("7.0.0", list[0]);
    }

    // ---------- header Date: scarti rispetto all'ora di ricezione ----------

    private static HttpSnapshot Dated(DateTime dateHeaderUtc, DateTime receivedUtc) =>
        Snap(received: receivedUtc, headers: [("Server", "nginx"), ("Date", dateHeaderUtc.ToString("R"))]);

    [Fact]
    public void DateOffsets_SameClock_LaterResponse_NoFinding()
    {
        var t0 = new DateTime(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc);
        // la seconda risposta arriva 90 s dopo e il suo Date è 90 s dopo: stesso orologio, stesso nodo
        var f = WafDetector.FromRepetition(["192.0.2.1"], [Dated(t0, t0), Dated(t0.AddSeconds(90), t0.AddSeconds(90))]);
        Assert.DoesNotContain(f, x => x.Name.Contains("Date"));
    }

    [Fact]
    public void DateOffsets_DifferentClocks_Finding()
    {
        var t0 = new DateTime(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc);
        var f = WafDetector.FromRepetition(["192.0.2.1"], [Dated(t0, t0), Dated(t0.AddSeconds(90), t0)]);
        var d = Assert.Single(f, x => x.Name.Contains("Date"));
        Assert.Equal(WafCategory.LoadBalancer, d.Category);
        Assert.Contains("scarto di 90 s tra gli orologi dei nodi", d.Evidence);
        // sotto i 60 s: nessuna segnalazione
        Assert.DoesNotContain(WafDetector.FromRepetition(["192.0.2.1"], [Dated(t0, t0), Dated(t0.AddSeconds(45), t0)]), x => x.Name.Contains("Date"));
    }

    [Fact]
    public void DateOffsets_WithoutReceivedUtc_AreSkipped()
    {
        var t0 = new DateTime(2026, 10, 24, 12, 0, 0, DateTimeKind.Utc);
        var a = Snap(headers: [("Date", t0.ToString("R"))]);
        var b = Snap(headers: [("Date", t0.AddSeconds(900).ToString("R"))]);
        Assert.DoesNotContain(WafDetector.FromRepetition(["192.0.2.1"], [a, b]), x => x.Name.Contains("Date"));
    }
}
