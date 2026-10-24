using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;

namespace PhpVulnScanner.Tests;

/// <summary>v1.5: linguaggio del filtro della tabella (ResultFilter): AND, OR, esclusione, virgolette, campi, jolly, CIDR e intervalli, errori.</summary>
public class V15FilterTests
{
    private static ScanResult Wp() => new()
    {
        Input = "192.0.2.10", Host = "192.0.2.10", IsIpLiteral = true, Port = 443, Scheme = "https",
        HostHeader = "www.example.org", ResolvedIps = ["192.0.2.10"],
        Alive = AliveState.Alive, HttpReachable = true,
        PhpDetected = true, PhpPresence = "yes", PhpVersionRaw = "7.4.3-4ubuntu2.29", Sapi = "fpm", OsHint = "Ubuntu",
        Application = "WordPress", ApplicationVersion = "6.4.2", Technologies = ["WordPress 6.4.2", "Nginx 1.18.0", "jQuery 3.7.1"],
        Multipart = MultipartBarrier.Accepted, WafSummary = "Cloudflare (CDN, alta)",
        Verdict = Verdict.LikelyVulnerable, Priority = Priority.High, VerdictReason = "ramo 7.4 fuori supporto con suffisso di distribuzione: backport non escludibile",
        DiscoveredNames = ["blog.example.org", "shop.example.org"], SameContentNames = ["www2.example.org"],
        PhpSurface = ["/wp-login.php (200)", "/xmlrpc.php (405)"], Exposures = ["/.git/HEAD (200): repository esposto"], Cycle = 2,
    };

    private static ScanResult Fixed() => new()
    {
        Input = "198.51.100.7", Host = "198.51.100.7", IsIpLiteral = true, Port = 8443, Scheme = "https",
        Alive = AliveState.Alive, HttpReachable = true,
        PhpDetected = true, PhpPresence = "yes", PhpVersionRaw = "8.3.36", Sapi = "mod_php", OsHint = "Debian",
        Application = "Nextcloud", Technologies = ["Nextcloud", "Apache HTTP Server 2.4.62"],
        Multipart = MultipartBarrier.Blocked, WafSummary = "ModSecurity (WAF, media)",
        Verdict = Verdict.FixedByVersion, Priority = Priority.None, VerdictReason = "versione 8.3.36 uguale o successiva alla correzione 8.3.36", Cycle = 1,
    };

    private static ScanResult Maybe() => new()
    {
        Input = "intra.example.org", Host = "intra.example.org", IsIpLiteral = false, Port = 80, Scheme = "http", ResolvedIps = ["203.0.113.45"],
        Alive = AliveState.NotTested, HttpReachable = true,
        PhpDetected = false, PhpPresence = "maybe", Multipart = MultipartBarrier.NotTested,
        Verdict = Verdict.NoPhpDetected, Priority = Priority.None, VerdictReason = "solo indizi di PHP, nessuna prova", Cycle = 1,
    };

    private static ScanResult Down() => new()
    {
        Input = "192.0.2.200", Host = "192.0.2.200", IsIpLiteral = true, Port = 443,
        Alive = AliveState.NoResponse, HttpReachable = false, PhpPresence = "no",
        Verdict = Verdict.NotReachable, Priority = Priority.None, VerdictReason = "host non confermato attivo", Cycle = 1,
    };

    private static List<ScanResult> All() => [Wp(), Fixed(), Maybe(), Down()];

    private static string[] Hits(string query) => All().Where(r => ResultFilter.Matches(query, r)).Select(r => r.Host).ToArray();

    [Fact]
    public void EmptyQuery_MatchesEverything()
    {
        Assert.Equal(4, Hits("").Length);
        Assert.Equal(4, Hits("   ").Length);
        var f = ResultFilter.Parse(null);
        Assert.True(f.IsValid);
        Assert.True(f.IsEmpty);
    }

    [Fact]
    public void PlainTerm_IsSubstring_CaseInsensitive_OverAllFields()
    {
        Assert.Equal(["192.0.2.10"], Hits("wordpress"));
        Assert.Equal(["192.0.2.10"], Hits("CLOUDFLARE"));
        Assert.Equal(["192.0.2.10", "intra.example.org"], Hits("example"));   // nomi scoperti, Host
        Assert.Equal(["192.0.2.10"], Hits("xmlrpc"));           // superficie
        Assert.Equal(["192.0.2.10"], Hits(".git"));             // esposizioni
    }

    [Fact]
    public void Whitespace_IsAnd()
    {
        Assert.Equal(["192.0.2.10"], Hits("wordpress cloudflare"));
        Assert.Empty(Hits("wordpress modsecurity"));
    }

    [Fact]
    public void Pipe_IsOr_WithOrWithoutSpaces()
    {
        Assert.Equal(["192.0.2.10", "198.51.100.7"], Hits("wordpress|nextcloud"));
        Assert.Equal(["192.0.2.10", "198.51.100.7"], Hits("wordpress | nextcloud"));
    }

    [Fact]
    public void Or_BindsTighterThanAnd()
    {
        // a b|c = a AND (b OR c)
        Assert.Equal(["198.51.100.7"], Hits("debian wordpress|nextcloud"));
        Assert.Equal(["192.0.2.10"], Hits("ubuntu wordpress|nextcloud"));
        Assert.Empty(Hits("ubuntu nextcloud|modsecurity"));
    }

    [Fact]
    public void LeadingMinus_Negates()
    {
        Assert.Equal(["198.51.100.7", "intra.example.org", "192.0.2.200"], Hits("-wordpress"));
        Assert.Equal(["intra.example.org"], Hits("example -wordpress"));
        Assert.Equal(["192.0.2.200"], Hits("-alive:Alive -php:forse"));
    }

    [Fact]
    public void Quotes_KeepSpaces_AlsoAfterFieldPrefix()
    {
        Assert.Equal(["intra.example.org"], Hits("\"solo indizi\""));
        Assert.Equal(["intra.example.org"], Hits("motivo:\"solo indizi\""));
        Assert.Equal(["192.0.2.10", "198.51.100.7", "192.0.2.200"], Hits("-motivo:\"solo indizi\""));
        Assert.Empty(Hits("\"indizi solo\""));
    }

    [Fact]
    public void Field_Ip_SubstringAndResolved()
    {
        Assert.Equal(["192.0.2.10", "192.0.2.200"], Hits("ip:192.0.2."));
        Assert.Equal(["intra.example.org"], Hits("ip:203.0.113"));     // ResolvedIps di un nome
        Assert.Empty(Hits("ip:wordpress"));
    }

    [Fact]
    public void Field_Ip_Cidr()
    {
        Assert.Equal(["192.0.2.10", "192.0.2.200"], Hits("ip:192.0.2.0/24"));
        Assert.Equal(["192.0.2.10"], Hits("ip:192.0.2.0/25"));
        Assert.Equal(["192.0.2.200"], Hits("ip:192.0.2.128/25"));
        Assert.Equal(["intra.example.org"], Hits("ip:203.0.113.0/24"));
        Assert.Equal(4, Hits("ip:0.0.0.0/0").Length);
    }

    [Fact]
    public void Field_Ip_Range_ShortAndFull()
    {
        Assert.Equal(["192.0.2.10"], Hits("ip:192.0.2.1-50"));
        Assert.Equal(["192.0.2.10", "192.0.2.200"], Hits("ip:192.0.2.1-192.0.2.254"));
        Assert.Equal(["192.0.2.200"], Hits("ip:192.0.2.100-192.0.2.200"));
        Assert.Empty(Hits("ip:192.0.2.11-199"));
    }

    [Fact]
    public void Field_Ip_InvalidCidrOrRange_IsError()
    {
        var f = ResultFilter.Parse("ip:192.0.2.0/33");
        Assert.False(f.IsValid);
        Assert.Contains("CIDR", f.Error);
        Assert.False(f.Matches(Wp()));
        f = ResultFilter.Parse("ip:192.0.2.50-10");
        Assert.False(f.IsValid);
        Assert.Contains("intervallo", f.Error);
    }

    [Fact]
    public void Field_Name_CoversDisplayDiscoveredSameContentAndHostHeader()
    {
        Assert.Equal(["192.0.2.10"], Hits("nome:blog"));          // DiscoveredNames
        Assert.Equal(["192.0.2.10"], Hits("nome:www2"));          // SameContentNames
        Assert.Equal(["192.0.2.10"], Hits("name:www.example"));   // HostHeader, alias inglese
        Assert.Equal(["intra.example.org"], Hits("nome:intra"));  // DisplayName di un bersaglio FQDN
        Assert.Empty(Hits("nome:192.0.2"));
    }

    [Fact]
    public void Field_Port_TextAndRange()
    {
        Assert.Equal(["192.0.2.10", "198.51.100.7", "192.0.2.200"], Hits("porta:443"));   // testo: anche 8443
        Assert.Equal(["192.0.2.10", "192.0.2.200"], Hits("porta:443-443"));             // intervallo: esatto
        Assert.Equal(["198.51.100.7"], Hits("port:8443"));
        Assert.Equal(["192.0.2.10", "intra.example.org", "192.0.2.200"], Hits("porta:1-1024"));
        Assert.Equal(["198.51.100.7"], Hits("porta:8000-9000"));
        Assert.Equal(["192.0.2.10", "198.51.100.7", "192.0.2.200"], Hits("porta:*443"));
    }

    [Fact]
    public void Field_Version_Sapi_App_Waf_Os_Cycle()
    {
        Assert.Equal(["192.0.2.10"], Hits("ver:7.4"));
        Assert.Equal(["198.51.100.7"], Hits("versione:8.3.36"));
        Assert.Equal(["192.0.2.10"], Hits("sapi:fpm"));
        Assert.Equal(["192.0.2.10"], Hits("sapi:PHP-FPM"));          // etichetta a video
        Assert.Equal(["198.51.100.7"], Hits("sapi:mod_php"));
        Assert.Equal(["192.0.2.10"], Hits("app:6.4.2"));              // ApplicationVersion
        Assert.Equal(["192.0.2.10"], Hits("app:\"WordPress 6.4\""));
        Assert.Equal(["198.51.100.7"], Hits("waf:modsec"));
        Assert.Equal(["192.0.2.10"], Hits("os:ubuntu"));
        Assert.Equal(["192.0.2.10"], Hits("ciclo:2"));
        Assert.Equal(["198.51.100.7", "intra.example.org", "192.0.2.200"], Hits("cycle:1-1"));
        Assert.Empty(Hits("ver:cloudflare"));
    }

    [Fact]
    public void Field_Reason_Surface_Tech_Exposure()
    {
        Assert.Equal(["192.0.2.10"], Hits("motivo:backport"));
        Assert.Equal(["192.0.2.10"], Hits("superficie:wp-login"));
        Assert.Equal(["192.0.2.10"], Hits("surface:405"));
        Assert.Equal(["192.0.2.10"], Hits("tech:jquery"));
        Assert.Equal(["198.51.100.7"], Hits("tecnologia:apache"));
        Assert.Equal(["192.0.2.10"], Hits("esposizione:.git"));
        Assert.Empty(Hits("exposure:wordpress"));
    }

    [Fact]
    public void EnumFields_MatchEnumNameAndItalianLabel()
    {
        Assert.Equal(["192.0.2.10"], Hits("verdetto:LikelyVulnerable"));
        Assert.Equal(["192.0.2.10"], Hits("verdetto:probabilmente"));
        Assert.Equal(["198.51.100.7"], Hits("verdict:\"Corretto per versione\""));
        Assert.Equal(["192.0.2.10"], Hits("priorita:High"));
        Assert.Equal(["192.0.2.10"], Hits("priorità:alta"));
        Assert.Equal(["198.51.100.7", "intra.example.org", "192.0.2.200"], Hits("priority:nessuna"));
        Assert.Equal(["192.0.2.200"], Hits("alive:NoResponse"));
        Assert.Equal(["192.0.2.200"], Hits("alive:\"nessuna risposta\""));
        Assert.Equal(["198.51.100.7"], Hits("barriera:Blocked"));
        Assert.Equal(["198.51.100.7"], Hits("barrier:bloccato"));
        Assert.Equal(["192.0.2.10"], Hits("barriera:accettato"));
    }

    [Fact]
    public void Field_Php_ThreeStates()
    {
        Assert.Equal(["192.0.2.10", "198.51.100.7"], Hits("php:si"));
        Assert.Equal(["192.0.2.10", "198.51.100.7"], Hits("php:sì"));
        Assert.Equal(["192.0.2.10", "198.51.100.7"], Hits("php:yes"));
        Assert.Equal(["192.0.2.200"], Hits("php:no"));
        Assert.Equal(["intra.example.org"], Hits("php:forse"));
        Assert.Equal(["intra.example.org"], Hits("php:maybe"));
        Assert.Equal(["intra.example.org"], Hits("php:may"));     // testo di PhpPresence come sottostringa
    }

    [Fact]
    public void Glob_Star_IsAnchored()
    {
        Assert.Equal(["192.0.2.10"], Hits("ver:7.4*"));
        Assert.Empty(Hits("ver:*7.4"));                           // ancorato alla fine: deve finire con 7.4
        Assert.Equal(["192.0.2.10"], Hits("ver:*ubuntu*"));
        Assert.Empty(Hits("ver:ubuntu*"));                        // ancorato all'inizio
        Assert.Equal(["198.51.100.7"], Hits("ver:8.3.*"));
        Assert.Equal(["192.0.2.10", "198.51.100.7"], Hits("app:*"));   // qualunque applicazione
    }

    [Fact]
    public void Glob_QuestionMark_IsExactlyOneChar()
    {
        Assert.Equal(["198.51.100.7"], Hits("ver:8.3.3?"));
        Assert.Empty(Hits("ver:8.3.3??"));
        Assert.Equal(["192.0.2.10", "192.0.2.200"], Hits("ip:192.0.2.??*"));
        Assert.Equal(["192.0.2.10"], Hits("ip:192.0.2.??"));
    }

    [Fact]
    public void Glob_OnListFields_AnyElementMayMatch()
    {
        Assert.Equal(["192.0.2.10"], Hits("nome:blog.*"));
        Assert.Equal(["192.0.2.10"], Hits("superficie:/xmlrpc.php*"));
        Assert.Equal(["198.51.100.7"], Hits("tech:Apache*"));
        Assert.Empty(Hits("tech:pache*"));
    }

    [Fact]
    public void Glob_WithoutField_AppliesToEveryField()
    {
        Assert.Equal(["192.0.2.10"], Hits("*.example.org -intra"));   // nomi scoperti interi
        Assert.Equal(["192.0.2.10", "198.51.100.7"], Hits("8.3.3?|7.4.3*"));
    }

    [Fact]
    public void Glob_RegexMetacharactersAreLiteral()
    {
        var rx = ResultFilter.GlobRegex("a.b(c)[d]*");
        Assert.Matches(rx, "a.b(c)[d]xyz");
        Assert.DoesNotMatch(rx, "axb(c)[d]");
        Assert.Same(rx, ResultFilter.GlobRegex("a.b(c)[d]*"));   // cache
    }

    [Fact]
    public void UnknownField_IsError_NeverThrows()
    {
        var f = ResultFilter.Parse("colore:rosso");
        Assert.False(f.IsValid);
        Assert.Contains("colore", f.Error);
        Assert.False(f.Matches(Wp()));
        Assert.False(ResultFilter.Matches("colore:rosso", Wp()));
    }

    [Fact]
    public void MalformedQuotes_And_DanglingPipe_AreErrors_NeverThrow()
    {
        foreach (var q in new[] { "\"aperta", "motivo:\"aperta", "a |", "| a", "a || b", "ver:", "-", "ip:1.2.3.4/x", "\"\"" })
        {
            var f = ResultFilter.Parse(q);
            if (f.IsValid) continue;                          // mai eccezioni; se non valido non trova nulla
            Assert.NotEmpty(f.Error);
            Assert.False(f.Matches(Wp()), q);
        }
        Assert.False(ResultFilter.Parse("\"aperta").IsValid);
        Assert.False(ResultFilter.Parse("a |").IsValid);
        Assert.False(ResultFilter.Parse("| a").IsValid);
        Assert.False(ResultFilter.Parse("ver:").IsValid);
        Assert.False(ResultFilter.Parse("\"\"").IsValid);
        Assert.True(ResultFilter.Parse("-").IsValid);           // un trattino da solo è testo
    }

    [Fact]
    public void Negation_InsideOrGroup()
    {
        // nextcloud OR NOT alive:Alive → Fixed (nextcloud), Maybe (NotTested), Down (NoResponse)
        Assert.Equal(["198.51.100.7", "intra.example.org", "192.0.2.200"], Hits("nextcloud|-alive:Alive"));
    }

    [Fact]
    public void NumericField_CompareAsTextUnlessRange()
    {
        Assert.Equal(["192.0.2.10", "198.51.100.7", "192.0.2.200"], Hits("porta:44"));   // sottostringa: 443, 8443
        Assert.Equal(["intra.example.org"], Hits("porta:80"));
        Assert.Equal(["intra.example.org"], Hits("porta:80-80"));
        Assert.Empty(Hits("porta:8080-8090"));
    }

    [Fact]
    public void FieldNames_AreCaseInsensitive()
    {
        Assert.Equal(["192.0.2.10"], Hits("VER:7.4"));
        Assert.Equal(["192.0.2.10"], Hits("Verdetto:Likely"));
    }
}
