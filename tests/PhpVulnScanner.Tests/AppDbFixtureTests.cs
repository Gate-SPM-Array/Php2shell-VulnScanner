using System.Text.Json;
using PhpVulnScanner.Core.Apps;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;
using Xunit.Abstractions;

namespace PhpVulnScanner.Tests;

/// <summary>
/// Riconoscimento applicazioni sui campioni anonimizzati di una scansione reale (<c>Fixtures/samples_v1.3.json</c>: 25 combinazioni
/// distinte di Server / X-Powered-By / cookie / applicazione, IP sostituiti con 198.51.100.x, nomi con *.example.org, corpi a 8 KiB).
/// Per ogni campione si ricostruiscono gli <see cref="HttpSnapshot"/>, si eseguono <see cref="StackFingerprint.Apply"/> e
/// <see cref="TechnologyDatabase.Apply"/> e si confrontano applicazione e tecnologie con la tabella attesa (scritta guardando l'uscita reale).
/// </summary>
[Collection("AppDbDefault")]
public class AppDbFixtureTests
{
    private static readonly Lazy<TechnologyDatabase> Db = new(() => TechnologyDatabase.Load(Path.Combine(LocalizationTests.RepoRoot(), "data")));
    private readonly ITestOutputHelper _out;
    public AppDbFixtureTests(ITestOutputHelper output) => _out = output;

    public static string FixturePath => Path.Combine(LocalizationTests.RepoRoot(), "tests", "PhpVulnScanner.Tests", "Fixtures", "samples_v1.3.json");

    public sealed record Sample(int Id, string Label, string Host, int Port, string Scheme, string? TlsIssuer, List<HttpSnapshot> Requests);

    public static List<Sample> LoadSamples()
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(FixturePath));
        var list = new List<Sample>();
        foreach (var s in doc.RootElement.GetProperty("samples").EnumerateArray())
        {
            var reqs = new List<HttpSnapshot>();
            foreach (var r in s.GetProperty("requests").EnumerateArray())
            {
                string body = r.GetProperty("body").GetString() ?? "";
                reqs.Add(new HttpSnapshot
                {
                    Method = r.GetProperty("method").GetString() ?? "GET",
                    Url = r.GetProperty("url").GetString() ?? "",
                    Status = r.GetProperty("status").GetInt32(),
                    Reason = r.GetProperty("reason").GetString() ?? "",
                    Headers = r.GetProperty("headers").EnumerateArray().Select(h => new KeyValuePair<string, string>(h.GetProperty("Key").GetString() ?? "", h.GetProperty("Value").GetString() ?? "")).ToList(),
                    Body = body,
                    BodyLength = body.Length,
                });
            }
            string? issuer = s.TryGetProperty("tls", out var tls) && tls.ValueKind == JsonValueKind.Object ? tls.GetProperty("issuer").GetString() : null;
            list.Add(new Sample(s.GetProperty("id").GetInt32(), s.GetProperty("label").GetString() ?? "", s.GetProperty("host").GetString() ?? "",
                s.GetProperty("port").GetInt32(), s.GetProperty("scheme").GetString() ?? "http", issuer, reqs));
        }
        return list;
    }

    /// <summary>Esegue sul campione la stessa catena passiva dello scanner: intestazioni → StackFingerprint (firme manuali) → database firme.</summary>
    private static ScanResult Run(Sample s)
    {
        var r = new ScanResult { Host = s.Host, Port = s.Port, HttpReachable = true };
        var first = s.Requests.FirstOrDefault(x => x.HasResponse);
        if (first != null)
        {
            r.ServerHeader = first.Header("Server") ?? "";
            r.PoweredBy = first.Header("X-Powered-By") ?? "";
        }
        if (s.TlsIssuer != null) r.Tls = new TlsInfo { Handshake = true, Issuer = s.TlsIssuer };
        var old = TechnologyDatabase.Default;
        try
        {
            TechnologyDatabase.Default = null;          // le firme manuali da sole, poi il database esplicitamente
            StackFingerprint.Apply(r, s.Requests);
            Db.Value.Apply(r, s.Requests);
        }
        finally { TechnologyDatabase.Default = old; }
        return r;
    }

    // ---- tabella attesa (scritta guardando l'uscita reale della catena StackFingerprint → database firme) ----
    // Application: applicazione attesa ("" = nessuna). Must: tecnologie che devono comparire (nome, o "nome versione" per fissare la
    // versione). MustNot: tecnologie che non devono comparire (guardia contro i falsi positivi, in pratica PHP sugli host non PHP).
    // Php: PhpDetected atteso. Ncsc: vero se l'applicazione è nell'inventario NCSC-NL (NcscStatus compilato).

    private sealed record Expect(int Id, string Application, string[] Must, string[] MustNot, bool Php, bool Ncsc = false, string Sapi = "", string Os = "");

    private const string AffectedViaPhp = "NCSC-NL: prodotto affetto in quanto dipende dalla versione di PHP (nessuna versione del prodotto corregge da sola)";

    private static readonly Expect[] Table =
    [
        // Plesk compare prima di WordPress tra le tecnologie (confidenza 100 da X-Powered-By-Plesk, implica PHP per correzione locale);
        // l'applicazione resta WordPress perché la firma manuale (/wp-content/) ha la precedenza. Nessuna versione: il meta generator è oltre gli 8 KiB.
        new(136, "WordPress", ["WordPress", "Plesk", "IIS 10.0", "Microsoft ASP.NET", "PHP"], [], Php: true, Ncsc: true, Os: "Windows"),
        new(141, "WordPress", ["PHP 7.4.33", "WordPress", "Apache HTTP Server 2.4.37", "OpenSSL 1.1.1k", "MySQL"], [], Php: true, Ncsc: true, Os: "Rocky Linux"),
        new(48, "Laravel", ["PHP 8.3.36", "Apache HTTP Server 2.4.62", "OpenSSL 3.2.2"], ["WordPress"], Php: true, Ncsc: true, Os: "Rocky Linux"),
        // mod_fcgid nel banner: SAPI cgi; UNIX dal banner "(Unix)"
        new(32, "Laravel", ["PHP 7.3.33", "Apache HTTP Server 2.4.63", "UNIX"], [], Php: true, Ncsc: true, Sapi: "cgi"),
        // redirect 303 + pagina 404 senza Server: nulla di riconoscibile negli 8 KiB (il MyBB della scansione originale era oltre il taglio)
        new(138, "", [], ["MyBB", "PHP"], Php: false),
        new(91, "Moodle", ["Moodle", "PHP", "Apache HTTP Server 2.4.66", "Debian"], [], Php: true, Ncsc: true, Os: "Debian"),
        // Plesk da X-Powered-By-Plesk su un IIS che risponde solo 301: PHP è dedotto per implicazione (correzione locale "Plesk" → PHP),
        // non osservato. Deduzione debole, segnalata nel rapporto: il vhost non ha mostrato PHP.
        new(135, "Plesk", ["Plesk", "PHP", "IIS 10.0", "Microsoft ASP.NET", "Windows Server"], [], Php: true, Ncsc: true, Os: "Windows"),
        new(1, "", ["IIS 10.0", "Microsoft ASP.NET", "Windows Server"], ["PHP"], Php: false, Os: "Windows"),
        new(19, "", ["IIS 8.5", "Microsoft ASP.NET 4.0.30319", "Bootstrap", "jQuery"], ["PHP"], Php: false, Os: "Windows"),
        new(64, "", ["Apache Tomcat", "Java"], ["PHP"], Php: false),
        new(116, "", ["Liferay 6.2", "Java", "Apache HTTP Server", "Google Analytics"], ["PHP"], Php: false),
        // WildFly/Undertow: nessuna firma nel database (lacuna, non errore)
        new(16, "", [], ["PHP"], Php: false),
        new(30, "", ["Nginx 1.18.0", "Ubuntu"], ["PHP"], Php: false, Os: "Ubuntu"),
        new(11, "", ["F5 BigIP"], ["PHP"], Php: false),
        // il cookie di persistenza BIGipServer* non è una firma Wappalyzer (lo riconosce WafDetector): qui restano ASP.NET e le librerie
        new(76, "", ["Microsoft ASP.NET", "jQuery 1.11.2", "Bootstrap"], ["PHP"], Php: false),
        new(5, "", ["Microsoft HTTPAPI 2.0"], ["PHP"], Php: false, Os: "Windows"),
        // "File not found." di php-fpm sul .php inesistente; la versione arriva dall'X-Powered-By di una risposta successiva
        new(86, "", ["PHP 8.1.14", "Apache HTTP Server 2.4.53", "OpenSSL 3.0.7"], [], Php: true, Os: "Rocky Linux"),
        // phpinfo(): lo riconosce PhpFingerprint (livello 1), non questa catena passiva; qui restano Apache e Ubuntu
        new(43, "", ["Apache HTTP Server 2.4.41", "Ubuntu"], [], Php: false, Os: "Ubuntu"),
        new(2, "", ["Apache HTTP Server"], ["PHP"], Php: false),
        new(54, "", ["Apache HTTP Server 2.4.18", "Ubuntu"], ["PHP"], Php: false, Os: "Ubuntu"),
        new(14, "", ["IIS 10.0", "Windows Server"], ["PHP"], Php: false, Os: "Windows"),
        new(63, "Matomo", ["Matomo Analytics", "PHP", "Apache HTTP Server 2.4.52", "Ubuntu"], [], Php: true, Ncsc: true, Os: "Ubuntu"),
        new(88, "", ["Kestrel", "Microsoft ASP.NET"], ["PHP"], Php: false),
        // DNN: i cookie dnn_IsMobile/.ASPXANONYMOUS non sono firme Wappalyzer (il database cerca DotNetNuke nel meta generator o negli script)
        new(74, "", ["IIS 10.0", "Windows Server"], ["PHP"], Php: false),
        // "Cloudflare" compare per implicazione Wappalyzer da cdnjs (cdnjs.cloudflare.com negli script): il sito NON è dietro Cloudflare.
        // Falso positivo ereditato dalle firme a monte, segnalato nel rapporto; non si asserisce né in positivo né in negativo.
        new(117, "", ["PHP 8.0.30", "Apache HTTP Server 2.4.62", "jQuery 3.5.1", "Bootstrap 4.5.2"], [], Php: true, Os: "Oracle Linux"),
    ];

    public static IEnumerable<object[]> Ids() => Table.Select(e => new object[] { e.Id });

    private static bool Has(IEnumerable<string> techs, string expected) =>
        techs.Any(t => t == expected || (!expected.Any(char.IsDigit) && t.StartsWith(expected + " ", StringComparison.Ordinal)));

    [Theory]
    [MemberData(nameof(Ids))]
    public void Sample_MatchesExpectedApplicationAndTechnologies(int id)
    {
        var e = Table.Single(x => x.Id == id);
        var s = LoadSamples().Single(x => x.Id == id);
        var r = Run(s);
        _out.WriteLine($"#{s.Id} [{s.Label}]");
        _out.WriteLine($"   app={r.Application} ver={r.ApplicationVersion} php={r.PhpDetected} sapi={r.Sapi} os={r.OsHint}");
        _out.WriteLine($"   tech={string.Join(" | ", r.Technologies)}");
        _out.WriteLine($"   ncsc={r.NcscStatus} check={r.AppVersionCheck} statuses={string.Join(" | ", r.TechnologyStatuses)}");

        Assert.Equal(e.Application, r.Application);
        Assert.Equal(e.Php, r.PhpDetected);
        foreach (var m in e.Must) Assert.True(Has(r.Technologies, m), $"tecnologia attesa assente: {m} (trovate: {string.Join(", ", r.Technologies)})");
        foreach (var m in e.MustNot) Assert.False(Has(r.Technologies, m), $"tecnologia non attesa: {m}");
        Assert.True(r.Technologies.Count <= 12);
        if (e.Sapi.Length > 0) Assert.Equal(e.Sapi, r.Sapi);
        if (e.Os.Length > 0) Assert.Equal(e.Os, r.OsHint);

        if (e.Ncsc)
        {
            Assert.Equal(AffectedViaPhp, r.NcscStatus);   // tutte le applicazioni dei campioni sono "Affected" senza versione corretta
            Assert.StartsWith("https://github.com/NCSC-NL/php2shell/blob/main/software/software_list_", r.NcscReference);
            Assert.Equal("", r.AppVersionCheck);          // nessuna versione del prodotto da confrontare
            // lo stato per tecnologia c'è quando l'applicazione è anche tra le tecnologie del database (Laravel dei campioni è riconosciuto
            // solo dalla firma manuale XSRF-TOKEN: il cookie di sessione è "<app>_session", non "laravel_session")
            if (Has(r.Technologies, e.Application) || e.Application == "Matomo")
                Assert.Contains(r.TechnologyStatuses, t => t.EndsWith(": affetto (dipende dalla versione di PHP)", StringComparison.Ordinal));
            else
                Assert.Empty(r.TechnologyStatuses);
        }
        else
        {
            Assert.Equal("", r.NcscStatus);
            Assert.Equal("", r.AppVersionCheck);
        }
        // il runtime PHP, i web server, le librerie e i sistemi operativi non sono pacchetti dell'inventario: mai uno stato per loro
        Assert.DoesNotContain(r.TechnologyStatuses, t => t.StartsWith("PHP:") || t.StartsWith("OpenSSL:") || t.StartsWith("Apache") || t.StartsWith("MySQL:") || t.StartsWith("jQuery:"));
        Assert.True(r.TechnologyStatuses.Count <= 12);
        Assert.All(r.TechnologyStatuses, t => Assert.Contains(": ", t));
    }

    [Fact]
    public void AllSamples_HaveAnExpectation_AndEvidenceIsAlwaysPresentWithAnApplication()
    {
        var samples = LoadSamples();
        Assert.Equal(samples.Select(s => s.Id).Order(), Table.Select(e => e.Id).Order());
        foreach (var s in samples)
        {
            var r = Run(s);
            if (r.Application.Length > 0) Assert.False(string.IsNullOrEmpty(r.ApplicationEvidence), $"#{s.Id}: applicazione senza evidenza");
            if (r.PhpDetected) Assert.False(string.IsNullOrEmpty(r.PhpEvidence), $"#{s.Id}: PHP senza evidenza");
            // Match direttamente: ogni tecnologia riconosciuta ha un'evidenza e una confidenza
            foreach (var m in Db.Value.Match(s.Requests, s.TlsIssuer))
            {
                Assert.False(string.IsNullOrEmpty(m.Evidence), $"#{s.Id}: {m.Name} senza evidenza");
                Assert.InRange(m.Confidence, 1, 100);
            }
        }
    }

    /// <summary>Domini pubblici di terzi (CDN, standard, fornitori) che possono comparire nei corpi senza identificare il cliente.</summary>
    private static readonly string[] PublicVendorSuffixes =
    [
        ".example.org", ".example.net", ".example.com", ".w3.org", ".w.org", ".php.net", ".debian.org", ".bootstrapcdn.com", ".cloudflare.com",
        ".googletagmanager.com", ".tailwindcss.com", ".googleapis.com", ".jquery.com", ".google.com", ".gstatic.com", ".microsoft.com", ".jsdelivr.net",
    ];

    [Fact]
    public void Fixture_ContainsNoRealIpOrCustomerName()
    {
        string text = File.ReadAllText(FixturePath);
        // nessun nome di cliente: tutti i nomi devono stare sotto example.org / example.net / example.com
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, @"\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.(it|eu|org|net|com)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase))
            Assert.True(PublicVendorSuffixes.Any(suf => m.Value.EndsWith(suf, StringComparison.OrdinalIgnoreCase)), "nome non anonimizzato nel fixture: " + m.Value);
        // solo indirizzi di documentazione (RFC 5737) e loopback
        foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(text, @"\b(?:\d{1,3}\.){3}\d{1,3}\b"))
        {
            string ip = m.Value;
            if (ip.StartsWith("198.51.100.") || ip.StartsWith("203.0.113.") || ip.StartsWith("192.0.2.") || ip.StartsWith("127.") || ip == "0.0.0.0") continue;
            var parts = ip.Split('.').Select(int.Parse).ToArray();
            Assert.True(parts.Any(p => p > 255) || parts[0] < 10, $"indirizzo non anonimizzato nel fixture: {ip}");   // numeri di versione (3.0.2.0) ammessi
        }
        var samples = LoadSamples();
        Assert.Equal(25, samples.Count);
        Assert.All(samples, s => Assert.StartsWith("198.51.100.", s.Host));
        Assert.All(samples.SelectMany(s => s.Requests), r => Assert.True(r.Body.Length <= 8 * 1024 + 4, "corpo oltre 8 KiB"));
    }
}
