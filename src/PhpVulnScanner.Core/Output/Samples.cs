using System.Text.Json;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;

namespace PhpVulnScanner.Core.Output;

/// <summary>
/// "Campioni per analisi" (modalità debug): un campione per ogni combinazione distinta di Server / X-Powered-By /
/// applicazione / cookie / sonda della superficie, con IP, nomi scoperti, etichette dei domini (anche in prosa) e indirizzi e-mail
/// sostituiti (198.51.100.x, hostN.example.org, orgN, utenteN@example.org) in URL, intestazioni e corpi. Serve a far crescere le firme
/// senza far uscire dati del cliente; i corpi vanno comunque controllati prima di condividerli (v1.3 lasciava passare le etichette).
/// </summary>
public static class Samples
{
    private static readonly Regex Ipv4Rx = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.CultureInvariant);
    private static readonly Regex SubLabelRx = new(@"\b(?:[A-Za-z0-9-]{2,}\.)+(org\d+\.[A-Za-z]{2,})", RegexOptions.CultureInvariant);
    private static readonly Regex EmailRx = new(@"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", RegexOptions.CultureInvariant);

    /// <summary>Etichette di dominio che non identificano l'organizzazione: restano nei campioni (servono alle firme).</summary>
    private static readonly HashSet<string> GenericLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        "www", "www2", "mail", "web", "cloud", "portal", "portale", "static", "admin", "login", "intranet", "test", "demo", "shop",
        "blog", "news", "home", "cdn", "api", "app", "apps", "dev", "beta", "old", "new", "wordpress", "moodle", "plesk", "webmail",
        "owa", "vpn", "ftp", "smtp", "imap", "pop", "ns1", "ns2", "mx", "autodiscover", "remote", "secure", "sso", "auth", "idp",
        "gov", "edu", "com", "org", "net", "info", "biz", "co", "ac", "it", "eu", "example",
    };

    /// <summary>
    /// Etichette dei nomi scoperti (es. "ente" e "acme" in portale.ente-acme.example) di almeno 4 caratteri, escluse quelle generiche:
    /// vengono sostituite ovunque (anche in prosa: "Ente Acme"). Le etichette con trattino valgono anche spezzate.
    /// </summary>
    internal static IEnumerable<string> OrganisationLabels(IEnumerable<string> names)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in names)
        {
            var labels = n.TrimStart('*', '.').Split('.', StringSplitOptions.RemoveEmptyEntries);
            foreach (var l in labels.Take(Math.Max(0, labels.Length - 1)))   // il TLD non identifica nessuno
            {
                if (l.Length < 4 || GenericLabels.Contains(l) || l.All(char.IsDigit)) continue;
                set.Add(l);
                foreach (var part in l.Split('-', StringSplitOptions.RemoveEmptyEntries))
                    if (part.Length >= 4 && !GenericLabels.Contains(part) && !part.All(char.IsDigit)) set.Add(part);
            }
        }
        return set.OrderByDescending(s => s.Length).ThenBy(s => s, StringComparer.OrdinalIgnoreCase);
    }

    public static string Build(ScanSession session)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hostMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var nameMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var labelMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var mailMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string MapHost(string h)
        {
            if (!hostMap.TryGetValue(h, out var v)) hostMap[h] = v = $"198.51.100.{(hostMap.Count % 250) + 1}";
            return v;
        }
        string MapName(string n)
        {
            if (!nameMap.TryGetValue(n, out var v)) nameMap[n] = v = $"host{nameMap.Count + 1}.example.org";
            return v;
        }
        string MapLabel(string l)
        {
            if (!labelMap.TryGetValue(l, out var v)) labelMap[l] = v = $"org{labelMap.Count + 1}";
            return v;
        }
        string MapMail(string m)
        {
            if (!mailMap.TryGetValue(m, out var v)) mailMap[m] = v = $"utente{mailMap.Count + 1}@example.org";
            return v;
        }

        // nomi e etichette di tutta la sessione: un nome scoperto su una riga può comparire nei corpi di un'altra
        var allNames = new List<string>();
        foreach (var r in session.Results)
        {
            allNames.AddRange(r.DiscoveredNames);
            allNames.AddRange(r.SameContentNames);
            if (r.HostHeader.Length > 0 && !r.IsIpLiteral || r.NameRescan) allNames.Add(r.HostHeader);
            if (!r.IsIpLiteral) allNames.Add(r.Host);
        }
        var sessionNames = allNames.Where(n => n.Length > 3 && !n.EndsWith(".example.org", StringComparison.OrdinalIgnoreCase))
            .Select(n => n.TrimStart('*', '.')).Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(n => n.Length).ToList();
        var labels = OrganisationLabels(sessionNames).ToList();

        var list = new List<object>();
        foreach (var r in session.Results.Where(r => r.HttpReachable))
        {
            string cookie = r.Requests.SelectMany(q => q.HeaderValues("Set-Cookie")).Select(c => c.Split('=')[0].Trim()).FirstOrDefault() ?? "";
            string key = $"{r.ServerHeader}|{r.PoweredBy}|{r.Application}|{cookie}|{r.PhpSurfaceProbe}|{r.Requests.FirstOrDefault()?.Status}";
            if (!seen.Add(key)) continue;

            string Anon(string s)
            {
                if (string.IsNullOrEmpty(s)) return s;
                // ordine: nomi interi, poi etichette, poi e-mail (i segnaposto non devono essere ritoccati: "utente" contiene "ente"), poi IP
                foreach (var n in sessionNames)
                    s = Regex.Replace(s, Regex.Escape(n), MapName(n), RegexOptions.IgnoreCase);
                foreach (var l in labels)
                    s = Regex.Replace(s, Regex.Escape(l), MapLabel(l), RegexOptions.IgnoreCase);
                s = SubLabelRx.Replace(s, m => "sub." + m.Groups[1].Value);   // astancona.org69.it → sub.org69.it
                s = EmailRx.Replace(s, m => MapMail(m.Value));
                s = Ipv4Rx.Replace(s, m => MapHost(m.Value));
                return s;
            }

            list.Add(new
            {
                sample = list.Count + 1,
                host = r.IsIpLiteral ? MapHost(r.Host) : MapName(r.Host),
                port = r.Port, scheme = r.Scheme,
                name_rescan = r.NameRescan,
                server = Anon(r.ServerHeader), x_powered_by = r.PoweredBy, application = r.Application, application_evidence = Anon(r.ApplicationEvidence),
                session_cookie_name = cookie, surface_probe = r.PhpSurfaceProbe, sapi = r.Sapi, os_hint = r.OsHint,
                php_detected = r.PhpDetected, php_version = r.PhpVersionRaw, verdict = r.Verdict.ToString(), waf = r.WafSummary,
                php_surface = r.PhpSurface,
                tls = r.Tls == null ? null : new { r.Tls.Handshake, r.Tls.Protocol, subject = Anon(r.Tls.Subject), issuer = Anon(r.Tls.Issuer), sans = r.Tls.SubjectAltNames.Select(Anon).ToList() },
                requests = r.Requests.Select(q => new
                {
                    q.Method, url = Anon(q.Url), q.Status, q.Reason,
                    request_headers = q.RequestHeaders?.Select(h => new { h.Key, Value = Anon(h.Value) }).ToList(),
                    headers = q.Headers.Select(h => new { h.Key, Value = Anon(h.Value) }).ToList(),
                    body = Anon(q.Body.Length > 16 * 1024 ? q.Body[..(16 * 1024)] : q.Body), q.BodyLength, q.BodyTruncated, q.Error, q.ErrorKind,
                }).ToList(),
            });
        }
        return JsonSerializer.Serialize(new { app_version = session.AppVersion, generated = DateTime.Now, note = "IP, nomi scoperti, etichette dei domini e indirizzi e-mail sostituiti (198.51.100.x, hostN.example.org, orgN, utenteN@example.org); corpi limitati a 16 KiB. I corpi possono ancora contenere nomi di organizzazioni o persone non legati a un nome scoperto: verificare prima di condividere.", samples = list },
            new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    }
}
