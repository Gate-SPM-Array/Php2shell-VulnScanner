using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Waf;

public enum WafCategory { Waf, Cdn, ReverseProxy, LoadBalancer }
public enum Confidence { Low, Medium, High }

/// <summary>Un elemento rilevato davanti all'origine, con l'evidenza che lo ha fatto riconoscere.</summary>
public sealed record WafFinding(WafCategory Category, string Name, Confidence Confidence, string Evidence);

/// <summary>
/// Riconoscimento di WAF, CDN, reverse proxy e bilanciatori da intestazioni, cookie, corpo delle pagine di blocco,
/// certificato TLS e comportamento (una richiesta palesemente ostile ma inerte, confrontata con la richiesta normale).
/// Le firme sono indizi: il report mostra sempre l'evidenza, mai il solo nome.
/// </summary>
public static class WafDetector
{
    private sealed record Sig(string Name, WafCategory Cat, Confidence Conf, string Where, Regex Rx);

    private static Sig H(string name, WafCategory cat, Confidence c, string header, string pattern) =>
        new(name, cat, c, "header:" + header, new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
    private static Sig Ck(string name, WafCategory cat, Confidence c, string pattern) =>
        new(name, cat, c, "cookie", new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
    private static Sig B(string name, WafCategory cat, Confidence c, string pattern) =>
        new(name, cat, c, "body", new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
    private static Sig HN(string name, WafCategory cat, Confidence c, string headerPattern) =>
        new(name, cat, c, "headername", new Regex(headerPattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));

    private static readonly Sig[] Signatures =
    [
        // CDN / WAF cloud
        H("Cloudflare", WafCategory.Cdn, Confidence.High, "Server", @"^cloudflare"),
        HN("Cloudflare", WafCategory.Cdn, Confidence.High, @"^cf-ray$|^cf-cache-status$|^cf-mitigated$"),
        Ck("Cloudflare", WafCategory.Cdn, Confidence.Medium, @"^(__cfduid|__cf_bm|cf_clearance)="),
        B("Cloudflare {block}", WafCategory.Waf, Confidence.High, @"cloudflare|Attention Required!|cf-error-details|Ray ID"),
        H("Akamai", WafCategory.Cdn, Confidence.High, "Server", @"AkamaiGHost|AkamaiNetStorage"),
        HN("Akamai", WafCategory.Cdn, Confidence.High, @"^x-akamai-|^akamai-"),
        Ck("Akamai", WafCategory.Cdn, Confidence.Medium, @"^(ak_bmsc|bm_sz|_abck|akaalb_)"),
        B("Akamai {block}", WafCategory.Waf, Confidence.Medium, @"Reference #\d+\.[0-9a-f]+\.\d+\.[0-9a-f]+"),
        H("Imperva / Incapsula", WafCategory.Waf, Confidence.High, "X-CDN", @"Incapsula|Imperva"),
        HN("Imperva / Incapsula", WafCategory.Waf, Confidence.High, @"^x-iinfo$"),
        Ck("Imperva / Incapsula", WafCategory.Waf, Confidence.High, @"^(visid_incap_|incap_ses_|nlbi_)"),
        B("Imperva / Incapsula {block}", WafCategory.Waf, Confidence.High, @"Incapsula incident ID|_Incapsula_Resource|subject=WAF Block Page"),
        H("Sucuri", WafCategory.Waf, Confidence.High, "Server", @"Sucuri|Cloudproxy"),
        HN("Sucuri", WafCategory.Waf, Confidence.High, @"^x-sucuri-"),
        B("Sucuri {block}", WafCategory.Waf, Confidence.High, @"Sucuri WebSite Firewall|cloudproxy@sucuri\.net"),
        H("AWS CloudFront", WafCategory.Cdn, Confidence.High, "Via", @"CloudFront"),
        HN("AWS CloudFront", WafCategory.Cdn, Confidence.High, @"^x-amz-cf-id$|^x-amz-cf-pop$"),
        H("AWS ELB/ALB", WafCategory.LoadBalancer, Confidence.High, "Server", @"^awselb"),
        Ck("AWS ALB {affinity}", WafCategory.LoadBalancer, Confidence.High, @"^AWSALB(CORS|TG)?="),
        B("AWS WAF {block}", WafCategory.Waf, Confidence.Medium, @"Request blocked\.|AWS WAF"),
        H("Azure Front Door", WafCategory.Cdn, Confidence.High, "X-Azure-Ref", @"."),
        HN("Azure Front Door", WafCategory.Cdn, Confidence.High, @"^x-azure-ref$|^x-fd-healthprobe$|^x-azure-fdid$"),
        Ck("Azure App Service / ARR {affinity}", WafCategory.LoadBalancer, Confidence.High, @"^ARRAffinity(SameSite)?="),
        H("Microsoft IIS ARR", WafCategory.ReverseProxy, Confidence.High, "X-Powered-By", @"^ARR/"),
        B("Azure Application Gateway WAF {block}", WafCategory.Waf, Confidence.Medium, @"Microsoft-Azure-Application-Gateway"),
        H("Azure Application Gateway", WafCategory.Waf, Confidence.Medium, "Server", @"Microsoft-Azure-Application-Gateway"),
        H("Google Cloud (GFE / Cloud Armor)", WafCategory.Cdn, Confidence.Medium, "Server", @"^gws$|Google Frontend|^GSE$"),
        H("Google Cloud (proxy)", WafCategory.ReverseProxy, Confidence.Medium, "Via", @"1\.1 google"),
        H("Fastly", WafCategory.Cdn, Confidence.High, "X-Served-By", @"^cache-"),
        HN("Fastly", WafCategory.Cdn, Confidence.High, @"^x-fastly-request-id$|^fastly-debug"),
        H("Varnish", WafCategory.ReverseProxy, Confidence.High, "Via", @"varnish"),
        HN("Varnish", WafCategory.ReverseProxy, Confidence.High, @"^x-varnish$"),
        H("Varnish", WafCategory.ReverseProxy, Confidence.Medium, "X-Cache", @"varnish"),
        Ck("F5 BIG-IP {affinity}", WafCategory.LoadBalancer, Confidence.High, @"^BIGipServer|^TS[0-9a-f]{6,8}="),
        H("F5 BIG-IP", WafCategory.LoadBalancer, Confidence.High, "Server", @"BigIP|BIG-IP"),
        HN("F5 BIG-IP ASM / Advanced WAF", WafCategory.Waf, Confidence.High, @"^x-wa-info$|^x-cnection$"),
        B("F5 BIG-IP ASM {block}", WafCategory.Waf, Confidence.High, @"The requested URL was rejected\. Please consult with your administrator|support ID is: \d+"),
        Ck("Citrix NetScaler / ADC", WafCategory.LoadBalancer, Confidence.High, @"^(citrix_ns_id|NSC_|ns_af=)"),
        H("Citrix NetScaler / ADC", WafCategory.LoadBalancer, Confidence.High, "Via", @"NS-CACHE"),
        HN("Citrix NetScaler {altered}", WafCategory.LoadBalancer, Confidence.Medium, @"^cneonction$|^nncoection$"),
        Ck("Fortinet FortiWeb", WafCategory.Waf, Confidence.High, @"^FORTIWAFSID="),
        B("Fortinet FortiWeb {block}", WafCategory.Waf, Confidence.Medium, @"\.fgd_icon|FortiWeb|Fortinet"),
        Ck("Barracuda WAF", WafCategory.Waf, Confidence.High, @"^barra_counter_session=|^BNI__BARRACUDA|^BNI_persistence"),
        H("Barracuda WAF", WafCategory.Waf, Confidence.Medium, "Server", @"Barracuda"),
        B("ModSecurity {block}", WafCategory.Waf, Confidence.High, @"Mod_Security|ModSecurity|NOYB"),
        H("ModSecurity", WafCategory.Waf, Confidence.Medium, "Server", @"Mod_Security|NOYB"),
        B("Wordfence (plugin WAF)", WafCategory.Waf, Confidence.High, @"Generated by Wordfence|wordfence"),
        B("Sophos / Astaro WAF", WafCategory.Waf, Confidence.Medium, @"Powered by UTM Web Protection|Sophos"),
        H("Check Point", WafCategory.Waf, Confidence.Medium, "X-CP-", @"."),
        HN("DDoS-Guard", WafCategory.Cdn, Confidence.High, @"^x-ddos-guard"),
        H("DDoS-Guard", WafCategory.Cdn, Confidence.High, "Server", @"ddos-guard"),
        H("StackPath / MaxCDN", WafCategory.Cdn, Confidence.Medium, "Server", @"StackPath|NetDNA"),
        H("Bunny CDN", WafCategory.Cdn, Confidence.High, "Server", @"BunnyCDN"),
        H("KeyCDN", WafCategory.Cdn, Confidence.High, "Server", @"keycdn"),
        H("CDN77", WafCategory.Cdn, Confidence.High, "Server", @"CDN77"),
        H("Radware AppWall", WafCategory.Waf, Confidence.Medium, "X-SL-CompState", @"."),
        H("Radware", WafCategory.Waf, Confidence.Medium, "Server", @"Radware"),
        H("Palo Alto / Prisma", WafCategory.Waf, Confidence.Medium, "Server", @"Prisma|Palo Alto"),
        H("nginx {front-end}", WafCategory.ReverseProxy, Confidence.Low, "Server", @"^nginx"),
        H("Apache {front-end}", WafCategory.ReverseProxy, Confidence.Low, "Server", @"^Apache(?!.*PHP)"),
        H("HAProxy", WafCategory.LoadBalancer, Confidence.Medium, "Server", @"haproxy"),
        Ck("HAProxy / {generic-affinity}", WafCategory.LoadBalancer, Confidence.Medium, @"^(SERVERID|SRV|SRVID|ROUTEID|route|JSESSIONID.*\.node\d|lb_?cookie|__lb)="),
        H("Traefik", WafCategory.ReverseProxy, Confidence.High, "Server", @"traefik"),
        H("Envoy", WafCategory.ReverseProxy, Confidence.High, "Server", @"^envoy"),
        HN("Envoy", WafCategory.ReverseProxy, Confidence.High, @"^x-envoy-"),
        H("Caddy", WafCategory.ReverseProxy, Confidence.Medium, "Server", @"^Caddy"),
        H("LiteSpeed", WafCategory.ReverseProxy, Confidence.Low, "Server", @"LiteSpeed"),
        H("Squid", WafCategory.ReverseProxy, Confidence.High, "Via", @"squid"),
        H("Zscaler", WafCategory.ReverseProxy, Confidence.High, "Via", @"zscaler"),
        H("Kong", WafCategory.ReverseProxy, Confidence.High, "Via", @"kong"),
        H("Kemp LoadMaster", WafCategory.LoadBalancer, Confidence.Medium, "Server", @"Kemp"),
        H("A10 Networks", WafCategory.LoadBalancer, Confidence.Medium, "Server", @"A10|AX-"),
        H("{generic-proxy} (Via)", WafCategory.ReverseProxy, Confidence.Low, "Via", @"."),
        HN("{generic-cache}", WafCategory.ReverseProxy, Confidence.Low, @"^x-cache$|^x-cache-hits$|^x-proxy-cache$|^x-backend-server$|^x-upstream$"),
    ];

    /// <summary>Firme statiche su una risposta.</summary>
    public static List<WafFinding> FromSnapshot(HttpSnapshot snap)
    {
        var found = new List<WafFinding>();
        if (!snap.HasResponse) return found;
        foreach (var sig in Signatures)
        {
            string? ev = null;
            if (sig.Where.StartsWith("header:", StringComparison.Ordinal))
            {
                string hn = sig.Where[7..];
                foreach (var h in snap.Headers)
                    if ((h.Key.Equals(hn, StringComparison.OrdinalIgnoreCase) || (hn.EndsWith('-') && h.Key.StartsWith(hn, StringComparison.OrdinalIgnoreCase))) && sig.Rx.IsMatch(h.Value))
                    { ev = $"{h.Key}: {Short(h.Value)}"; break; }
            }
            else if (sig.Where == "headername")
            {
                foreach (var h in snap.Headers)
                    if (sig.Rx.IsMatch(h.Key)) { ev = $"{h.Key}: {Short(h.Value)}"; break; }
            }
            else if (sig.Where == "cookie")
            {
                foreach (var c in snap.HeaderValues("Set-Cookie"))
                    if (sig.Rx.IsMatch(c)) { ev = "Set-Cookie: " + Short(c.Split(';')[0]); break; }
            }
            else if (sig.Where == "body")
            {
                // le pagine di blocco contano solo con stato di errore/blocco, per non scambiare un articolo che parla di Cloudflare per Cloudflare
                if (snap.Status >= 400 && snap.Body.Length > 0)
                {
                    var m = sig.Rx.Match(snap.Body);
                    if (m.Success) ev = L.F("corpo della risposta {0}: \"{1}\"", snap.Status, Short(m.Value));
                }
            }
            if (ev != null) Merge(found, new WafFinding(sig.Cat, DisplayName(sig.Name), sig.Conf, ev));
        }
        return found;
    }

    /// <summary>Indizi dal certificato TLS (CDN e WAF cloud terminano TLS con certificati propri o condivisi).</summary>
    public static List<WafFinding> FromTls(TlsInfo? tls)
    {
        var found = new List<WafFinding>();
        if (tls is not { Handshake: true }) return found;
        string issuer = tls.Issuer;
        void Add(string name, WafCategory cat, Confidence c) => Merge(found, new WafFinding(cat, DisplayName(name), c, L.F("certificato emesso da \"{0}\" per \"{1}\"", issuer, tls.Subject)));
        if (Regex.IsMatch(issuer, "Cloudflare", RegexOptions.IgnoreCase)) Add("Cloudflare", WafCategory.Cdn, Confidence.High);
        if (Regex.IsMatch(issuer, "Amazon", RegexOptions.IgnoreCase)) Add("AWS {acm-cert}", WafCategory.Cdn, Confidence.Low);
        if (Regex.IsMatch(issuer, "Microsoft Azure", RegexOptions.IgnoreCase)) Add("Azure {managed-cert}", WafCategory.Cdn, Confidence.Low);
        if (Regex.IsMatch(issuer, "Google Trust Services|GTS", RegexOptions.IgnoreCase) && Regex.IsMatch(tls.Subject, @"\.(google|goog|run\.app)$", RegexOptions.IgnoreCase)) Add("Google Cloud", WafCategory.Cdn, Confidence.Low);
        if (Regex.IsMatch(issuer, "Incapsula|Imperva", RegexOptions.IgnoreCase)) Add("Imperva / Incapsula", WafCategory.Waf, Confidence.High);
        if (Regex.IsMatch(issuer, "Akamai", RegexOptions.IgnoreCase)) Add("Akamai", WafCategory.Cdn, Confidence.High);
        if (tls.SubjectAltNames.Count >= 30) Merge(found, new WafFinding(WafCategory.Cdn, L.T("Certificato condiviso (molti SAN)"), Confidence.Low, L.F("{0} nomi alternativi nel certificato: tipico di CDN e hosting condivisi", tls.SubjectAltNames.Count)));
        return found;
    }

    /// <summary>
    /// Test comportamentale: la risposta a una richiesta con parametri dall'aspetto ostile ma inerti, confrontata con la
    /// richiesta normale sullo stesso percorso. Un cambio di stato verso 403/406/429/5xx, o un cambio di header Server,
    /// indica un filtro attivo.
    /// </summary>
    public static WafFinding? FromBehaviour(HttpSnapshot baseline, HttpSnapshot hostile)
    {
        if (!baseline.HasResponse) return null;
        if (!hostile.HasResponse)
            return new WafFinding(WafCategory.Waf, L.T("Filtro attivo (connessione chiusa)"), Confidence.Medium,
                L.F("la richiesta con parametri ostili non ha ricevuto risposta ({0}), quella normale sì ({1})", hostile.Error, baseline.Status));
        bool blockedStatus = hostile.Status is 403 or 406 or 418 or 429 or 503 or 501 && baseline.Status != hostile.Status;
        bool serverChanged = !string.Equals(baseline.Header("Server") ?? "", hostile.Header("Server") ?? "", StringComparison.Ordinal);
        if (blockedStatus)
            return new WafFinding(WafCategory.Waf, L.T("Filtro attivo sui parametri"), serverChanged ? Confidence.High : Confidence.Medium,
                L.F("richiesta normale: {0}; con parametri ostili: {1}{2}", baseline.Status, hostile.Status, serverChanged ? L.F(" (header Server diverso: \"{0}\")", hostile.Header("Server")) : ""));
        if (hostile.Status == 404 && baseline.Status == 200)
            return new WafFinding(WafCategory.Waf, L.T("Possibile filtro (404 sui parametri ostili)"), Confidence.Low,
                L.F("richiesta normale: {0}; con parametri ostili: {1}", baseline.Status, hostile.Status));
        return null;
    }

    /// <summary>Indizi di bilanciamento: più indirizzi per il nome, risposte che cambiano tra richieste ripetute.</summary>
    public static List<WafFinding> FromRepetition(IReadOnlyList<string> resolvedIps, IReadOnlyList<HttpSnapshot> repeats)
    {
        var found = new List<WafFinding>();
        if (resolvedIps.Count > 1)
            found.Add(new WafFinding(WafCategory.LoadBalancer, L.T("Più indirizzi per il nome (DNS round-robin o anycast)"), Confidence.Medium, string.Join(", ", resolvedIps)));
        var ok = repeats.Where(r => r.HasResponse).ToList();
        if (ok.Count >= 2)
        {
            var servers = ok.Select(r => r.Header("Server") ?? "").Distinct().ToList();
            if (servers.Count > 1)
                found.Add(new WafFinding(WafCategory.LoadBalancer, L.T("Header Server diverso tra richieste ripetute"), Confidence.Medium, string.Join(" | ", servers.Select(s => s.Length == 0 ? L.T("(vuoto)") : s))));
            var backends = ok.SelectMany(r => r.Headers.Where(h => Regex.IsMatch(h.Key, "^x-(backend|served-by|upstream|node|server-id|host-id|instance)", RegexOptions.IgnoreCase)).Select(h => $"{h.Key}: {h.Value}")).Distinct().ToList();
            if (backends.Count > 1)
                found.Add(new WafFinding(WafCategory.LoadBalancer, L.T("Identificativo di backend variabile"), Confidence.High, string.Join(" | ", backends)));
            // v1.6: confronto degli SCARTI (Date − ora di ricezione), non dei Date grezzi: tra due richieste consecutive passano secondi,
            // e un singolo nodo con l'orologio giusto dava "orologi diversi" solo perché la seconda risposta era arrivata dopo.
            var offsets = ok.Where(r => r.ReceivedUtc != null)
                .Select(r => (Date: r.Header("Date"), Received: r.ReceivedUtc!.Value))
                .Where(x => x.Date != null && DateTimeOffset.TryParse(x.Date, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out _))
                .Select(x => (DateTimeOffset.Parse(x.Date!, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal).UtcDateTime - x.Received).TotalSeconds)
                .ToList();
            if (offsets.Count >= 2 && offsets.Max() - offsets.Min() > 60)
                found.Add(new WafFinding(WafCategory.LoadBalancer, L.T("Orologi diversi nell'header Date"), Confidence.Low, L.F("scarto di {0:F0} s tra gli orologi dei nodi (Date rispetto all'ora di ricezione): probabili nodi distinti", offsets.Max() - offsets.Min())));
        }
        return found;
    }

    public static void Merge(List<WafFinding> list, WafFinding f)
    {
        int i = list.FindIndex(x => x.Name == f.Name && x.Category == f.Category);
        if (i < 0) { list.Add(f); return; }
        var cur = list[i];
        if (f.Confidence > cur.Confidence || (f.Confidence == cur.Confidence && !cur.Evidence.Contains(f.Evidence)))
            list[i] = cur with { Confidence = f.Confidence > cur.Confidence ? f.Confidence : cur.Confidence, Evidence = cur.Evidence.Contains(f.Evidence) ? cur.Evidence : cur.Evidence + "; " + f.Evidence };
    }

    /// <summary>Riassunto per la tabella: i nomi delle rilevazioni più affidabili, per categoria.</summary>
    public static string Summarize(IReadOnlyList<WafFinding> findings)
    {
        if (findings.Count == 0) return L.T("nessuno rilevato");
        var strong = findings.Where(f => f.Confidence >= Confidence.Medium).ToList();
        if (strong.Count == 0)
            return L.T("solo indizi deboli") + ": " + string.Join("; ", findings.Select(f => f.Name).Distinct().Take(2));
        return string.Join("; ", strong.OrderByDescending(f => f.Confidence).ThenBy(f => f.Category).Select(f => $"{Labels.WafCategory(f.Category)}: {f.Name}").Distinct().Take(4));
    }

    /// <summary>I nomi delle firme restano in inglese (nomi di prodotto); le qualifiche tra graffe si traducono.</summary>
    internal static string DisplayName(string name) => name
        .Replace("{block}", "(" + L.T("pagina di blocco") + ")")
        .Replace("{affinity}", "(" + L.T("cookie di affinità") + ")")
        .Replace("{altered}", "(" + L.T("header alterati") + ")")
        .Replace("{generic-affinity}", L.T("cookie di affinità generico"))
        .Replace("{generic-proxy}", L.T("Proxy generico"))
        .Replace("{generic-cache}", L.T("Cache o proxy generico"))
        .Replace("{front-end}", "(" + L.T("front-end o reverse proxy") + ")")
        .Replace("{acm-cert}", "(" + L.T("certificato ACM") + ")")
        .Replace("{managed-cert}", "(" + L.T("certificato gestito") + ")");

    private static string Short(string s) => s.Length <= 80 ? s : s[..77] + "...";
}
