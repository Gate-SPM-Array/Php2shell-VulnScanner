using System.Globalization;
using System.Net;
using System.Text;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Core.Report;

/// <summary>
/// Report compatto: solo ciò che serve a decidere. Intestazione con i dati della scansione e i riquadri per verdetto
/// (servizi e host distinti), i servizi da tenere in considerazione, le esposizioni, le applicazioni riconosciute, un
/// rigo per host attivo, il rimando al report completo. Niente righe non raggiungibili, niente intestazioni grezze,
/// niente dettaglio per richiesta: resta leggibile (e inviabile) anche su una /16.
/// </summary>
public static class CompactReportGenerator
{
    private static CultureInfo C => L.Culture;

    /// <summary>Verdetti che richiedono attenzione, nell'ordine in cui vanno letti.</summary>
    public static readonly Verdict[] Attention = [Verdict.VulnerableByVersion, Verdict.LikelyVulnerable, Verdict.MitigatedAtEdge, Verdict.Undetermined];

    /// <summary>Ordine "caso peggiore": più alto = più grave. Serve a scegliere il verdetto di un host tra le sue righe.</summary>
    public static int Severity(Verdict v) => v switch
    {
        Verdict.VulnerableByVersion => 7,
        Verdict.LikelyVulnerable => 6,
        Verdict.MitigatedAtEdge => 5,
        Verdict.Undetermined => 4,
        Verdict.FixedByVersion => 3,
        Verdict.NoPhpDetected => 2,
        _ => 1,
    };

    /// <summary>Verdetto peggiore tra più righe (es. le porte di un host).</summary>
    public static Verdict Worst(IEnumerable<Verdict> verdicts)
    {
        Verdict best = Verdict.NotReachable; int bs = 0;
        foreach (var v in verdicts) { int s = Severity(v); if (s > bs) { bs = s; best = v; } }
        return best;
    }

    /// <summary>Pagina phpinfo esposta: la versione viene da lì, oppure la superficie o le esposizioni la nominano.</summary>
    public static bool HasPhpInfo(ScanResult r) =>
        r.PhpVersionSource.Contains("phpinfo", StringComparison.OrdinalIgnoreCase) || r.PhpVersionSource.Contains("info.php", StringComparison.OrdinalIgnoreCase);

    /// <summary>Directory listing sul percorso principale (prima risposta con "&lt;title&gt;Index of /").</summary>
    public static bool HasDirectoryListing(ScanResult r) =>
        r.Requests.Count > 0 && r.Requests[0].Body.Contains("<title>Index of /", StringComparison.OrdinalIgnoreCase);

    public static string Build(ScanSession s) => Build(s, "");

    public static string Build(ScanSession s, string fullReportFileName)
    {
        var sb = new StringBuilder(32 * 1024);
        string title = L.F("Report compatto PHP2Shell – {0:dd/MM/yyyy HH:mm}", s.StartLocal);
        sb.Append("<!doctype html><html lang=\"").Append(L.Code).Append("\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>")
          .Append(E(title)).Append("</title><style>").Append(Css).Append("</style></head><body><div class=\"wrap\">");

        var results = s.Results;
        var reachable = results.Where(r => r.HttpReachable).ToList();
        var httpHosts = reachable.Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        // ---- intestazione ----
        sb.Append("<header><h1>").Append(E(L.T("PHP Vuln Scanner – Report compatto PHP2Shell"))).Append("</h1>");
        sb.Append("<p class=\"lead\">").Append(E(L.T("Sintesi decisionale: servizi da tenere in considerazione, esposizioni, applicazioni riconosciute e host attivi. Evidenze, intestazioni e test per richiesta sono nel report completo."))).Append("</p>");
        sb.Append("<table class=\"kv\">");
        Kv(sb, L.T("Bersagli / porte"), (s.TargetsSummary.Length > 0 ? s.TargetsSummary : L.F("{0} bersagli", s.TargetCount)) + " × " + string.Join(", ", s.Ports));
        Kv(sb, L.T("Avvio"), s.StartLocal.ToString("dd/MM/yyyy HH:mm:ss", C));
        Kv(sb, L.T("Fine"), s.EndLocal?.ToString("dd/MM/yyyy HH:mm:ss", C) ?? "–");
        Kv(sb, L.T("Stato"), StatusLabel(s.Status));
        if (s.Cycles > 1) Kv(sb, L.T("Cicli"), L.F("{0} di {1}", s.Cycle, s.Cycles) + ", " + (s.Consolidated ? L.T("risultati consolidati (vince il più informativo, a parità il più recente)") : L.T("una sessione per ciclo")));
        Kv(sb, L.T("Programma"), $"PHP Vuln Scanner v{s.AppVersion}");
        Kv(sb, L.T("Database applicazioni"), s.DataVersion.Length > 0 ? s.DataVersion.Replace("\n", " | ") : L.T("non caricato: solo le firme incorporate"));
        sb.Append("</table></header>");

        // ---- riquadri: servizi e host per verdetto ----
        sb.Append("<section><h2>").Append(E(L.T("Riepilogo"))).Append("</h2><div class=\"kpis\">");
        var suspect = results.Where(IsPhpSuspect).ToList();
        foreach (var v in new[] { Verdict.VulnerableByVersion, Verdict.LikelyVulnerable, Verdict.Undetermined, Verdict.MitigatedAtEdge, Verdict.FixedByVersion, Verdict.NoPhpDetected, Verdict.NotReachable })
        {
            var rows = results.Where(r => r.Verdict == v);
            int services = 0; var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in rows) { services++; hosts.Add(HostLists.HostIp(r)); }
            int hinted = v == Verdict.NoPhpDetected ? suspect.Count(r => r.Verdict == v) : 0;
            sb.Append("<div class=\"kpi ").Append(Labels.VerdictClass(v)).Append("\"><span class=\"n\">").Append(services).Append("</span><span class=\"l\">").Append(E(Labels.Verdict(v))).Append("</span><span class=\"h\">")
              .Append(E(L.F("{0} servizi su {1} host", services, hosts.Count))).Append(hinted > 0 ? " " + E(L.F("(di cui {0} con indizi)", hinted)) : "").Append("</span></div>");
        }
        sb.Append("<div class=\"kpi warn\"><span class=\"n\">").Append(suspect.Count).Append("</span><span class=\"l\">").Append(E(L.T("PHP sospetto"))).Append("</span><span class=\"h\">")
          .Append(E(L.F("{0} servizi su {1} host", suspect.Count, suspect.Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count()))).Append("</span></div>");
        sb.Append("<div class=\"kpi muted\"><span class=\"n\">").Append(s.HostsAlive).Append("</span><span class=\"l\">").Append(E(L.T("Host attivi"))).Append("</span><span class=\"h\">")
          .Append(E(L.F("Host attivi {0} su {1}, {2} con HTTP", s.HostsAlive, s.HostsTotal, s.HostsHttp))).Append("</span></div>");
        sb.Append("</div>");
        sb.Append("<p class=\"note\">").Append(E(L.F("{0} servizi (righe bersaglio/porta/nome) su {1} host distinti.", results.Count, results.Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count()))).Append("</p>");

        foreach (var c in Correlations(reachable, httpHosts.Count))
            sb.Append("<p class=\"note\"><b>").Append(E(L.T("Correlazione"))).Append(":</b> ").Append(E(L.F("\"{0}: {1}\" compare su {2} host su {3} con HTTP, con web server diversi: è con ogni probabilità un unico dispositivo di perimetro (IPS/WAF di rete) e non una protezione dei singoli host.", Labels.WafCategory(c.Category), c.Name, c.Hosts, httpHosts.Count))).Append("</p>");
        if (s.Cycles > 1 && s.Consolidated)
            sb.Append("<p class=\"note\">").Append(E(L.F("Consolidamento di {0} cicli: {1} risultati con verdetto cambiato tra i cicli (segnati con Δ nella tabella; la storia è nella scheda).", s.Cycle, results.Count(ResultMerger.VerdictChanged)))).Append("</p>");
        sb.Append("</section>");

        // ---- da tenere in considerazione ----
        var attention = results.Where(r => Attention.Contains(r.Verdict)).OrderByDescending(r => r.Priority).ThenBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
        sb.Append("<section><h2>").Append(E(L.T("Da tenere in considerazione"))).Append("</h2>");
        sb.Append("<p class=\"note\">").Append(E(L.F("{0} servizi con verdetto vulnerabile, probabilmente vulnerabile, mitigato al perimetro o non determinabile, in ordine di priorità.", attention.Count))).Append("</p>");
        if (attention.Count > 0)
        {
            sb.Append("<table class=\"att\"><thead><tr>");
            foreach (var h in new[] { L.T("Bersaglio"), L.T("Nomi"), L.T("Porta"), L.T("Verdetto"), L.T("Priorità"), L.T("PHP"), L.T("SAPI"), L.T("App"), L.T("NCSC-NL"), L.T("Barriera"), L.T("WAF"), L.T("Superficie"), L.T("Ciclo"), L.T("Motivazione") })
                sb.Append("<th>").Append(E(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var r in attention)
            {
                sb.Append("<tr><td>").Append(E(HostLists.HostIp(r))).Append("</td><td>").Append(E(NamesCell(r))).Append("</td><td>").Append(r.Port).Append(r.Scheme.Length > 0 ? " " + r.Scheme : "").Append("</td><td>")
                  .Append(Badge(r.Verdict)).Append("</td><td>").Append(E(Labels.Priority(r.Priority))).Append("</td><td>").Append(E(PhpCell(r))).Append("</td><td>").Append(E(r.Sapi.Length > 0 ? Labels.Sapi(r.Sapi) : "–")).Append("</td><td>")
                  .Append(E(AppCell(r))).Append("</td><td>").Append(E(r.NcscStatus.Length > 0 ? r.NcscStatus : "–")).Append("</td><td>").Append(E(Labels.Multipart(r.Multipart))).Append(r.VariantsBlocked >= 0 ? $" ({r.VariantsBlocked}/{r.VariantsTotal})" : "").Append("</td><td>")
                  .Append(E(r.WafSummary.Length > 0 ? r.WafSummary : "–")).Append("</td><td>").Append(r.PhpSurface.Count).Append("</td><td>").Append(CycleCell(r, s)).Append("</td><td class=\"why\">").Append(E(ShortReason(r.VerdictReason))).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        // esposizioni
        var exposed = results.Where(r => r.HttpReachable && (r.Exposures.Count > 0 || HasPhpInfo(r) || HasDirectoryListing(r))).OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
        sb.Append("<h3>").Append(E(L.T("Esposizioni"))).Append("</h3>");
        if (exposed.Count == 0) sb.Append("<p class=\"note\">").Append(E(L.T("Nessuna esposizione accessoria rilevata (phpinfo, directory listing, file di configurazione o sorgenti)."))).Append("</p>");
        else
        {
            sb.Append("<table class=\"exp\"><thead><tr>");
            foreach (var h in new[] { L.T("Bersaglio"), L.T("Nomi"), L.T("Porta"), L.T("Esposizioni") }) sb.Append("<th>").Append(E(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var r in exposed)
            {
                var items = new List<string>();
                if (HasPhpInfo(r)) items.Add(L.F("pagina phpinfo esposta: {0}", r.PhpVersionSource));
                if (HasDirectoryListing(r)) items.Add(L.T("directory listing sul percorso principale"));
                foreach (var x in r.Exposures) if (!items.Contains(x)) items.Add(x);
                sb.Append("<tr><td>").Append(E(HostLists.HostIp(r))).Append("</td><td>").Append(E(NamesCell(r))).Append("</td><td>").Append(r.Port).Append("</td><td>").Append(E(string.Join("; ", items))).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        // applicazioni riconosciute
        var apps = reachable.Where(r => r.Application.Length > 0)
            .GroupBy(r => (App: r.Application, Ver: r.ApplicationVersion), StringTupleComparer.Instance)
            .Select(g => (App: g.Key.Item1, Ver: g.Key.Item2, Hosts: g.Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(Targets.TargetParser.SortKey, StringComparer.Ordinal).ToList(),
                          Check: g.Select(r => r.AppVersionCheck).FirstOrDefault(x => x.Length > 0) ?? "", Ncsc: g.Select(r => r.NcscStatus).FirstOrDefault(x => x.Length > 0) ?? ""))
            .OrderBy(a => a.App, StringComparer.OrdinalIgnoreCase).ThenBy(a => a.Ver, StringComparer.OrdinalIgnoreCase).ToList();
        sb.Append("<h3>").Append(E(L.T("Applicazioni riconosciute"))).Append("</h3>");
        if (apps.Count == 0) sb.Append("<p class=\"note\">").Append(E(L.T("Nessuna applicazione riconosciuta."))).Append("</p>");
        else
        {
            sb.Append("<table class=\"app\"><thead><tr>");
            foreach (var h in new[] { L.T("Applicazione"), L.T("Versione"), L.T("NCSC-NL"), L.T("Host") }) sb.Append("<th>").Append(E(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var a in apps)
                sb.Append("<tr><td>").Append(E(a.App)).Append("</td><td>").Append(E(a.Ver.Length > 0 ? a.Ver + (a.Check.Length > 0 ? " – " + a.Check : "") : "–")).Append("</td><td>").Append(E(a.Ncsc.Length > 0 ? a.Ncsc : "–")).Append("</td><td>")
                  .Append(a.Hosts.Count).Append(": ").Append(E(Limit(a.Hosts, 6))).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</section>");

        // ---- host attivi ----
        var hostRows = results.Where(r => HostLists.IsAlive(r) || r.HttpReachable).GroupBy(HostLists.HostIp, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => Targets.TargetParser.SortKey(g.Key), StringComparer.Ordinal).ToList();
        sb.Append("<section><h2>").Append(E(L.T("Host attivi"))).Append("</h2>");
        sb.Append("<p class=\"note\">").Append(E(L.F("{0} host attivi o con risposta HTTP; un rigo per indirizzo, verdetto peggiore tra le sue porte.", hostRows.Count))).Append("</p>");
        if (hostRows.Count > 0)
        {
            sb.Append("<table class=\"hosts\"><thead><tr>");
            foreach (var h in new[] { L.T("Bersaglio"), L.T("Nomi"), L.T("Porte HTTP"), L.T("Verdetto"), L.T("App"), L.T("Alive") }) sb.Append("<th>").Append(E(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var g in hostRows)
            {
                var names = HostLists.Names(g);
                var ports = g.Where(r => r.HttpReachable).Select(r => (r.Port, r.Scheme)).Distinct().OrderBy(p => p.Port).Select(p => p.Port + (p.Scheme.Length > 0 ? " " + p.Scheme : "")).ToList();
                var hostApps = g.Where(r => r.Application.Length > 0).Select(r => r.Application + (r.ApplicationVersion.Length > 0 ? " " + r.ApplicationVersion : "")).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                string alive = g.Select(r => r.AliveMethod).FirstOrDefault(m => m.Length > 0) ?? (g.Any(r => r.HttpReachable) ? "HTTP" : g.Any(r => r.Tls is { Handshake: true }) ? "TLS" : "–");
                sb.Append("<tr><td>").Append(E(g.Key)).Append("</td><td>").Append(E(names.Count > 0 ? string.Join(", ", names) : "–")).Append("</td><td>").Append(E(ports.Count > 0 ? string.Join(", ", ports) : "–")).Append("</td><td>")
                  .Append(Badge(Worst(g.Select(r => r.Verdict)))).Append("</td><td>").Append(E(hostApps.Count > 0 ? string.Join(", ", hostApps) : "–")).Append("</td><td>").Append(E(alive)).Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</section>");

        // ---- PHP sospetto: indizi senza prova ----
        var suspectRows = suspect.OrderByDescending(r => r.PhpHintScore).ThenBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
        sb.Append("<section><h2>").Append(E(L.T("PHP sospetto"))).Append("</h2>");
        sb.Append("<p class=\"note\">").Append(E(L.T("Servizi senza prova di PHP ma con indizi (intestazioni, cookie, percorsi, pannelli): da verificare sull'host prima di escluderli."))).Append(' ')
          .Append(E(L.F("{0} servizi su {1} host.", suspectRows.Count, suspectRows.Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count()))).Append("</p>");
        if (suspectRows.Count > 0)
        {
            sb.Append("<table class=\"sus\"><thead><tr>");
            foreach (var h in new[] { L.T("Bersaglio"), L.T("Nomi"), L.T("Porta"), L.T("Punteggio"), L.T("Indizi"), L.T("WAF") }) sb.Append("<th>").Append(E(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var r in suspectRows)
                sb.Append("<tr><td>").Append(E(HostLists.HostIp(r))).Append("</td><td>").Append(E(NamesCell(r))).Append("</td><td>").Append(r.Port).Append(r.Scheme.Length > 0 ? " " + r.Scheme : "").Append("</td><td>")
                  .Append(r.PhpHintScore).Append("</td><td>").Append(E(string.Join("; ", r.PhpHints))).Append("</td><td>").Append(E(r.WafSummary.Length > 0 ? r.WafSummary : "–")).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</section>");

        // ---- loquacità ----
        var talkative = results.Where(r => r.VerbosityScore > 0).OrderByDescending(r => r.VerbosityScore).ThenBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
        sb.Append("<section><h2>").Append(E(L.T("Loquacità"))).Append("</h2>");
        sb.Append("<p class=\"note\">").Append(E(L.T("Quanto ogni host racconta di sé senza che gli venga chiesto: versioni, phpinfo, directory listing, pagine di stato e di debug, file di Composer, nomi interni nel certificato. Un indice alto è un argomento organizzativo anche senza vulnerabilità."))).Append(' ')
          .Append(E(L.F("{0} servizi su {1} host.", talkative.Count, talkative.Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count()))).Append("</p>");
        if (talkative.Count > 0)
        {
            sb.Append("<table class=\"loq\"><thead><tr>");
            foreach (var h in new[] { L.T("Bersaglio"), L.T("Nomi"), L.T("Porta"), L.T("Indice"), L.T("Voci") }) sb.Append("<th>").Append(E(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var r in talkative)
                sb.Append("<tr><td>").Append(E(HostLists.HostIp(r))).Append("</td><td>").Append(E(NamesCell(r))).Append("</td><td>").Append(r.Port).Append(r.Scheme.Length > 0 ? " " + r.Scheme : "").Append("</td><td>")
                  .Append(r.VerbosityScore).Append("/5</td><td>").Append(E(string.Join("; ", r.VerbosityItems))).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</section>");

        // ---- certificati (v1.6) ----
        var certs = results.Where(r => r.CertificateStatus.Length > 0 && r.CertificateStatus != L.T("valido")).OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
        sb.Append("<section><h2>").Append(E(L.T("Certificati"))).Append("</h2>");
        sb.Append("<p class=\"note\">").Append(E(L.T("Servizi TLS con un certificato scaduto, autofirmato, non attendibile, con nome non corrispondente o chiave debole: non incide sul verdetto PHP2Shell, ma indica chi deve intervenire e dove."))).Append(' ')
          .Append(E(L.F("{0} servizi su {1} host.", certs.Count, certs.Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count()))).Append("</p>");
        if (certs.Count > 0)
        {
            sb.Append("<table class=\"cert\"><thead><tr>");
            foreach (var h in new[] { L.T("Bersaglio"), L.T("Porta"), L.T("Nomi"), L.T("Stato del certificato") }) sb.Append("<th>").Append(E(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var r in certs)
                sb.Append("<tr><td>").Append(E(HostLists.HostIp(r))).Append("</td><td>").Append(r.Port).Append("</td><td>").Append(E(NamesCell(r))).Append("</td><td>")
                  .Append(E(r.CertificateStatus)).Append("</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</section>");

        // ---- inventario (v1.6): solo quando la sessione ne ha uno ----
        try { sb.Append(InventoryReportSection.InventorySection(s, Inventory.InventoryMatcher.Read(s.Folder, s.AppVersion))); } catch { }

        // ---- piè di pagina ----
        sb.Append("<footer>");
        if (!string.IsNullOrWhiteSpace(fullReportFileName))
            sb.Append("<p>").Append(E(L.T("Report completo (evidenze, test, intestazioni):"))).Append(" <a href=\"").Append(E(Uri.EscapeDataString(fullReportFileName).Replace("%2F", "/"))).Append("\">").Append(E(fullReportFileName)).Append("</a></p>");
        sb.Append("<p>").Append(E(L.F("Generato da PHP Vuln Scanner v{0} il {1:dd/MM/yyyy HH:mm:ss}. Uso responsabile: scansionare solo sistemi propri o con autorizzazione scritta.", s.AppVersion, DateTime.Now))).Append("</p>");
        sb.Append("</footer></div></body></html>");
        return sb.ToString();
    }

    /// <summary>
    /// Correlazione tra host: lo stesso elemento a monte su almeno il 60% degli host con HTTP e con almeno 3 header Server
    /// diversi è un dispositivo di perimetro condiviso, non N protezioni locali.
    /// </summary>
    public static List<(WafCategory Category, string Name, int Hosts)> Correlations(IEnumerable<ScanResult> reachable, int httpHosts)
    {
        var list = new List<(WafCategory, string, int)>();
        if (httpHosts < 3) return list;
        var groups = new Dictionary<(WafCategory, string), (HashSet<string> Hosts, HashSet<string> Servers)>();
        foreach (var r in reachable)
            foreach (var f in r.Waf)
            {
                if (!groups.TryGetValue((f.Category, f.Name), out var g)) groups[(f.Category, f.Name)] = g = (new(StringComparer.OrdinalIgnoreCase), new(StringComparer.OrdinalIgnoreCase));
                g.Hosts.Add(HostLists.HostIp(r));
                if (r.ServerHeader.Length > 0) g.Servers.Add(r.ServerHeader);
            }
        foreach (var kv in groups.OrderByDescending(k => k.Value.Hosts.Count))
            if (kv.Value.Hosts.Count * 100 >= 60 * httpHosts && kv.Value.Servers.Count >= 3) list.Add((kv.Key.Item1, kv.Key.Item2, kv.Value.Hosts.Count));
        return list;
    }

    /// <summary>PHP "Forse" (v1.5): nessuna prova ma indizi passivi; un inventario da verificare, non un verdetto.</summary>
    public static bool IsPhpSuspect(ScanResult r) => r.HttpReachable && !r.PhpDetected && r.PhpPresence == "maybe";

    /// <summary>Tutti i nomi del servizio (nome della riga, scoperti, stesso contenuto, stesso esito), deduplicati e ordinati, mai troncati: i nomi dicono chi deve agire.</summary>
    public static string NamesCell(ScanResult r)
    {
        var names = HostLists.Names([r]);
        return names.Count > 0 ? string.Join(", ", names) : "–";
    }

    private static string PhpCell(ScanResult r)
    {
        string v = r.PhpVersionRaw.Length > 0 ? r.PhpVersionRaw : r.PhpDetected ? L.T("n.d.") : "–";
        if (r.PhpVersionFloor.Length > 0) v += " (" + r.PhpVersionFloor + ")";
        return v;
    }

    private static string AppCell(ScanResult r)
    {
        if (r.Application.Length == 0) return "–";
        string a = r.Application;
        if (r.ApplicationVersion.Length > 0) a += " " + r.ApplicationVersion;
        if (r.AppVersionCheck.Length > 0) a += " – " + r.AppVersionCheck;
        return a;
    }

    private static string CycleCell(ScanResult r, ScanSession s)
    {
        string c = s.Cycles > 1 ? r.Cycle.ToString() : "–";
        if (ResultMerger.VerdictChanged(r)) c += " <b class=\"b warn\" title=\"" + E(string.Join(" | ", r.History)) + "\">Δ</b>";
        return c;
    }

    /// <summary>Motivazione in breve: la prima frase (fino al primo ";"), al massimo 160 caratteri; la barriera ha già la sua colonna.</summary>
    public static string ShortReason(string reason)
    {
        int i = reason.IndexOf(';');
        string s = (i > 0 ? reason[..i] : reason).Trim();
        return s.Length > 160 ? s[..159] + "…" : s;
    }

    private static string Limit(List<string> items, int max) =>
        items.Count == 0 ? "–" : string.Join(", ", items.Take(max)) + (items.Count > max ? $" +{items.Count - max}" : "");

    private static string Badge(Verdict v) => "<b class=\"b " + Labels.VerdictClass(v) + "\">" + E(Labels.Verdict(v)) + "</b>";

    private static string StatusLabel(ScanStatus s) => s switch
    {
        ScanStatus.Completed => L.T("Completata"),
        ScanStatus.Stopped => L.T("Interrotta"),
        ScanStatus.Error => L.T("Errore"),
        _ => L.T("In corso"),
    };

    private static void Kv(StringBuilder sb, string k, string v) =>
        sb.Append("<tr><th>").Append(E(k)).Append("</th><td>").Append(E(v)).Append("</td></tr>");

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    private sealed class StringTupleComparer : IEqualityComparer<(string, string)>
    {
        public static readonly StringTupleComparer Instance = new();
        public bool Equals((string, string) x, (string, string) y) => string.Equals(x.Item1, y.Item1, StringComparison.OrdinalIgnoreCase) && string.Equals(x.Item2, y.Item2, StringComparison.OrdinalIgnoreCase);
        public int GetHashCode((string, string) o) => HashCode.Combine(o.Item1.ToLowerInvariant(), o.Item2.ToLowerInvariant());
    }

    /// <summary>Stesso linguaggio visivo del report completo (palette, riquadri, badge), ridotto a ciò che la pagina usa.</summary>
    public const string Css = """
:root{--bg:#fff;--fg:#1f2937;--muted:#6b7280;--line:#e5e7eb;--soft:#f6f7f9;--accent:#1d4ed8;--ok:#15803d;--ok-soft:#ecfdf3;--warn:#b45309;--warn-soft:#fff8e6;--bad:#b91c1c;--bad-soft:#fef2f2}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#111418;--fg:#e5e7eb;--muted:#9aa3af;--line:#2a2f37;--soft:#181c22;--accent:#7aa2ff;--ok:#4ade80;--ok-soft:#10241a;--warn:#fbbf24;--warn-soft:#2a2210;--bad:#f87171;--bad-soft:#2a1416}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1400px;margin:0 auto;padding:24px 16px 60px}h1{font-size:24px;margin:0 0 6px}h2{font-size:19px;margin:36px 0 10px;border-top:1px solid var(--line);padding-top:10px}h3{font-size:15px;margin:18px 0 6px}
.lead{color:var(--muted);max-width:900px;margin:0 0 14px}.note{color:var(--muted);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:4px 7px;text-align:left;vertical-align:top}th{background:var(--soft);font-weight:600}
table.kv{width:auto;margin:6px 0 10px}table.kv th{width:180px;white-space:nowrap}
.kpis{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 12px}.kpi{border:1px solid var(--line);border-radius:8px;padding:8px 14px;background:var(--bg);min-width:150px}
.kpi .n{display:block;font-size:22px;font-weight:600}.kpi .l{display:block;font-size:12px;color:var(--muted)}.kpi .h{display:block;font-size:11px;color:var(--muted)}
.kpi.bad .n{color:var(--bad)}.kpi.warn .n{color:var(--warn)}.kpi.ok .n{color:var(--ok)}
.b{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}.b.bad{background:var(--bad-soft);color:var(--bad)}.b.warn{background:var(--warn-soft);color:var(--warn)}.b.ok{background:var(--ok-soft);color:var(--ok)}.b.muted{background:var(--soft);color:var(--muted)}
table.att td:nth-child(-n+2),table.exp td:nth-child(-n+2),table.hosts td:nth-child(-n+2),table.sus td:nth-child(-n+2),table.loq td:nth-child(-n+2),table.app td:nth-child(4){font-family:Consolas,"Cascadia Mono",monospace;font-size:12px}td.why{font-size:12px;color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:10px}a{color:var(--accent)}
@media print{table{font-size:11px}tr{break-inside:avoid}}
""";
}
