using System.Globalization;
using System.Net;
using System.Text;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Output;
using PhpVulnScanner.Core.Php;

namespace PhpVulnScanner.Core.Report;

/// <summary>
/// Report HTML autoconsistente (nessuna risorsa esterna, apribile offline, stampabile in PDF dal browser):
/// parametri, riepilogo per verdetto, tabella filtrabile, scheda per bersaglio con tutte le evidenze, metodo e limiti.
/// </summary>
public static class ReportGenerator
{
    private static CultureInfo C => L.Culture;

    /// <summary>
    /// Genera nella cartella di sessione il report completo (report_completo_v&lt;ver&gt;.html, tutte le righe e le evidenze) e il report
    /// compatto (report_v&lt;ver&gt;.html: solo ciò che ha qualcosa da dire), mai sovrascritti; restituisce il percorso del compatto.
    /// </summary>
    public static string Generate(ScanSession session, string? folder = null)
    {
        folder ??= session.Folder;
        var full = SessionFiles.NextReportPath(folder, SessionFiles.FullReportPrefix, session.AppVersion);
        File.WriteAllText(full, Build(session, PerCycleSection(session, folder)), new UTF8Encoding(false));
        var compact = SessionFiles.NextReportPath(folder, SessionFiles.CompactReportPrefix, session.AppVersion);
        File.WriteAllText(compact, BuildCompact(session, Path.GetFileName(full)), new UTF8Encoding(false));
        return compact;
    }

    /// <summary>Report compatto (CompactReportGenerator): solo ciò che ha qualcosa da dire, con il rimando al completo.</summary>
    public static string BuildCompact(ScanSession s, string fullReportFileName) => CompactReportGenerator.Build(s, fullReportFileName);

    /// <summary>Sezione "Per ciclo" dei loop consolidati, dalle osservazioni di results.jsonl nella cartella; null quando non c'è nulla da aggiungere.</summary>
    public static string? PerCycleSection(ScanSession s, string folder)
    {
        try
        {
            if (s.Cycles <= 1 || !s.Consolidated) return null;
            string jsonl = Path.Combine(folder, SessionFiles.ResultsJsonl);
            if (!File.Exists(jsonl)) return null;
            var obs = SessionFiles.ReadJsonl(jsonl);
            if (obs.Count == 0) return null;
            var cycles = CycleReports.SplitByCycle(s, obs);
            if (cycles.Count <= 1) return null;
            // CSV per ciclo accanto al report (results_c1.csv …)
            var csv = new CsvFormat(s.Config.CsvDialect);
            foreach (var (cycle, session) in cycles)
            {
                try { File.WriteAllText(Path.Combine(folder, $"results_c{cycle}.csv"), SessionFiles.ResultsToCsv(session.Results, csv), SessionFiles.Utf8Bom); } catch { }
            }
            return CycleReports.BuildPerCycleSection(s, cycles);
        }
        catch { return null; }
    }

    public static string Build(ScanSession s) => Build(s, null);

    /// <summary>Report completo; <paramref name="extraSections"/> = frammenti HTML aggiuntivi (es. la sezione "Per ciclo" dei loop consolidati) inseriti prima del piè di pagina.</summary>
    public static string Build(ScanSession s, string? extraSections)
    {
        var sb = new StringBuilder(64 * 1024);
        string title = L.F("Report PHP2Shell – {0:dd/MM/yyyy HH:mm}", s.StartLocal);
        sb.Append("<!doctype html><html lang=\"").Append(L.Code).Append("\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>")
          .Append(E(title)).Append("</title><style>").Append(Css).Append("</style></head><body><div class=\"wrap\">");

        // Intestazione
        sb.Append("<header><h1>").Append(E(L.T("PHP Vuln Scanner – Report di scansione PHP2Shell"))).Append("</h1>");
        sb.Append("<p class=\"lead\">").Append(E(L.T("CVE-2026-109618 e CVE-2026-109619: rilevazione dell'esposizione dall'esterno (versione dichiarata, precondizioni raggiungibili, barriere al perimetro) e degli elementi a monte (WAF, CDN, reverse proxy, bilanciatori)."))).Append("</p>");
        sb.Append("<table class=\"kv\">");
        Kv(sb, L.T("Avvio"), s.StartLocal.ToString("dd/MM/yyyy HH:mm:ss", C));
        Kv(sb, L.T("Fine"), s.EndLocal?.ToString("dd/MM/yyyy HH:mm:ss", C) ?? "–");
        Kv(sb, L.T("Stato"), StatusLabel(s.Status));
        Kv(sb, L.T("Bersagli / porte"), L.F("{0} bersagli × {1} porte ({2})", s.TargetCount, s.PortCount, string.Join(", ", s.Ports)) + (s.TargetsSummary.Length > 0 ? " – " + L.F("elenco: {0}", s.TargetsSummary) : ""));
        Kv(sb, L.T("Host attivi"), L.F("{0} su {1} host distinti; {2} con risposta HTTP", s.HostsAlive, s.HostsTotal, s.HostsHttp));
        if (s.Cycles > 1) Kv(sb, L.T("Cicli"), L.F("{0} di {1}", s.Cycle, s.Cycles) + ", " + (s.Consolidated ? L.T("risultati consolidati (vince il più informativo, a parità il più recente)") : L.T("una sessione per ciclo")) + L.F(", pausa {0} s", s.Config.CyclePauseSec));
        Kv(sb, L.T("Percorsi sondati"), string.Join(" ", s.Paths));
        Kv(sb, L.T("Alive check"), s.Config.Alive.Enabled ? AliveDesc(s.Config.Alive) : L.T("disattivato"));
        Kv(sb, L.T("Livelli"), L.T("1 passivo") + (s.Config.LightMode ? " (" + L.T("modalità leggera HEAD") + ")" : "") + (s.Config.Level1InfoPages ? " + " + L.T("pagine rivelatrici") : "") + (s.Config.Level1EasterEgg ? " + " + L.T("easter egg") : "")
            + (s.Config.Level2 ? "; " + L.F("2 precondizioni e barriere (multipart di {0} KiB)", s.Config.SizeProbeKiB) : "") + (s.Config.WafDetect ? "; " + L.T("rilevazione WAF/proxy") + (s.Config.WafBehaviour ? " " + L.T("con test comportamentale") : "") : ""));
        Kv(sb, L.T("Timeout"), L.F("connessione {0} ms, lettura {1} ms, {2} thread", s.Config.ConnectTimeoutMs, s.Config.ReadTimeoutMs, s.Config.Threads));
        Kv(sb, L.T("Scoperta"), (s.Config.SurfaceDiscovery ? L.T("superficie PHP (file .php inesistente, punti di ingresso, link)") : L.T("superficie PHP disattivata")) + "; "
            + (!s.Config.DiscoverNames ? L.T("nomi non raccolti") : s.Config.RescanDiscoveredNames ? L.F("nomi raccolti e riscansionati con Host/SNI (max {0} per host)", s.Config.MaxNamesPerHost) : L.T("nomi solo raccolti")));
        Kv(sb, L.T("Ordine e ritmo"), (s.Config.RandomOrder ? L.T("ordine casuale degli host") : L.T("ordine sequenziale")) + "; "
            + (s.Config.DelayMaxMs > 0 || s.Config.MaxRequestsPerSecond > 0 ? L.F("pausa {0}-{1} ms per richiesta, tetto {2} richieste/s", s.Config.DelayMinMs, s.Config.DelayMaxMs, s.Config.MaxRequestsPerSecond == 0 ? "∞" : s.Config.MaxRequestsPerSecond.ToString()) : L.T("nessuna pausa tra le richieste"))
            + (s.Config.DebugMode ? "; " + L.T("modalità debug") : ""));
        Kv(sb, L.T("Programma"), $"PHP Vuln Scanner v{s.AppVersion} – {E(s.Machine)} – {E(s.OsDescription)}");
        Kv(sb, L.T("Database applicazioni"), s.DataVersion.Length > 0 ? s.DataVersion.Replace("\n", " | ") : L.T("non caricato: solo le firme incorporate"));
        if (s.ParseErrors.Count > 0) Kv(sb, L.T("Avvisi"), string.Join("; ", s.ParseErrors.Select(E)));
        sb.Append("</table></header>");

        // Riepilogo
        var counts = Enum.GetValues<Verdict>().ToDictionary(v => v, v => s.Results.Count(r => r.Verdict == v));
        sb.Append("<section><h2>").Append(E(L.T("Riepilogo"))).Append("</h2><div class=\"kpis\">");
        var hostsBy = Enum.GetValues<Verdict>().ToDictionary(v => v, v => s.Results.Where(r => r.Verdict == v).Select(r => r.DisplayIp).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        int phpMaybe = s.Results.Count(CompactReportGenerator.IsPhpSuspect);
        foreach (var v in new[] { Verdict.VulnerableByVersion, Verdict.LikelyVulnerable, Verdict.Undetermined, Verdict.MitigatedAtEdge, Verdict.FixedByVersion, Verdict.NoPhpDetected, Verdict.NotReachable })
            sb.Append("<button class=\"kpi ").Append(Labels.VerdictClass(v)).Append("\" data-filter=\"").Append(v).Append("\" title=\"").Append(E(L.T("servizi (IP + porta + nome) e host distinti"))).Append("\"><span class=\"n\">").Append(counts[v]).Append("</span><span class=\"l\">").Append(E(Labels.Verdict(v))).Append(counts[v] > 0 ? "<br>" + E(L.F("su {0} host", hostsBy[v])) : "")
              .Append(v == Verdict.NoPhpDetected && phpMaybe > 0 ? "<br>" + E(L.F("(di cui {0} con indizi)", phpMaybe)) : "").Append("</span></button>");
        sb.Append("<button class=\"kpi muted\" data-filter=\"\"><span class=\"n\">").Append(s.Results.Count).Append("</span><span class=\"l\">").Append(E(L.T("Servizi"))).Append("</span></button>");
        sb.Append("<button class=\"kpi muted\" data-alive=\"1\"><span class=\"n\">").Append(s.HostsAlive).Append("</span><span class=\"l\">").Append(E(L.F("Host attivi su {0}", s.HostsTotal))).Append("<br>").Append(E(L.F("{0} con HTTP", s.HostsHttp))).Append("</span></button>");
        sb.Append("</div>");
        // Correlazione tra host: lo stesso comportamento su gran parte degli host è un dispositivo di perimetro, non N WAF
        var httpHosts = s.Results.Where(r => r.HttpReachable).Select(r => r.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        if (httpHosts >= 5)
        {
            var common = s.Results.Where(r => r.HttpReachable).SelectMany(r => r.Waf.Select(f => (f.Category, f.Name, r.Host)))
                .GroupBy(x => (x.Category, x.Name)).Select(g => (g.Key.Category, g.Key.Name, Hosts: g.Select(x => x.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count()))
                .Where(g => g.Hosts >= 5 && g.Hosts * 2 >= httpHosts).OrderByDescending(g => g.Hosts).ToList();
            foreach (var c in common)
                sb.Append("<p class=\"note\"><b>").Append(E(L.T("Correlazione"))).Append(":</b> ").Append(E(L.F("\"{0}: {1}\" compare su {2} host su {3} con HTTP, con web server diversi: è con ogni probabilità un unico dispositivo di perimetro (IPS/WAF di rete) e non una protezione dei singoli host.", Labels.WafCategory(c.Category), c.Name, c.Hosts, httpHosts))).Append("</p>");
        }
        if (s.Cycles > 1 && s.Consolidated)
        {
            int changed = s.Results.Count(ResultMerger.VerdictChanged);
            sb.Append("<p class=\"note\">").Append(E(L.F("Consolidamento di {0} cicli: {1} risultati con verdetto cambiato tra i cicli (segnati con Δ nella tabella; la storia è nella scheda).", s.Cycle, changed))).Append("</p>");
        }
        var discovered = s.Results.Where(r => r.DiscoveredNames.Count > 0).SelectMany(r => r.DiscoveredNames.Select(n => (n, r.Host))).GroupBy(x => x.n).Select(g => (Name: g.Key, Hosts: g.Select(x => x.Host).Distinct().ToList())).OrderBy(x => x.Name).ToList();
        if (discovered.Count > 0)
        {
            sb.Append("<details class=\"names\"><summary>").Append(E(L.F("Nomi scoperti: {0} distinti su {1} host (da certificati e Location)", discovered.Count, discovered.SelectMany(d => d.Hosts).Distinct().Count()))).Append("</summary><table class=\"res\"><thead><tr><th>").Append(E(L.T("Nome"))).Append("</th><th>").Append(E(L.T("Host"))).Append("</th></tr></thead><tbody>");
            foreach (var d in discovered) sb.Append("<tr><td class=\"mono\">").Append(E(d.Name)).Append("</td><td class=\"mono\">").Append(E(string.Join(", ", d.Hosts.Take(8)) + (d.Hosts.Count > 8 ? " …" : ""))).Append("</td></tr>");
            sb.Append("</tbody></table></details>");
        }
        sb.Append("<p class=\"note\">").Append(E(L.T("Lettura dei verdetti: \"Vulnerabile per versione\" e \"Probabilmente vulnerabile\" richiedono l'aggiornamento; \"Mitigato al perimetro\" è un tampone, non una correzione; \"Non determinabile\" significa che il server non dichiara la versione e nessun test esterno può dimostrare lo stato: serve una verifica sull'host (php -v, changelog del pacchetto)."))).Append("</p>");

        // Tabella
        sb.Append("<input id=\"q\" type=\"search\" placeholder=\"").Append(E(L.T("Filtra per host, versione, WAF…"))).Append("\">");
        sb.Append("<table class=\"res\" id=\"res\"><thead><tr>");
        foreach (var h in new[] { L.T("Avvio"), L.T("Bersaglio"), L.T("Nome"), L.T("Porta"), L.T("Alive"), L.T("PHP"), L.T("Versione"), L.T("Stato versione"), L.T("SAPI"), L.T("App"), L.T("Superficie"), L.T("Barriera multipart"), L.T("WAF / proxy / bilanciatore"), L.T("Verdetto"), L.T("Priorità") })
            sb.Append("<th>").Append(E(h)).Append("</th>");
        sb.Append("</tr></thead><tbody>");
        int i = 0;
        foreach (var r in s.Results)
        {
            i++;
            bool hasCard = r.HttpReachable || s.Config.ReportUnreachableDetails;
            sb.Append("<tr class=\"row\" data-verdict=\"").Append(r.Verdict).Append("\" data-alive=\"").Append(r.Alive == AliveState.Alive || (!s.Config.Alive.Enabled && r.HttpReachable) ? "1" : "0").Append("\"><td class=\"mono\">").Append(E(Stamp.Local(r.StartedLocal))).Append("</td><td>")
              .Append(hasCard ? "<a href=\"#r" + i + "\">" + E(r.DisplayIp) + "</a>" : E(r.DisplayIp)).Append(ResultMerger.VerdictChanged(r) ? " <span class=\"badge warn\" title=\"" + E(string.Join(" | ", r.History)) + "\">Δ</span>" : "").Append("</td><td class=\"mono\">")
              .Append(E(NameColumn(r))).Append("</td><td>")
              .Append(r.Port).Append(r.Scheme.Length > 0 ? " " + r.Scheme : "").Append("</td><td>").Append(E(Labels.Alive(r.Alive))).Append(r.AliveMethod.Length > 0 ? " (" + E(r.AliveMethod) + ")" : "").Append("</td><td>")
              .Append(r.PhpDetected ? E(L.T("sì")) : CompactReportGenerator.IsPhpSuspect(r) ? E(L.T("forse")) : r.HttpReachable ? E(L.T("no")) : "–").Append("</td><td>").Append(E(r.PhpVersionRaw.Length > 0 ? r.PhpVersionRaw : "–")).Append("</td><td>")
              .Append(E(Labels.VersionStatus(r.VersionStatus))).Append("</td><td>").Append(E(r.Sapi.Length > 0 ? Labels.Sapi(r.Sapi) : "–")).Append("</td><td>").Append(E(r.Application.Length > 0 ? r.Application + (r.ApplicationVersion.Length > 0 ? " " + r.ApplicationVersion : "") : "–")).Append("</td><td>")
              .Append(r.PhpSurface.Count > 0 ? "<span title=\"" + E(string.Join(", ", r.PhpSurface)) + "\">" + r.PhpSurface.Count + "</span>" : r.HttpReachable ? "0" : "–").Append("</td><td>").Append(E(Labels.Multipart(r.Multipart)))
              .Append(r.VariantsBlocked >= 0 ? $" ({r.VariantsBlocked}/{r.VariantsTotal})" : "").Append("</td><td>").Append(E(r.WafSummary.Length > 0 ? r.WafSummary : "–")).Append("</td><td><span class=\"badge ")
              .Append(Labels.VerdictClass(r.Verdict)).Append("\">").Append(E(Labels.Verdict(r.Verdict))).Append("</span></td><td>").Append(E(Labels.Priority(r.Priority))).Append("</td></tr>");
        }
        sb.Append("</tbody></table></section>");

        // Schede
        sb.Append("<section><h2>").Append(E(L.T("Dettaglio per bersaglio"))).Append("</h2>");
        i = 0;
        int skipped = 0;
        foreach (var r in s.Results)
        {
            i++;
            if (!r.HttpReachable && !s.Config.ReportUnreachableDetails) { skipped++; continue; }
            sb.Append("<details class=\"card\" id=\"r").Append(i).Append("\" data-verdict=\"").Append(r.Verdict).Append("\" data-alive=\"").Append(r.Alive == AliveState.Alive || (!s.Config.Alive.Enabled && r.HttpReachable) ? "1" : "0").Append("\"><summary><span class=\"badge ").Append(Labels.VerdictClass(r.Verdict)).Append("\">")
              .Append(E(Labels.Verdict(r.Verdict))).Append("</span> <b>").Append(E(r.Display)).Append(":").Append(r.Port).Append("</b> <span class=\"muted\">").Append(E(r.VerdictReason)).Append("</span></summary>");
            sb.Append("<table class=\"kv\">");
            Kv(sb, L.T("Indirizzi"), string.Join(", ", r.ResolvedIps));
            Kv(sb, L.T("Host header"), r.HostHeader);
            Kv(sb, L.T("Avvio"), Stamp.Local(r.StartedLocal));
            Kv(sb, L.T("Priorità"), Labels.Priority(r.Priority));
            if (r.Alive != AliveState.NotTested) Kv(sb, L.T("Alive check"), Labels.Alive(r.Alive) + (r.AliveMethod.Length > 0 ? $" ({r.AliveMethod})" : "") + (r.AliveMethods.Length > 0 ? ": " + r.AliveMethods : ""));
            if (r.SapiEvidence.Length > 0) Kv(sb, "SAPI", (r.Sapi.Length > 0 ? Labels.Sapi(r.Sapi) + ": " : "") + r.SapiEvidence);
            if (r.OsHint.Length > 0) Kv(sb, L.T("Sistema operativo dichiarato"), r.OsHint);
            if (r.Application.Length > 0) Kv(sb, L.T("Applicazione"), $"{E(r.Application)}{(r.ApplicationVersion.Length > 0 ? " " + E(r.ApplicationVersion) : "")} ({E(r.ApplicationEvidence)})" + (r.ApplicationReference.Length > 0 ? $" – <a href=\"{r.ApplicationReference}\">{E(r.ApplicationReference.Contains("NCSC-NL") ? L.T("inventario NCSC-NL") : L.T("sito del prodotto"))}</a>" : ""), raw: true);
            if (r.NcscStatus.Length > 0) Kv(sb, L.T("Stato NCSC-NL per CVE"), E(r.NcscStatus) + (r.NcscReference.Length > 0 ? $" – <a href=\"{r.NcscReference}\">{E(L.T("scheda"))}</a>" : ""), raw: true);
            if (r.Technologies.Count > 0) Kv(sb, L.T("Tecnologie riconosciute"), string.Join(", ", r.Technologies));
            if (r.TechnologyStatuses.Count > 0) Kv(sb, L.T("Stato NCSC-NL delle tecnologie"), string.Join("; ", r.TechnologyStatuses));
            if (r.AppVersionCheck.Length > 0) Kv(sb, L.T("Versione dell'applicazione rispetto a NCSC-NL"), r.AppVersionCheck);
            if (r.SameContentNames.Count > 0) Kv(sb, L.T("Nomi con lo stesso contenuto"), string.Join(", ", r.SameContentNames) + " " + L.T("(= vhost predefinito, nessuna riga aggiuntiva)"));
            if (r.SameOutcomeNames.Count > 0) Kv(sb, L.T("Nomi con lo stesso esito"), string.Join(", ", r.SameOutcomeNames) + " " + L.T("(contenuto diverso, stesso verdetto, versione, SAPI, applicazione, barriera, WAF e priorità: nessuna riga aggiuntiva, osservazione in results.jsonl)"));
            if (r.PhpHints.Count > 0) Kv(sb, L.T("Indizi di PHP (peso)"), (r.PhpPresence == "maybe" ? L.T("forse") : r.PhpPresence == "yes" ? L.T("sì") : L.T("no")) + $" ({r.PhpHintScore}): " + string.Join("; ", r.PhpHints));
            if (r.IniHints.Count > 0) Kv(sb, L.T("Impostazioni PHP da phpinfo"), string.Join("; ", r.IniHints));
            if (r.VerbosityScore > 0) Kv(sb, L.T("Loquacità"), $"{r.VerbosityScore}/5" + (r.VerbosityItems.Count > 0 ? ": " + string.Join("; ", r.VerbosityItems) : ""));
            if (r.PhpVersionFloor.Length > 0) Kv(sb, L.T("Versione minima di PHP dichiarata"), r.PhpVersionFloor + (r.PhpVersionFloorSource.Length > 0 ? " (" + r.PhpVersionFloorSource + ")" : ""));
            if (r.HeadVsGet.Length > 0) Kv(sb, L.T("HEAD contro GET"), r.HeadVsGet);
            if (r.AllowedMethods.Length > 0) Kv(sb, L.T("Metodi consentiti (Allow)"), r.AllowedMethods);
            if (r.BrowserUaResult.Length > 0) Kv(sb, L.T("Secondo giro con User-Agent da browser"), r.BrowserUaResult);
            if (r.FastCgiExposed is bool fc) Kv(sb, L.T("FastCGI 9000"), (fc ? L.T("php-fpm esposto su TCP") : L.T("nessuna risposta FastCGI")) + (r.FastCgiDetail.Length > 0 ? ": " + r.FastCgiDetail : ""));
            if (r.Libraries.Count > 0) Kv(sb, L.T("Librerie (installed.json)"), string.Join(", ", r.Libraries));
            if (r.Components.Count > 0) Kv(sb, L.T("Componenti (plugin, temi, moduli)"), string.Join(", ", r.Components));
            if (r.Exposures.Count > 0) Kv(sb, L.T("Esposizioni"), "<ul class=\"exp\">" + string.Concat(r.Exposures.Select(x => "<li>" + E(x) + "</li>")) + "</ul>", raw: true);
            if (r.PhpSurfaceProbe.Length > 0) Kv(sb, L.T("Sonda .php inesistente"), r.SapiEvidence);
            if (r.PhpSurface.Count > 0) Kv(sb, L.T("Superficie PHP"), string.Join(", ", r.PhpSurface));
            if (r.DiscoveredNames.Count > 0) Kv(sb, L.T("Nomi scoperti"), string.Join(", ", r.DiscoveredNames));
            if (r.History.Count > 1) Kv(sb, L.T("Storia dei cicli"), string.Join(" → ", r.History));
            else if (s.Cycles > 1) Kv(sb, L.T("Ciclo"), r.Cycle.ToString());
            if (r.Tls != null) Kv(sb, "TLS", r.Tls.Handshake ? $"{r.Tls.Protocol}; CN={r.Tls.Subject}; {L.T("emesso da")} {r.Tls.Issuer}; {L.T("scadenza")} {r.Tls.NotAfter:dd/MM/yyyy}; SAN={r.Tls.SubjectAltNames.Count}; {(r.Tls.NameMatches ? L.T("nome corrispondente") : L.T("nome NON corrispondente"))}" : L.F("nessun TLS: {0}", r.Tls.Error));
            if (r.CertificateStatus.Length > 0) Kv(sb, L.T("Certificato"), r.CertificateStatus);
            if (r.ServerHeader.Length > 0) Kv(sb, "Server", r.ServerHeader);
            if (r.PoweredBy.Length > 0) Kv(sb, "X-Powered-By", r.PoweredBy);
            if (r.PhpEvidence.Length > 0) Kv(sb, L.T("Indizi di PHP"), r.PhpEvidence);
            if (r.PhpVersionRaw.Length > 0) Kv(sb, L.T("Versione PHP"), $"{r.PhpVersionRaw} ({L.T("fonte")}: {r.PhpVersionSource}; {Labels.VersionStatus(r.VersionStatus)}{(r.FixedRelease.Length > 0 ? $"; {L.T("correzione")}: {r.FixedRelease}" : "")})");
            if (r.BodyDeclaredVersions.Count > 0) Kv(sb, L.T("Versioni dichiarate nel corpo (non verificate)"), string.Join(", ", r.BodyDeclaredVersions));
            if (r.CacheHint.Length > 0) Kv(sb, L.T("Cache o intermediario"), r.CacheHint);
            if (r.Multipart != MultipartBarrier.NotTested) Kv(sb, L.T("Barriera multipart"), Labels.Multipart(r.Multipart) + (r.MultipartDetail.Length > 0 ? ": " + r.MultipartDetail : ""));
            if (r.UploadProgressFieldBlocked != null) Kv(sb, "PHP_SESSION_UPLOAD_PROGRESS", r.UploadProgressFieldBlocked.Value ? L.T("campo filtrato al perimetro") : L.T("campo non filtrato"));
            if (r.SizeLimit.Length > 0) Kv(sb, L.T("Limite di dimensione"), r.SizeLimit);
            if (r.Waf.Count > 0) Kv(sb, L.T("A monte"), string.Join("<br>", r.Waf.Select(f => $"<b>{E(Labels.WafCategory(f.Category))}</b>: {E(f.Name)} ({E(L.T("confidenza"))} {E(Labels.Confidence(f.Confidence))}) – {E(f.Evidence)}")), raw: true);
            Kv(sb, L.T("Durata"), L.F("{0:F0} ms", r.DurationMs) + (r.PhaseMs.Count > 0 ? " (" + r.PhaseSummary + ")" : ""));
            if (r.Error.Length > 0) Kv(sb, L.T("Errore"), r.Error);
            sb.Append("</table>");

            sb.Append("<table class=\"tests\"><thead><tr><th>").Append(E(L.T("Test"))).Append("</th><th>").Append(E(L.T("Esito"))).Append("</th><th>").Append(E(L.T("Dettaglio"))).Append("</th><th>").Append(E(L.T("Richiesta"))).Append("</th><th>").Append(E(L.T("Risposta"))).Append("</th></tr></thead><tbody>");
            foreach (var t in r.Tests)
                sb.Append("<tr><td>").Append(E(t.Name)).Append("<br><span class=\"muted mono\">").Append(E(t.Id)).Append("</span></td><td><span class=\"out ").Append(t.Outcome.ToString().ToLowerInvariant()).Append("\">").Append(E(Labels.Outcome(t.Outcome))).Append("</span></td><td>")
                  .Append(E(t.Detail)).Append("</td><td class=\"mono\">").Append(E(t.Request)).Append("</td><td class=\"mono\">").Append(E(t.Response)).Append("</td></tr>");
            sb.Append("</tbody></table>");

            var first = r.Requests.FirstOrDefault(q => q.HasResponse && q.Method == "GET");
            if (first != null)
            {
                sb.Append("<details class=\"hdr\"><summary>").Append(E(L.F("Intestazioni della risposta a {0} {1} ({2})", first.Method, first.Url, first.Summary))).Append("</summary><pre>");
                if (first.RequestHeaders != null) { foreach (var h in first.RequestHeaders) sb.Append("> ").Append(E(h.Key)).Append(": ").Append(E(h.Value)).Append('\n'); sb.Append('\n'); }
                foreach (var h in first.Headers) sb.Append(E(h.Key)).Append(": ").Append(E(h.Value)).Append('\n');
                sb.Append("</pre></details>");
            }
            sb.Append("</details>");
        }
        if (skipped > 0) sb.Append("<p class=\"note\">").Append(E(L.F("{0} bersagli non raggiungibili senza scheda di dettaglio (alive check e motivazione sono nella tabella e in results.csv).", skipped))).Append("</p>");
        sb.Append("</section>");

        // Metodo e limiti
        sb.Append("<section><h2>").Append(E(L.T("Metodo e limiti"))).Append("</h2><ul>");
        foreach (var line in MethodLines()) sb.Append("<li>").Append(E(line)).Append("</li>");
        sb.Append("</ul><h3>").Append(E(L.T("Riferimenti"))).Append("</h3><ul class=\"refs\">");
        foreach (var (name, url) in References) sb.Append("<li>").Append(E(name)).Append(": <a href=\"").Append(url).Append("\">").Append(url).Append("</a></li>");
        sb.Append("</ul></section>");

        if (!string.IsNullOrEmpty(extraSections)) sb.Append(extraSections);
        sb.Append("<footer>").Append(E(L.F("Generato da PHP Vuln Scanner v{0} il {1:dd/MM/yyyy HH:mm:ss}. Uso responsabile: scansionare solo sistemi propri o con autorizzazione scritta.", s.AppVersion, DateTime.Now))).Append("</footer>");
        sb.Append("</div><script>").Append(Js).Append("</script></body></html>");
        return sb.ToString();
    }

    public static IEnumerable<string> MethodLines() =>
    [
        L.T("Livello 1 (passivo): richieste GET sui percorsi configurati; la versione viene letta da X-Powered-By, dall'header Server, dalle pagine phpinfo esposte e dall'easter egg di PHP. Confronto con le prime versioni corrette: 8.2.35, 8.3.36, 8.4.27, 8.5.12."),
        L.T("Rami 5.4 … 8.1: nessuna release ufficiale; Debian, Ubuntu, RHEL, Plesk, cPanel e Sury correggono senza cambiare il numero. Il verdetto \"Probabilmente vulnerabile\" va confermato sull'host leggendo il changelog del pacchetto (php2shell-guard automatizza il controllo)."),
        L.T("Livello 2 (precondizioni e barriere): POST url-encoded e multipart minime confrontate con la GET; se il multipart è respinto, otto varianti di Content-Type verificano che il blocco non confronti la stringa esatta; il campo PHP_SESSION_UPLOAD_PROGRESS è inviato senza cookie, quindi PHP non scrive alcuna sessione; un multipart di dimensione configurabile rivela i limiti al perimetro (413). Nessuna richiesta porta PHP in esaurimento memoria."),
        L.T("Nessun test esterno dimostra la sfruttabilità: con versione non dichiarata il verdetto resta \"Non determinabile\" per scelta, perché un PHP corretto e uno vulnerabile rispondono allo stesso modo (cfr. issue #1 dello scanner Assetnote). La prova sta sull'host: php -v, data di build, changelog, riavvio dei worker."),
        L.T("WAF / CDN / reverse proxy / bilanciatore: firme su intestazioni, cookie, pagine di blocco e certificato TLS, più una richiesta con parametri dall'aspetto ostile ma inerti confrontata con quella normale e tre richieste ripetute per osservare differenze tra nodi. Ogni rilevazione riporta l'evidenza; la confidenza è una stima."),
        L.T("Quando risponde un WAF o un CDN al posto dell'origine, le intestazioni possono essere riscritte: l'assenza di X-Powered-By non prova che PHP manchi, e il blocco del multipart può valere solo per chi passa dal perimetro (l'origine resta esposta se raggiungibile direttamente)."),
        L.T("Alive check: ICMP, TCP (anche un RST prova che l'host è attivo) e UDP (solo una risposta o un ICMP port unreachable confermano l'host; il silenzio non significa spento). I bersagli senza conferma vengono saltati se l'opzione è attiva."),
        L.T("SAPI, sistema operativo e applicazione sono dedotti dai banner e dai corpi già scaricati, senza richieste in più; la priorità è un ordinamento di remediation derivato da verdetto, SAPI (mod_php = caso a rischio massimo secondo l'avviso PHP) e barriera, non un verdetto nuovo. L'applicazione riconosciuta rimanda alla pagina dell'inventario NCSC-NL, dove lo stato per prodotto viene aggiornato nel tempo."),
        L.T("Superficie PHP: un file .php inesistente rivela chi gestisce l'estensione (PHP-FPM \"File not found.\", php-cgi \"No input file specified.\", modulo PHP con X-Powered-By sulla 404) anche senza banner; i punti di ingresso comuni e i link .php dei corpi scaricati sono verificati con HEAD/GET e contano solo se rispondono in modo diverso dal file inesistente. Il livello 2 usa il miglior .php trovato quando i percorsi configurati non ne offrono uno."),
        L.T("Nomi scoperti: una scansione per IP raggiunge solo il vhost predefinito; CN e SAN del certificato e gli host delle Location rivelano i siti ospitati, e la seconda passata (Host e SNI = nome, TCP verso lo stesso IP) li raggiunge. I nomi sono validati come nomi DNS: i redirect malformati (host incollato al percorso) vengono scartati."),
        L.T("Cicli e consolidamento: a ogni ciclo l'elenco viene ripassato per intero; con il consolidamento per ogni bersaglio/porta/nome resta il risultato più informativo (versione dichiarata > non determinabile, raggiungibile > non raggiungibile, barriera osservata > non provata), a parità il più recente, e la storia dei verdetti resta nella scheda. L'ordine casuale e le pause tra le richieste servono a non assomigliare a un attacco agli occhi di un IDS/IPS."),
        L.T("CVE-2026-115560 (advisory PHP del 23/10/2026) non ha una release corretta: «Corretto per versione» si riferisce a CVE-2026-109618 e CVE-2026-109619. L'esposizione alla 115560 richiede session.upload_progress attivo e un cambio a runtime di session.serialize_handler, invisibile dall'esterno: si verifica sull'host (php-fpm -i, grep del codice). La sola osservazione possibile da fuori è una pagina phpinfo esposta, da cui lo scanner legge session.upload_progress.enabled e session.serialize_handler."),
        L.T("PHP \"Forse\": nessuna prova di PHP (banner, cookie PHPSESSID, versione) ma indizi passivi pesati (intestazioni, cookie di applicazioni PHP, percorsi, pannelli); è un inventario da verificare sull'host, non un verdetto, e il servizio resta \"PHP non rilevato\". Indice di loquacità 0-5: quanto l'host rivela di sé senza che gli venga chiesto (versioni nei banner, phpinfo, directory listing, pagine di stato e di debug, file di Composer, nomi interni nel certificato); un indice alto è un argomento organizzativo anche senza vulnerabilità."),
        L.T("Nomi con lo stesso esito: un nome scoperto che risponde con contenuto diverso dal vhost predefinito ma con lo stesso verdetto, versione, SAPI, applicazione, barriera, WAF e priorità non ha una riga propria (il nome sta nella colonna Nomi del titolare); l'osservazione completa resta in results.jsonl. Un nome che rivela qualcosa di diverso ha sempre la sua riga."),
        L.T("Lo scanner non contiene né esegue codice di sfruttamento e non modifica lo stato dei bersagli. Il User-Agent dichiara lo strumento. Scansionare solo sistemi propri o con autorizzazione scritta."),
    ];

    /// <summary>Colonna Nome della tabella: il nome della riga, oppure i nomi ripiegati sulla riga per IP (stesso contenuto, stesso esito).</summary>
    private static string NameColumn(ScanResult r)
    {
        if (r.DisplayName.Length > 0) return r.DisplayName;
        var parts = new List<string>();
        if (r.SameContentNames.Count > 0) parts.Add(string.Join(", ", r.SameContentNames) + " " + L.T("(= vhost predefinito)"));
        if (r.SameOutcomeNames.Count > 0) parts.Add(string.Join(", ", r.SameOutcomeNames) + " " + L.T("(= stesso esito)"));
        return string.Join("; ", parts);
    }

    public static readonly (string Name, string Url)[] References =
    [
        ("PHP, GHSA-w8hw-w9fx-j79w (CVE-2026-109618)", "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w"),
        ("PHP, GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)", "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"),
        ("CERT-EU Security Advisory 2026-018", "https://cert.europa.eu/publications/security-advisories/2026-018"),
        ("Datadog Security Labs, PHP2Shell", "https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/"),
        ("Wiz, PHP2Shell", "https://www.wiz.io/blog/php2shell-php-rce"),
        ("Assetnote php2shell-scanner, issue #1 (falso positivo su versioni corrette)", "https://github.com/assetnote/php2shell-scanner/issues/1"),
        ("Blue-B/php2shell-guard (verifica sull'host, test delle regole al proxy)", "https://github.com/Blue-B/php2shell-guard"),
        ("PHP2Shell: Detection Opportunities", "https://gist.github.com/Blevene/472692937d05145d29d17dc3c6edc2a0"),
        ("NCSC-NL, informazioni operative e inventario dei prodotti con dipendenza PHP", "https://github.com/NCSC-NL/php2shell"),
    ];

    private static string StatusLabel(ScanStatus s) => s switch
    {
        ScanStatus.Completed => L.T("Completata"),
        ScanStatus.Stopped => L.T("Interrotta"),
        ScanStatus.Error => L.T("Errore"),
        _ => L.T("In corso"),
    };

    private static string AliveDesc(AliveConfig a)
    {
        var parts = new List<string>();
        if (a.Icmp) parts.Add("ICMP");
        if (a.TcpPorts.Count > 0) parts.Add("TCP " + string.Join(",", a.TcpPorts));
        if (a.UdpPorts.Count > 0) parts.Add("UDP " + string.Join(",", a.UdpPorts));
        return string.Join(" + ", parts) + L.F(", timeout {0} ms", a.TimeoutMs) + (a.SkipIfNotAlive ? L.T(", salta i non attivi") : "");
    }

    private static void Kv(StringBuilder sb, string k, string v, bool raw = false) =>
        sb.Append("<tr><th>").Append(E(k)).Append("</th><td>").Append(raw ? v : E(v)).Append("</td></tr>");

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    private const string Css = """
:root{--bg:#fff;--fg:#1f2937;--muted:#6b7280;--line:#e5e7eb;--soft:#f6f7f9;--accent:#1d4ed8;--ok:#15803d;--ok-soft:#ecfdf3;--warn:#b45309;--warn-soft:#fff8e6;--bad:#b91c1c;--bad-soft:#fef2f2;--code:#f3f4f6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#111418;--fg:#e5e7eb;--muted:#9aa3af;--line:#2a2f37;--soft:#181c22;--accent:#7aa2ff;--ok:#4ade80;--ok-soft:#10241a;--warn:#fbbf24;--warn-soft:#2a2210;--bad:#f87171;--bad-soft:#2a1416;--code:#1d2229}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1400px;margin:0 auto;padding:24px 16px 60px}h1{font-size:24px;margin:0 0 6px}h2{font-size:19px;margin:36px 0 10px;border-top:1px solid var(--line);padding-top:10px}h3{font-size:15px;margin:18px 0 6px}
.lead{color:var(--muted);max-width:900px;margin:0 0 14px}.note{color:var(--muted);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:5px 8px;text-align:left;vertical-align:top}th{background:var(--soft);font-weight:600}
table.kv{width:auto;margin:6px 0 10px}table.kv th{width:180px;white-space:nowrap}
.kpis{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 12px}.kpi{border:1px solid var(--line);border-radius:8px;padding:8px 14px;background:var(--bg);color:var(--fg);cursor:pointer;min-width:120px;text-align:left;font:inherit}
.kpi .n{display:block;font-size:22px;font-weight:600}.kpi .l{display:block;font-size:12px;color:var(--muted)}.kpi.active{outline:2px solid var(--accent)}
.kpi.bad .n{color:var(--bad)}.kpi.warn .n{color:var(--warn)}.kpi.ok .n{color:var(--ok)}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;white-space:nowrap}.badge.bad{background:var(--bad-soft);color:var(--bad)}.badge.warn{background:var(--warn-soft);color:var(--warn)}.badge.ok{background:var(--ok-soft);color:var(--ok)}.badge.muted{background:var(--soft);color:var(--muted)}
#q{width:100%;padding:7px 10px;margin:8px 0;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit}
details.card{border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:8px 0;background:var(--bg)}details.card>summary{cursor:pointer;font-size:14px}details.card[open]>summary{margin-bottom:8px}
table.tests th:nth-child(1){width:15%}table.tests th:nth-child(2){width:8%}table.tests th:nth-child(3){width:45%}table.tests th:nth-child(4){width:14%}table.tests th:nth-child(5){width:18%}
details.hdr{margin:6px 0}details.names{margin:8px 0;font-size:13px}details.names>summary{cursor:pointer}pre{background:var(--code);padding:8px 10px;border-radius:6px;overflow:auto;font-size:12px}
.mono{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px}.muted{color:var(--muted)}
.out{font-weight:600}.out.pass{color:var(--ok)}.out.warn{color:var(--warn)}.out.fail{color:var(--bad)}.out.error{color:var(--bad)}.out.info,.out.skipped{color:var(--muted)}
.hidden{display:none}footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:10px}ul.refs{font-size:13px}a{color:var(--accent)}
@media print{.kpis button{border:1px solid #999}details.card{break-inside:avoid}#q{display:none}details.card{display:block}details.card>summary{list-style:none}}
""";

    private const string Js = """
(function(){var f='',q='',al=false;function apply(){var rows=document.querySelectorAll('tr.row,details.card');rows.forEach(function(r){var ok=(!f||r.dataset.verdict===f)&&(!al||r.dataset.alive==='1')&&(!q||r.textContent.toLowerCase().indexOf(q)>=0);r.classList.toggle('hidden',!ok);});document.querySelectorAll('.kpi').forEach(function(b){b.classList.toggle('active',b.dataset.alive?al:(b.dataset.filter===f&&f!==''));});}
document.querySelectorAll('.kpi').forEach(function(b){b.addEventListener('click',function(){if(b.dataset.alive){al=!al;}else{f=(f===b.dataset.filter)?'':b.dataset.filter;}apply();});});
var s=document.getElementById('q');if(s){s.addEventListener('input',function(){q=s.value.toLowerCase();apply();});}
document.querySelectorAll('tr.row a').forEach(function(a){a.addEventListener('click',function(){var d=document.querySelector(a.getAttribute('href'));if(d){d.open=true;}});});apply();})();
""";
}
