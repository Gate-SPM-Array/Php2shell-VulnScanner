using System.Net;
using System.Text;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Inventory;

namespace PhpVulnScanner.Core.Report;

/// <summary>Sezione "Inventario" del report compatto: contatori della riconciliazione e le tre tabelle delle discordanze. Tutto il testo è codificato HTML.</summary>
public static class InventoryReportSection
{
    /// <summary>Restituisce la <c>&lt;section&gt;</c> "Inventario" da inserire nel report compatto; "" quando <paramref name="rep"/> è null.</summary>
    public static string InventorySection(ScanSession s, InventoryReport? rep)
    {
        if (rep == null) return "";
        var sb = new StringBuilder(8 * 1024);
        sb.Append("<section class=\"inventory\"><h2>").Append(E(L.T("Inventario"))).Append("</h2>");
        if (rep.InventoryPath.Length > 0)
            sb.Append("<p class=\"note\">").Append(E(L.F("File: {0}", rep.InventoryPath))).Append("</p>");

        // ---- contatori ----
        sb.Append("<div class=\"kpis\">");
        Kpi(sb, rep.Entries, L.T("Voci in inventario"), "muted");
        Kpi(sb, rep.Matched, L.T("Servizi riconciliati"), "ok");
        Kpi(sb, rep.DeclaredNotObserved.Count, L.T("Dichiarati ma non osservati"), rep.DeclaredNotObserved.Count > 0 ? "warn" : "muted");
        Kpi(sb, rep.ObservedNotInventoried.Count, L.T("Osservati ma non inventariati"), rep.ObservedNotInventoried.Count > 0 ? "warn" : "muted");
        Kpi(sb, rep.VersionMismatches.Count, L.T("Versioni diverse"), rep.VersionMismatches.Count > 0 ? "bad" : "muted");
        sb.Append("</div>");
        if (rep.SkippedRows > 0)
            sb.Append("<p class=\"note\">").Append(E(L.F("{0} righe dell'inventario scartate alla lettura (bersaglio mancante o non valido).", rep.SkippedRows))).Append("</p>");

        // ---- versioni diverse ----
        sb.Append("<h3>").Append(E(L.T("Versioni diverse"))).Append("</h3>");
        if (rep.VersionMismatches.Count == 0) sb.Append("<p class=\"note\">").Append(E(L.T("Nessuna: ogni versione dichiarata coincide con quella osservata."))).Append("</p>");
        else
        {
            Table(sb, [L.T("Bersaglio"), L.T("Porta"), L.T("Nomi"), L.T("Dichiarata"), L.T("Osservata"), L.T("Referente")],
                rep.VersionMismatches.OrderBy(m => Targets.TargetParser.SortKey(m.Service.Ip), StringComparer.Ordinal).ThenBy(m => m.Service.Port)
                   .Select(m => new[] { m.Service.Ip, m.Service.Port.ToString(), Names(m.Service.Names), m.Declared, m.Observed, Dash(m.Service.Owner) }));
        }

        // ---- PHP dichiarato ma non osservato ----
        if (rep.DeclaredPhpNotObserved.Count > 0)
        {
            sb.Append("<h3>").Append(E(L.T("PHP dichiarato ma non osservato"))).Append("</h3>");
            sb.Append("<p class=\"note\">").Append(E(L.T("L'inventario dichiara una versione di PHP ma il servizio non mostra PHP: versione da verificare sull'host, oppure PHP non più in uso."))).Append("</p>");
            Table(sb, [L.T("Bersaglio"), L.T("Porta"), L.T("Nomi"), L.T("Verdetto"), L.T("Referente")],
                rep.DeclaredPhpNotObserved.OrderBy(x => Targets.TargetParser.SortKey(x.Ip), StringComparer.Ordinal).ThenBy(x => x.Port)
                   .Select(x => new[] { x.Ip, x.Port.ToString(), Names(x.Names), VerdictLabel(x.Verdict), Dash(x.Owner) }));
        }

        // ---- dichiarati ma non osservati ----
        sb.Append("<h3>").Append(E(L.T("Dichiarati ma non osservati"))).Append("</h3>");
        if (rep.DeclaredNotObserved.Count == 0) sb.Append("<p class=\"note\">").Append(E(L.T("Nessuna voce: ogni bersaglio dell'inventario ha risposto HTTP."))).Append("</p>");
        else
        {
            sb.Append("<p class=\"note\">").Append(E(L.T("Voci dell'inventario il cui bersaglio non ha mai risposto HTTP in questa sessione: spento, fuori dall'elenco scansionato, filtrato o dismesso."))).Append("</p>");
            Table(sb, [L.T("Bersaglio"), L.T("Versione dichiarata"), L.T("Referente"), L.T("Ambiente"), L.T("Applicazione")],
                rep.DeclaredNotObserved.OrderBy(e => Targets.TargetParser.SortKey(e.Target), StringComparer.Ordinal)
                   .Select(e => new[] { e.Target, Dash(e.PhpVersion), Dash(e.Owner), Dash(e.Environment), Dash(e.Application) }));
        }

        // ---- osservati ma non inventariati ----
        sb.Append("<h3>").Append(E(L.T("Osservati ma non inventariati"))).Append("</h3>");
        if (rep.ObservedNotInventoried.Count == 0) sb.Append("<p class=\"note\">").Append(E(L.T("Nessuno: ogni servizio HTTP osservato è in inventario."))).Append("</p>");
        else
        {
            sb.Append("<p class=\"note\">").Append(E(L.T("Servizi HTTP il cui indirizzo e i cui nomi non compaiono nell'inventario: da censire o da spegnere."))).Append("</p>");
            Table(sb, [L.T("Bersaglio"), L.T("Porta"), L.T("Nomi"), L.T("Verdetto")],
                rep.ObservedNotInventoried.OrderBy(x => Targets.TargetParser.SortKey(x.Ip), StringComparer.Ordinal).ThenBy(x => x.Port)
                   .Select(x => new[] { x.Ip, x.Port.ToString(), Names(x.Names), VerdictLabel(x.Verdict) }));
        }

        sb.Append("<p class=\"note\">").Append(E(L.T("Il referente dell'inventario è riportato anche accanto a ogni servizio nelle tabelle del report e nella colonna Referente della tabella dei risultati."))).Append("</p>");
        sb.Append("</section>");
        return sb.ToString();
    }

    private static void Kpi(StringBuilder sb, int n, string label, string cls) =>
        sb.Append("<div class=\"kpi ").Append(cls).Append("\"><span class=\"n\">").Append(n).Append("</span><span class=\"l\">").Append(E(label)).Append("</span></div>");

    private static void Table(StringBuilder sb, string[] headers, IEnumerable<string[]> rows)
    {
        sb.Append("<table class=\"att\"><thead><tr>");
        foreach (var h in headers) sb.Append("<th>").Append(E(h)).Append("</th>");
        sb.Append("</tr></thead><tbody>");
        foreach (var row in rows)
        {
            sb.Append("<tr>");
            foreach (var c in row) sb.Append("<td>").Append(E(c)).Append("</td>");
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table>");
    }

    private static string Names(List<string> names) => names.Count == 0 ? "–" : string.Join(", ", names);
    private static string Dash(string s) => string.IsNullOrWhiteSpace(s) ? "–" : s;
    private static string VerdictLabel(string key) => Enum.TryParse<Verdict>(key, out var v) ? Labels.Verdict(v) : key;
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
}
