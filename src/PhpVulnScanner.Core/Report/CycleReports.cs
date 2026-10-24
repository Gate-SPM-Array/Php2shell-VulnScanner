using System.Globalization;
using System.Net;
using System.Text;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Output;

namespace PhpVulnScanner.Core.Report;

/// <summary>
/// Vista per ciclo di una sessione consolidata: results.jsonl conserva ogni osservazione di ogni ciclo, qui le si
/// raggruppano in sessioni per ciclo (per report o CSV separati) e si produce il frammento HTML "Per ciclo" che il
/// report completo può incorporare: KPI di ogni ciclo e, per ogni servizio con HTTP in almeno un ciclo, una riga per ciclo.
/// </summary>
public static class CycleReports
{
    private static CultureInfo C => L.Culture;

    /// <summary>
    /// Divide le osservazioni per ciclo. Ogni sessione copia i campi di intestazione della consolidata, ha Cycle = i,
    /// Consolidated = false, risultati ordinati (ultima osservazione per chiave entro il ciclo), HostsAlive/HostsHttp del
    /// ciclo, StartLocal/EndLocal = prima e ultima osservazione del ciclo.
    /// </summary>
    public static List<(int Cycle, ScanSession Session)> SplitByCycle(ScanSession consolidated, IEnumerable<ScanResult> observations)
    {
        var byCycle = new SortedDictionary<int, Dictionary<string, ScanResult>>();
        foreach (var r in observations)
        {
            if (!byCycle.TryGetValue(r.Cycle, out var map)) byCycle[r.Cycle] = map = new Dictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
            map[r.Key] = r;   // l'ultima osservazione della chiave nel ciclo è lo stato finale di quel ciclo
        }
        var list = new List<(int, ScanSession)>();
        foreach (var kv in byCycle)
        {
            var rows = kv.Value.Values.OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
            var s = new ScanSession
            {
                AppVersion = consolidated.AppVersion, Machine = consolidated.Machine, OsDescription = consolidated.OsDescription,
                Status = consolidated.Status, Folder = consolidated.Folder, TargetCount = consolidated.TargetCount, PortCount = consolidated.PortCount,
                Ports = [.. consolidated.Ports], Paths = [.. consolidated.Paths], ParseErrors = [.. consolidated.ParseErrors], TargetsSummary = consolidated.TargetsSummary,
                Cycle = kv.Key, Cycles = consolidated.Cycles, Consolidated = false, HostsTotal = consolidated.HostsTotal, DataVersion = consolidated.DataVersion,
                Config = consolidated.Config, Results = rows,
                HostsAlive = rows.Where(HostLists.IsAlive).Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                HostsHttp = rows.Where(r => r.HttpReachable).Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            };
            if (rows.Count > 0)
            {
                s.StartLocal = rows.Min(r => r.StartedLocal);
                s.EndLocal = rows.Max(r => r.StartedLocal.AddMilliseconds(r.DurationMs));
            }
            else { s.StartLocal = consolidated.StartLocal; s.EndLocal = consolidated.EndLocal; }
            list.Add((kv.Key, s));
        }
        return list;
    }

    /// <summary>Frammento HTML "Per ciclo" (sezione completa, senza &lt;html&gt;): usa le classi CSS del report completo.</summary>
    public static string BuildPerCycleSection(ScanSession consolidated, IReadOnlyList<(int Cycle, ScanSession Session)> cycles)
    {
        var sb = new StringBuilder(16 * 1024);
        sb.Append("<section class=\"cycles\"><h2>").Append(E(L.T("Per ciclo"))).Append("</h2>");
        sb.Append("<p class=\"note\">").Append(E(L.F("{0} cicli; per ogni ciclo i suoi numeri, poi l'andamento di ogni servizio con HTTP in almeno un ciclo.", cycles.Count))).Append("</p>");

        // KPI per ciclo
        var verdicts = new[] { Verdict.VulnerableByVersion, Verdict.LikelyVulnerable, Verdict.MitigatedAtEdge, Verdict.Undetermined, Verdict.FixedByVersion, Verdict.NoPhpDetected, Verdict.NotReachable };
        sb.Append("<table class=\"res\"><thead><tr>");
        foreach (var h in new[] { L.T("Ciclo"), L.T("Avvio"), L.T("Durata"), L.T("Righe"), L.T("Host attivi"), L.T("Host con HTTP") }) sb.Append("<th>").Append(E(h)).Append("</th>");
        foreach (var v in verdicts) sb.Append("<th>").Append(E(Labels.Verdict(v))).Append("</th>");
        sb.Append("</tr></thead><tbody>");
        foreach (var (cycle, s) in cycles)
        {
            double sec = s.EndLocal.HasValue ? Math.Max(0, (s.EndLocal.Value - s.StartLocal).TotalSeconds) : 0;
            sb.Append("<tr><td>").Append(cycle).Append("</td><td class=\"mono\">").Append(E(s.StartLocal.ToString("dd/MM/yyyy HH:mm:ss", C))).Append("</td><td>").Append(E(ScanEstimator.Duration(sec))).Append("</td><td>")
              .Append(s.Results.Count).Append("</td><td>").Append(s.HostsAlive).Append("</td><td>").Append(s.HostsHttp).Append("</td>");
            foreach (var v in verdicts) sb.Append("<td>").Append(s.Results.Count(r => r.Verdict == v)).Append("</td>");
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table>");

        // servizi: una riga per ciclo
        var perKey = new Dictionary<string, SortedDictionary<int, ScanResult>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (cycle, s) in cycles)
            foreach (var r in s.Results)
            {
                if (!perKey.TryGetValue(r.Key, out var m)) perKey[r.Key] = m = new SortedDictionary<int, ScanResult>();
                m[cycle] = r;
            }
        var services = perKey.Where(kv => kv.Value.Values.Any(r => r.HttpReachable))
            .Select(kv => (Key: kv.Key, Rows: kv.Value, First: kv.Value.Values.First()))
            .OrderBy(x => x.First.SortKey, StringComparer.Ordinal).ThenBy(x => x.First.Port).ToList();
        sb.Append("<h3>").Append(E(L.F("Servizi con HTTP in almeno un ciclo: {0}", services.Count))).Append("</h3>");
        foreach (var svc in services)
        {
            var rows = svc.Rows.Values.ToList();
            bool changed = rows.Select(r => r.Verdict).Distinct().Count() > 1;
            var last = rows[^1];
            sb.Append("<details class=\"card\"><summary><span class=\"badge ").Append(Labels.VerdictClass(last.Verdict)).Append("\">").Append(E(Labels.Verdict(last.Verdict))).Append("</span> <b>")
              .Append(E(svc.First.Display)).Append(':').Append(svc.First.Port).Append("</b> <span class=\"muted\">").Append(E(L.F("{0} cicli", rows.Count)))
              .Append(changed ? " <span class=\"badge warn\">Δ</span>" : "").Append("</span></summary>");
            sb.Append("<table class=\"res\"><thead><tr>");
            foreach (var h in new[] { L.T("Ciclo"), L.T("Avvio"), L.T("Verdetto"), L.T("Versione"), L.T("Barriera"), L.T("WAF"), L.T("Durata") }) sb.Append("<th>").Append(E(h)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var kv in svc.Rows)
            {
                var r = kv.Value;
                sb.Append("<tr><td>").Append(kv.Key).Append("</td><td class=\"mono\">").Append(E(Stamp.Local(r.StartedLocal))).Append("</td><td><span class=\"badge ").Append(Labels.VerdictClass(r.Verdict)).Append("\">").Append(E(Labels.Verdict(r.Verdict))).Append("</span></td><td>")
                  .Append(E(r.PhpVersionRaw.Length > 0 ? r.PhpVersionRaw : "–")).Append("</td><td>").Append(E(Labels.Multipart(r.Multipart))).Append(r.VariantsBlocked >= 0 ? $" ({r.VariantsBlocked}/{r.VariantsTotal})" : "").Append("</td><td>")
                  .Append(E(r.WafSummary.Length > 0 ? r.WafSummary : "–")).Append("</td><td>").Append(E(L.F("{0:F0} ms", r.DurationMs))).Append("</td></tr>");
            }
            sb.Append("</tbody></table></details>");
        }
        sb.Append("</section>");
        return sb.ToString();
    }

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
}
