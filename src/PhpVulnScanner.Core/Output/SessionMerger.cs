using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Report;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Core.Output;

/// <summary>Una sessione da fondere: cartella, intestazione (session.json) e tutte le osservazioni (results.jsonl, oppure results.json).</summary>
public sealed record MergeInput(string Folder, ScanSession Session, List<ScanResult> Observations)
{
    /// <summary>Etichetta della sessione nei confronti e nella storia: "2026-10-23 22:47 v1.2".</summary>
    public string Label => SessionMerger.LabelOf(Session);
}

/// <summary>
/// Fusione di più sessioni (anche di versioni diverse del programma) in una sessione consolidata: per ogni servizio vince
/// il risultato più informativo (stessa regola dei cicli, <see cref="ResultMerger"/>), e la storia riporta data, ora e
/// versione della sessione di ogni osservazione. Non scrive file: il chiamante salva la sessione con SessionWriter/SessionFiles.
/// </summary>
public static class SessionMerger
{
    public static string LabelOf(ScanSession s) => $"{s.StartLocal:yyyy-MM-dd HH:mm} v{s.AppVersion}";

    /// <summary>
    /// Legge una cartella di sessione: session.json (o results.json) per l'intestazione, results.jsonl per le osservazioni
    /// (results.json se il jsonl manca, versioni precedenti alla 1.3). I campi assenti nei file vecchi restano al valore predefinito.
    /// </summary>
    public static MergeInput Load(string folder)
    {
        if (string.IsNullOrWhiteSpace(folder) || !Directory.Exists(folder))
            throw new ArgumentException(L.F("Cartella di sessione non trovata: {0}", folder ?? ""));
        string sessionPath = Path.Combine(folder, SessionFiles.SessionJson);
        string resultsPath = Path.Combine(folder, SessionFiles.ResultsJson);
        string jsonlPath = Path.Combine(folder, SessionFiles.ResultsJsonl);
        bool hasSession = File.Exists(sessionPath), hasResults = File.Exists(resultsPath), hasJsonl = File.Exists(jsonlPath);
        if (!hasSession && !hasResults)
            throw new ArgumentException(L.F("La cartella {0} non contiene i file di sessione (session.json o results.json).", folder));

        ScanSession? header = null;
        if (hasSession) header = Read(sessionPath);
        ScanSession? full = null;
        if (header == null || (!hasJsonl && hasResults)) full = hasResults ? Read(resultsPath) : null;
        header ??= full ?? throw new ArgumentException(L.F("La cartella {0} non contiene i file di sessione (session.json o results.json).", folder));

        List<ScanResult> observations;
        if (hasJsonl) observations = SessionFiles.ReadJsonl(jsonlPath);
        else observations = full?.Results ?? header.Results ?? [];
        if (observations.Count == 0 && full == null && hasResults) observations = Read(resultsPath)?.Results ?? [];
        foreach (var r in observations) Normalize(r);
        header.Results = [];   // le osservazioni stanno nel record, l'intestazione resta leggera
        if (string.IsNullOrWhiteSpace(header.AppVersion)) header.AppVersion = "?";
        if (string.IsNullOrWhiteSpace(header.Folder)) header.Folder = folder;
        return new MergeInput(folder, header, observations);
    }

    private static ScanSession? Read(string path)
    {
        try { return JsonSerializer.Deserialize<ScanSession>(File.ReadAllText(path), ScanConfig.JsonOptions); }
        catch (JsonException ex) { throw new ArgumentException(L.F("File di sessione non valido {0}: {1}", path, ex.Message)); }
    }

    /// <summary>File di versioni precedenti: liste nulle e valori mancanti riportati ai predefiniti.</summary>
    private static void Normalize(ScanResult r)
    {
        r.ResolvedIps ??= [];
        r.PhaseMs ??= [];
        r.Waf ??= [];
        r.Tests ??= [];
        r.Requests ??= [];
        r.DiscoveredNames ??= [];
        r.PhpSurface ??= [];
        r.History ??= [];
        r.Technologies ??= [];
        r.SameContentNames ??= [];
        r.Libraries ??= [];
        r.Components ??= [];
        r.Exposures ??= [];
        r.TechnologyStatuses ??= [];
        if (r.Cycle <= 0) r.Cycle = 1;
    }

    private static readonly System.Reflection.MethodInfo MemberwiseCloneMethod =
        typeof(object).GetMethod("MemberwiseClone", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!;

    /// <summary>Copia superficiale di un risultato (le liste non modificate restano condivise).</summary>
    public static ScanResult ShallowClone(ScanResult r) => (ScanResult)MemberwiseCloneMethod.Invoke(r, null)!;

    /// <summary>Riga di storia con etichetta di sessione: "23/10 22.47 v1.2: Non raggiungibile (Nessuna risposta)". Il separatore delle ore è un punto perché <see cref="ResultMerger.VerdictChanged"/> legge il verdetto dopo il primo ":".</summary>
    public static string HistoryLine(ScanResult r, ScanSession session)
    {
        string v = Labels.Verdict(r.Verdict);
        if (r.PhpVersionRaw.Length > 0) v += $" ({r.PhpVersionRaw})";
        else if (!r.HttpReachable && r.Alive != Net.AliveState.NotTested) v += $" ({Labels.Alive(r.Alive)})";
        return $"{r.StartedLocal.ToString("dd/MM HH.mm", CultureInfo.InvariantCulture)} v{session.AppVersion}: {v}";
    }

    /// <summary>Sovrapposizione degli insiemi di host (indirizzi) tra le sessioni.</summary>
    public static MergeReport Analyse(IReadOnlyList<MergeInput> inputs)
    {
        var rep = new MergeReport();
        foreach (var inp in inputs.OrderBy(i => i.Session.StartLocal))
        {
            string label = inp.Label;
            var hosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var alive = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var http = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in inp.Observations)
            {
                string h = HostLists.HostIp(r);
                hosts.Add(h);
                if (HostLists.IsAlive(r)) alive.Add(h);
                if (r.HttpReachable) http.Add(h);
            }
            rep.Labels.Add(label);
            rep.HostsByLabel[label] = hosts;
            rep.AliveByLabel[label] = alive;
            rep.HttpByLabel[label] = http;
        }
        foreach (var set in rep.HostsByLabel.Values) rep.Union.UnionWith(set);
        bool first = true;
        foreach (var set in rep.HostsByLabel.Values)
        {
            if (first) { rep.Intersection.UnionWith(set); first = false; }
            else rep.Intersection.IntersectWith(set);
        }
        foreach (var label in rep.Labels)
        {
            var only = new HashSet<string>(rep.HostsByLabel[label], StringComparer.OrdinalIgnoreCase);
            foreach (var other in rep.Labels) if (other != label) only.ExceptWith(rep.HostsByLabel[other]);
            rep.OnlyIn[label] = only.OrderBy(TargetParser.SortKey, StringComparer.Ordinal).ToList();
        }
        return rep;
    }

    /// <summary>
    /// Fonde le sessioni in ordine cronologico (StartLocal): per ogni chiave vince il più informativo, la storia porta
    /// l'etichetta di sessione di ogni osservazione. Intestazione: unione dei bersagli, Cycles = numero di sessioni,
    /// Consolidated, Completed, conteggi host ricalcolati, Config e DataVersion dalla sessione più recente.
    /// </summary>
    public static ScanSession Merge(IReadOnlyList<MergeInput> inputs, string outFolder)
    {
        if (inputs.Count == 0) throw new ArgumentException(L.T("Nessuna sessione da fondere."));
        var ordered = inputs.OrderBy(i => i.Session.StartLocal).ToList();
        var byKey = new Dictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
        int sessionIndex = 0;
        foreach (var inp in ordered)
        {
            sessionIndex++;
            foreach (var obs in inp.Observations.OrderBy(r => r.StartedLocal))
            {
                // copia superficiale: la riga fusa riceve ciclo, storia e nomi uniti senza alterare l'osservazione originale (che serve ancora al confronto)
                var r = ShallowClone(obs);
                string line = HistoryLine(r, inp.Session);
                r.Cycle = sessionIndex;                       // nella sessione fusa il "ciclo" è la sessione di origine
                r.DiscoveredNames = [.. r.DiscoveredNames];

                if (!byKey.TryGetValue(r.Key, out var cur))
                {
                    r.History = [line];
                    byKey[r.Key] = r;
                    continue;
                }
                var w = ResultMerger.Merge(cur, r);
                if (w.History.Count > 0) w.History[^1] = line;
                // la stessa osservazione riproposta (jsonl di una sessione consolidata ripete il vincente): niente righe doppie
                for (int i = w.History.Count - 1; i > 0; i--) if (w.History[i] == w.History[i - 1]) w.History.RemoveAt(i);
                byKey[r.Key] = w;
            }
        }
        var results = byKey.Values.OrderBy(r => r.SortKey, StringComparer.Ordinal).ThenBy(r => r.Port).ToList();
        var newest = ordered[^1].Session;

        var targets = new List<string>();
        foreach (var inp in ordered)
            foreach (var t in inp.Session.TargetsSummary.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                if (!targets.Contains(t, StringComparer.OrdinalIgnoreCase)) targets.Add(t);
        var ports = ordered.SelectMany(i => i.Session.Ports).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var paths = ordered.SelectMany(i => i.Session.Paths).Distinct(StringComparer.Ordinal).ToList();
        var hosts = results.Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        var merged = new ScanSession
        {
            StartLocal = ordered.Min(i => i.Session.StartLocal),
            EndLocal = ordered.Max(i => i.Session.EndLocal ?? i.Session.StartLocal),
            Status = ScanStatus.Completed,
            Folder = outFolder,
            TargetCount = Math.Max(hosts.Count, ordered.Max(i => i.Session.TargetCount)),
            PortCount = ports.Count,
            Ports = ports,
            Paths = paths,
            ParseErrors = ordered.Select(i => L.F("fusione di {0} ({1} osservazioni)", i.Label, i.Observations.Count)).ToList(),
            TargetsSummary = string.Join(", ", targets),
            Cycle = ordered.Count,
            Cycles = ordered.Count,
            Consolidated = true,
            HostsTotal = hosts.Count,
            HostsAlive = results.Where(HostLists.IsAlive).Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            HostsHttp = results.Where(r => r.HttpReachable).Select(HostLists.HostIp).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            DataVersion = newest.DataVersion,
            Config = newest.Config,
            Results = results,
        };
        return merged;
    }
}

/// <summary>Sovrapposizione dei bersagli tra le sessioni e differenze tra le osservazioni, per decidere e documentare la fusione.</summary>
public sealed class MergeReport
{
    /// <summary>Etichette in ordine cronologico ("2026-10-23 22:47 v1.2").</summary>
    public List<string> Labels { get; } = [];
    public Dictionary<string, HashSet<string>> HostsByLabel { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, HashSet<string>> AliveByLabel { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, HashSet<string>> HttpByLabel { get; } = new(StringComparer.Ordinal);
    public HashSet<string> Union { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Intersection { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Host presenti solo in quella sessione, ordinati.</summary>
    public Dictionary<string, List<string>> OnlyIn { get; } = new(StringComparer.Ordinal);

    /// <summary>Riepilogo testuale della sovrapposizione, una riga per sessione più unione e intersezione.</summary>
    public string Summary()
    {
        var sb = new StringBuilder();
        foreach (var l in Labels) sb.AppendLine(L.F("{0}: {1} host, {2} attivi, {3} con HTTP, {4} solo in questa sessione", l, HostsByLabel[l].Count, AliveByLabel[l].Count, HttpByLabel[l].Count, OnlyIn[l].Count));
        sb.AppendLine(L.F("Unione {0} host, intersezione {1} host", Union.Count, Intersection.Count));
        return sb.ToString();
    }

    /// <summary>
    /// Frammento HTML con le differenze: host attivi solo in alcune sessioni, servizi con verdetto diverso tra sessioni,
    /// informazioni (versione PHP, applicazione, nomi) presenti in una sessione e assenti in un'altra.
    /// </summary>
    public string DifferencesHtml(IReadOnlyList<MergeInput> inputs, ScanSession merged)
    {
        var ordered = inputs.OrderBy(i => i.Session.StartLocal).ToList();
        var labels = ordered.Select(i => i.Label).ToList();
        // rappresentante di ogni servizio in ogni sessione: il più informativo, a parità il più recente
        var best = new List<Dictionary<string, ScanResult>>();
        foreach (var inp in ordered)
        {
            var d = new Dictionary<string, ScanResult>(StringComparer.OrdinalIgnoreCase);
            foreach (var r in inp.Observations.OrderBy(r => r.StartedLocal))
                if (!d.TryGetValue(r.Key, out var cur) || ResultMerger.Score(r) >= ResultMerger.Score(cur)) d[r.Key] = r;
            best.Add(d);
        }

        var sb = new StringBuilder(8 * 1024);
        sb.Append("<section class=\"merge\"><h2>").Append(E(L.T("Differenze tra le sessioni fuse"))).Append("</h2>");
        sb.Append("<p class=\"note\">").Append(E(L.F("{0} sessioni, {1} servizi nella sessione fusa, {2} host nell'unione e {3} in tutte le sessioni.", ordered.Count, merged.Results.Count, Union.Count, Intersection.Count))).Append("</p>");
        sb.Append("<table class=\"kv\">");
        foreach (var l in labels)
            sb.Append("<tr><th>").Append(E(l)).Append("</th><td>").Append(E(L.F("{0} host, {1} attivi, {2} con HTTP; solo qui: {3}", HostsByLabel.GetValueOrDefault(l)?.Count ?? 0, AliveByLabel.GetValueOrDefault(l)?.Count ?? 0, HttpByLabel.GetValueOrDefault(l)?.Count ?? 0,
                OnlyIn.TryGetValue(l, out var only) && only.Count > 0 ? string.Join(", ", only.Take(12)) + (only.Count > 12 ? $" +{only.Count - 12}" : "") : "–"))).Append("</td></tr>");
        sb.Append("</table>");

        // host attivi solo in alcune sessioni
        var aliveUnion = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in labels) if (AliveByLabel.TryGetValue(l, out var a)) aliveUnion.UnionWith(a);
        var partial = aliveUnion.Where(h => labels.Count(l => AliveByLabel.TryGetValue(l, out var a) && a.Contains(h)) < labels.Count).OrderBy(TargetParser.SortKey, StringComparer.Ordinal).ToList();
        sb.Append("<h3>").Append(E(L.F("Host attivi solo in alcune sessioni: {0}", partial.Count))).Append("</h3>");
        if (partial.Count > 0)
        {
            sb.Append("<table class=\"res\"><thead><tr><th>").Append(E(L.T("Host"))).Append("</th>");
            foreach (var l in labels) sb.Append("<th>").Append(E(l)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var h in partial)
            {
                sb.Append("<tr><td class=\"mono\">").Append(E(h)).Append("</td>");
                foreach (var l in labels)
                {
                    bool scanned = HostsByLabel.TryGetValue(l, out var hs) && hs.Contains(h);
                    bool alive = AliveByLabel.TryGetValue(l, out var a) && a.Contains(h);
                    sb.Append("<td>").Append(E(!scanned ? L.T("non scansionato") : alive ? L.T("Attivo") : L.T("Nessuna risposta"))).Append("</td>");
                }
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table>");
        }

        // servizi con verdetto diverso
        var keys = best.SelectMany(d => d.Keys).Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(k => (Key: k, First: best.Select(d => d.GetValueOrDefault(k)).First(r => r != null)!))
            .OrderBy(x => x.First.SortKey, StringComparer.Ordinal).ThenBy(x => x.First.Port).ToList();
        var differing = keys.Where(k => best.Select(d => d.GetValueOrDefault(k.Key)).Where(r => r != null).Select(r => r!.Verdict).Distinct().Count() > 1).ToList();
        sb.Append("<h3>").Append(E(L.F("Servizi con verdetto diverso tra le sessioni: {0}", differing.Count))).Append("</h3>");
        if (differing.Count > 0)
        {
            sb.Append("<table class=\"res\"><thead><tr><th>").Append(E(L.T("Bersaglio"))).Append("</th><th>").Append(E(L.T("Porta"))).Append("</th>");
            foreach (var l in labels) sb.Append("<th>").Append(E(l)).Append("</th>");
            sb.Append("<th>").Append(E(L.T("Fusione"))).Append("</th></tr></thead><tbody>");
            var mergedByKey = merged.Results.ToDictionary(r => r.Key, r => r, StringComparer.OrdinalIgnoreCase);
            foreach (var k in differing)
            {
                sb.Append("<tr><td class=\"mono\">").Append(E(k.First.Display)).Append("</td><td>").Append(k.First.Port).Append("</td>");
                foreach (var d in best)
                {
                    var r = d.GetValueOrDefault(k.Key);
                    sb.Append("<td>").Append(r == null ? E(L.T("non scansionato")) : Badge(r.Verdict) + (r.PhpVersionRaw.Length > 0 ? " " + E(r.PhpVersionRaw) : "")).Append("</td>");
                }
                sb.Append("<td>").Append(mergedByKey.TryGetValue(k.Key, out var m) ? Badge(m.Verdict) : "–").Append("</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        // informazioni presenti in una sessione e assenti in un'altra
        var info = new List<(ScanResult First, string What, List<string> Values)>();
        foreach (var k in keys)
        {
            // confronto solo tra osservazioni con risposta HTTP: una riga non raggiungibile non "perde" informazioni, non le ha mai avute
            var present = best.Select(d => d.GetValueOrDefault(k.Key)).Select(r => r is { HttpReachable: true } ? r : null).ToList();
            if (present.Count(r => r != null) < 2) continue;
            Check(present, r => r.PhpVersionRaw, L.T("Versione PHP"), k.First, info);
            Check(present, r => r.Application.Length > 0 ? r.Application + (r.ApplicationVersion.Length > 0 ? " " + r.ApplicationVersion : "") : "", L.T("Applicazione"), k.First, info);
            Check(present, r => string.Join(" ", HostLists.Names([r])), L.T("Nomi"), k.First, info);
        }
        sb.Append("<h3>").Append(E(L.F("Informazioni presenti in una sessione e assenti in un'altra: {0}", info.Count))).Append("</h3>");
        if (info.Count > 0)
        {
            sb.Append("<table class=\"res\"><thead><tr><th>").Append(E(L.T("Bersaglio"))).Append("</th><th>").Append(E(L.T("Porta"))).Append("</th><th>").Append(E(L.T("Informazione"))).Append("</th>");
            foreach (var l in labels) sb.Append("<th>").Append(E(l)).Append("</th>");
            sb.Append("</tr></thead><tbody>");
            foreach (var (first, what, values) in info)
            {
                sb.Append("<tr><td class=\"mono\">").Append(E(first.Display)).Append("</td><td>").Append(first.Port).Append("</td><td>").Append(E(what)).Append("</td>");
                foreach (var v in values) sb.Append("<td>").Append(E(v)).Append("</td>");
                sb.Append("</tr>");
            }
            sb.Append("</tbody></table>");
        }
        sb.Append("</section>");
        return sb.ToString();
    }

    private static void Check(List<ScanResult?> present, Func<ScanResult, string> pick, string what, ScanResult first, List<(ScanResult, string, List<string>)> info)
    {
        var values = present.Select(r => r == null ? null : pick(r)).ToList();
        bool some = values.Any(v => !string.IsNullOrEmpty(v)), missing = values.Any(v => v != null && v.Length == 0);
        if (some && missing) info.Add((first, what, values.Select(v => v == null ? L.T("nessuna risposta HTTP") : v.Length == 0 ? "–" : v).ToList()));
    }

    private static string Badge(Verdict v) => "<span class=\"badge " + Core.Labels.VerdictClass(v) + "\">" + E(Core.Labels.Verdict(v)) + "</span>";
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
}
