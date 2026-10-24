using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;

namespace PhpVulnScanner.Core.Engine;

/// <summary>
/// Consolidamento tra cicli (regola validata dal maintainer): vince il risultato più informativo — versione dichiarata
/// batte "non determinabile", raggiungibile batte non raggiungibile, barriera osservata batte non provata — e a parità
/// il ciclo più recente. La storia dei cicli resta nel risultato vincente, così una variazione del verdetto è visibile.
/// </summary>
public static class ResultMerger
{
    /// <summary>Punteggio di informatività: più alto = più informativo.</summary>
    public static int Score(ScanResult r)
    {
        int s = 0;
        if (r.HttpReachable) s += 100; else if (r.Alive == AliveState.Alive) s += 10;
        if (r.VersionStatus != VersionStatus.Unknown) s += 40;
        if (r.PhpDetected) s += 20;
        if (r.Application.Length > 0) s += 5;
        if (r.Multipart is not (MultipartBarrier.NotTested or MultipartBarrier.NoResponse)) s += 8;
        if (r.Waf.Count > 0) s += 2;
        if (r.PhpSurface.Count > 0) s += 1;
        return s;
    }

    /// <summary>Una riga di storia: "ciclo 2: Probabilmente vulnerabile (7.4.33)".</summary>
    public static string HistoryLine(ScanResult r)
    {
        string v = Labels.Verdict(r.Verdict);
        if (r.PhpVersionRaw.Length > 0) v += $" ({r.PhpVersionRaw})";
        else if (!r.HttpReachable && r.Alive != AliveState.NotTested) v += $" ({Labels.Alive(r.Alive)})";
        return L.F("ciclo {0}: {1}", r.Cycle, v);
    }

    /// <summary>
    /// Fonde il nuovo risultato con quello già consolidato e restituisce il vincente, con la storia completa.
    /// v1.8 (regola del maintainer): il più informativo vince come base, ma le informazioni che ha solo l'altro ciclo si uniscono campo per
    /// campo (valori singoli presi dove mancano, elenchi uniti); verdetto e priorità ricalcolati sui campi fusi; ciclo e orario dell'ultima
    /// osservazione; test e richieste restano quelli della base (sono le evidenze dei suoi campi), con una riga MERGE che elenca i campi presi
    /// dall'altro ciclo. Stesso ciclo (riemissione dopo la seconda chance dell'alive check): la riga di storia viene sostituita, non aggiunta.
    /// </summary>
    public static ScanResult Merge(ScanResult? current, ScanResult incoming, bool sameCycle = false)
    {
        if (current == null)
        {
            if (incoming.History.Count == 0) incoming.History.Add(HistoryLine(incoming));
            return incoming;
        }
        var history = new List<string>(current.History);
        if (history.Count == 0) history.Add(HistoryLine(current));
        if (sameCycle) history[^1] = HistoryLine(incoming);   // riemissione nello stesso ciclo (seconda chance): la riga di storia si aggiorna
        else history.Add(HistoryLine(incoming));
        int sc = Score(current), si = Score(incoming);
        var winner = si >= sc ? incoming : current;   // a parità vince il più recente
        var other = ReferenceEquals(winner, incoming) ? current : incoming;
        var taken = FillFrom(winner, other);
        winner.History = history;
        if (taken.Count > 0)
        {
            VerdictEngine.Apply(winner);
            winner.Add("MERGE", L.T("Fusione tra cicli"), TestOutcome.Info, L.F("dal ciclo {0}: {1}", other.Cycle, string.Join(", ", taken)));
        }
        // ciclo e orario dell'ultima osservazione (la base può essere quella più vecchia)
        if (!ReferenceEquals(winner, incoming) && incoming.StartedLocal > winner.StartedLocal) { winner.StartedLocal = incoming.StartedLocal; winner.Cycle = incoming.Cycle; }
        return winner;
    }

    /// <summary>Riempie in <paramref name="w"/> i campi vuoti con quelli di <paramref name="o"/> e unisce gli elenchi; restituisce i nomi dei campi presi.</summary>
    internal static List<string> FillFrom(ScanResult w, ScanResult o)
    {
        var taken = new List<string>();
        void Str(string name, Func<ScanResult, string> get, Action<ScanResult, string> set)
        {
            if (get(w).Length == 0 && get(o).Length > 0) { set(w, get(o)); taken.Add(name); }
        }
        void ListU(string name, Func<ScanResult, List<string>> get)
        {
            var lw = get(w); int before = lw.Count;
            foreach (var x in get(o)) if (!lw.Contains(x, StringComparer.OrdinalIgnoreCase)) lw.Add(x);
            if (lw.Count > before) taken.Add(name);
        }
        if (w.PhpVersionRaw.Length == 0 && o.PhpVersionRaw.Length > 0)
        {
            w.PhpVersionRaw = o.PhpVersionRaw; w.PhpVersionSource = o.PhpVersionSource; w.VersionStatus = o.VersionStatus; w.FixedRelease = o.FixedRelease; w.PackageSuffix = o.PackageSuffix;
            taken.Add("PhpVersionRaw");
        }
        if (!w.PhpDetected && o.PhpDetected) { w.PhpDetected = true; if (w.PhpEvidence.Length == 0) w.PhpEvidence = o.PhpEvidence; taken.Add("PhpDetected"); }
        Str("Sapi", r => r.Sapi, (r, v) => { r.Sapi = v; r.SapiEvidence = o.SapiEvidence; });
        Str("OsHint", r => r.OsHint, (r, v) => r.OsHint = v);
        Str("Application", r => r.Application, (r, v) => { r.Application = v; r.ApplicationEvidence = o.ApplicationEvidence; r.ApplicationReference = o.ApplicationReference; r.ApplicationVersion = o.ApplicationVersion; });
        Str("ApplicationVersion", r => r.ApplicationVersion, (r, v) => r.ApplicationVersion = v);
        Str("PoweredBy", r => r.PoweredBy, (r, v) => r.PoweredBy = v);
        Str("ServerHeader", r => r.ServerHeader, (r, v) => r.ServerHeader = v);
        Str("SessionCookie", r => r.SessionCookie, (r, v) => r.SessionCookie = v);
        Str("SizeLimit", r => r.SizeLimit, (r, v) => r.SizeLimit = v);
        Str("HeadVsGet", r => r.HeadVsGet, (r, v) => r.HeadVsGet = v);
        Str("AllowedMethods", r => r.AllowedMethods, (r, v) => r.AllowedMethods = v);
        Str("PhpVersionFloor", r => r.PhpVersionFloor, (r, v) => { r.PhpVersionFloor = v; r.PhpVersionFloorSource = o.PhpVersionFloorSource; });
        Str("BrowserUaResult", r => r.BrowserUaResult, (r, v) => r.BrowserUaResult = v);
        Str("CertificateStatus", r => r.CertificateStatus, (r, v) => r.CertificateStatus = v);
        Str("CacheHint", r => r.CacheHint, (r, v) => r.CacheHint = v);
        Str("NcscStatus", r => r.NcscStatus, (r, v) => { r.NcscStatus = v; r.NcscReference = o.NcscReference; });
        Str("AppVersionCheck", r => r.AppVersionCheck, (r, v) => r.AppVersionCheck = v);
        Str("InventoryStatus", r => r.InventoryStatus, (r, v) => { r.InventoryStatus = v; r.InventoryDeclaredVersion = o.InventoryDeclaredVersion; r.InventoryOwner = o.InventoryOwner; r.InventoryEnvironment = o.InventoryEnvironment; r.InventoryNote = o.InventoryNote; });
        Str("WafSummary", r => r.WafSummary, (r, v) => r.WafSummary = v);
        if (w.Multipart is MultipartBarrier.NotTested or MultipartBarrier.NoResponse && o.Multipart is not (MultipartBarrier.NotTested or MultipartBarrier.NoResponse))
        {
            w.Multipart = o.Multipart; w.MultipartDetail = o.MultipartDetail; w.VariantsBlocked = o.VariantsBlocked; w.VariantsTotal = o.VariantsTotal; w.UploadProgressFieldBlocked = o.UploadProgressFieldBlocked;
            taken.Add("Multipart");
        }
        if (w.Tls == null && o.Tls != null) { w.Tls = o.Tls; taken.Add("Tls"); }
        if (w.FastCgiExposed == null && o.FastCgiExposed != null) { w.FastCgiExposed = o.FastCgiExposed; w.FastCgiDetail = o.FastCgiDetail; taken.Add("FastCgiExposed"); }
        if (w.SessionIdAdopted == null && o.SessionIdAdopted != null) { w.SessionIdAdopted = o.SessionIdAdopted; w.SessionIdDetail = o.SessionIdDetail; taken.Add("SessionIdAdopted"); }
        if (w.Waf.Count == 0 && o.Waf.Count > 0) { w.Waf = [.. o.Waf]; taken.Add("Waf"); }
        if (Rank(o.PhpPresence) > Rank(w.PhpPresence)) { w.PhpPresence = o.PhpPresence; taken.Add("PhpPresence"); }
        if (o.PhpHintScore > w.PhpHintScore) { w.PhpHintScore = o.PhpHintScore; taken.Add("PhpHintScore"); }
        if (o.VerbosityScore > w.VerbosityScore) { w.VerbosityScore = o.VerbosityScore; taken.Add("VerbosityScore"); }
        ListU("DiscoveredNames", r => r.DiscoveredNames);
        ListU("SameContentNames", r => r.SameContentNames);
        ListU("SameOutcomeNames", r => r.SameOutcomeNames);
        ListU("PhpSurface", r => r.PhpSurface);
        ListU("Technologies", r => r.Technologies);
        ListU("TechnologyStatuses", r => r.TechnologyStatuses);
        ListU("Libraries", r => r.Libraries);
        ListU("Components", r => r.Components);
        ListU("Exposures", r => r.Exposures);
        ListU("PhpHints", r => r.PhpHints);
        ListU("IniHints", r => r.IniHints);
        ListU("VerbosityItems", r => r.VerbosityItems);
        ListU("BodyDeclaredVersions", r => r.BodyDeclaredVersions);
        ListU("ResolvedIps", r => r.ResolvedIps);
        // i nomi scoperti entrano sempre (già dalla v1.3); non contano come "campo preso"
        taken.Remove("DiscoveredNames");
        return taken;
    }

    private static int Rank(string presence) => presence == "yes" ? 2 : presence == "maybe" ? 1 : 0;

    /// <summary>Vero se i verdetti nella storia non sono tutti uguali.</summary>
    public static bool VerdictChanged(ScanResult r) =>
        r.History.Select(h => { int i = h.IndexOf(':'); string s = i < 0 ? h : h[(i + 1)..].Trim(); int p = s.IndexOf(" ("); return p < 0 ? s : s[..p]; }).Distinct().Count() > 1;
}
