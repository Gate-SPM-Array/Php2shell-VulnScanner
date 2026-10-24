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

    /// <summary>Fonde il nuovo risultato con quello già consolidato e restituisce il vincente, con la storia completa.</summary>
    public static ScanResult Merge(ScanResult? current, ScanResult incoming)
    {
        if (current == null)
        {
            if (incoming.History.Count == 0) incoming.History.Add(HistoryLine(incoming));
            return incoming;
        }
        var history = new List<string>(current.History);
        if (history.Count == 0) history.Add(HistoryLine(current));
        history.Add(HistoryLine(incoming));
        int sc = Score(current), si = Score(incoming);
        var winner = si >= sc ? incoming : current;   // a parità vince il più recente
        winner.History = history;
        foreach (var n in current.DiscoveredNames.Concat(incoming.DiscoveredNames))
            if (!winner.DiscoveredNames.Contains(n)) winner.DiscoveredNames.Add(n);
        return winner;
    }

    /// <summary>Vero se i verdetti nella storia non sono tutti uguali.</summary>
    public static bool VerdictChanged(ScanResult r) =>
        r.History.Select(h => { int i = h.IndexOf(':'); string s = i < 0 ? h : h[(i + 1)..].Trim(); int p = s.IndexOf(" ("); return p < 0 ? s : s[..p]; }).Distinct().Count() > 1;
}
