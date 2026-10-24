using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Waf;

/// <summary>Esecuzione della rilevazione WAF / CDN / reverse proxy / bilanciatore su un bersaglio già raggiunto.</summary>
public static class WafProbe
{
    /// <summary>Parametri dall'aspetto ostile ma inerti (nessun effetto su un'applicazione che li ignora): servono solo a vedere se un filtro reagisce.</summary>
    public const string HostileQuery = "?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&id=1%27%20OR%20%271%27%3D%271&file=..%2F..%2F..%2Fetc%2Fpasswd&cmd=%3Bcat%20%2Fetc%2Fpasswd";

    public static async Task RunAsync(ScanContext ctx)
    {
        var r = ctx.Result;
        var findings = new List<WafFinding>();

        foreach (var snap in r.Requests.Where(s => s.HasResponse))
            foreach (var f in WafDetector.FromSnapshot(snap)) WafDetector.Merge(findings, f);
        foreach (var f in WafDetector.FromTls(r.Tls)) WafDetector.Merge(findings, f);

        if (ctx.Config.WafBehaviour && ctx.Baseline != null)
        {
            string path = ctx.PrimaryPath + (ctx.PrimaryPath.Contains('?') ? "&" + HostileQuery[1..] : HostileQuery);
            var hostile = await ctx.GetAsync(path).ConfigureAwait(false);
            foreach (var f in WafDetector.FromSnapshot(hostile)) WafDetector.Merge(findings, f);
            var b = WafDetector.FromBehaviour(ctx.Baseline, hostile);
            if (b != null) WafDetector.Merge(findings, b);

            // ripetizioni per bilanciamento; dopo la richiesta ostile dicono anche se il filtro ha messo in lista nera chi scansiona
            var repeats = new List<HttpSnapshot> { ctx.Baseline };
            for (int i = 0; i < 2; i++)
            {
                ctx.Ct.ThrowIfCancellationRequested();
                var s = await ctx.GetAsync(ctx.PrimaryPath).ConfigureAwait(false);
                repeats.Add(s);
                foreach (var f in WafDetector.FromSnapshot(s)) WafDetector.Merge(findings, f);
            }
            var after = repeats.Skip(1).ToList();
            string afterNote = after.All(s => s.HasResponse)
                ? L.F("; le {0} richieste normali successive hanno risposto ({1}): nessun blocco dell'origine", after.Count, string.Join(", ", after.Select(s => s.Status)))
                : L.F("; richieste normali successive senza risposta ({0}): possibile blocco temporaneo dell'origine", string.Join(", ", after.Select(s => s.Summary)));
            r.Add("WAF-BEHAVIOUR", L.T("Richiesta con parametri ostili inerti"), b != null ? TestOutcome.Warn : TestOutcome.Info,
                (b != null ? b.Evidence : L.F("stessa risposta della richiesta normale ({0}): nessun filtro sui parametri rilevato", hostile.Summary)) + afterNote, hostile);
            foreach (var f in WafDetector.FromRepetition(r.ResolvedIps, repeats)) WafDetector.Merge(findings, f);
        }

        r.Waf = findings.OrderByDescending(f => f.Confidence).ThenBy(f => f.Category).ToList();
        r.WafSummary = WafDetector.Summarize(r.Waf);
        foreach (var f in r.Waf)
            r.Add("WAF-" + f.Category.ToString().ToUpperInvariant(), $"{Labels.WafCategory(f.Category)}: {f.Name}",
                f.Confidence == Confidence.High ? TestOutcome.Warn : TestOutcome.Info, L.F("confidenza {0}: {1}", Labels.Confidence(f.Confidence), f.Evidence));
        if (r.Waf.Count == 0) r.Add("WAF-NONE", L.T("WAF / proxy / bilanciatore"), TestOutcome.Info, L.T("nessun indizio nelle intestazioni, nei cookie, nel certificato e nel comportamento"));
    }
}
