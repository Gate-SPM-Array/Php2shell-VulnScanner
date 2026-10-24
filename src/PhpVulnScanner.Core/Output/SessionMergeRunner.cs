using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Report;

namespace PhpVulnScanner.Core.Output;

/// <summary>
/// Fusione di sessioni (v1.4), lato file: legge le cartelle, controlla la sovrapposizione dei bersagli, scrive la sessione fusa
/// (session.json, results.json, results.jsonl con tutte le osservazioni, CSV, report completo e compatto con la sezione "Differenze",
/// file degli host). Le sessioni originali restano intatte; la fusione è una sessione come le altre e si può rifondere.
/// </summary>
public static class SessionMergeRunner
{
    public static ScanSession Run(IReadOnlyList<string> folders, string outputFolder, Action<string>? log)
    {
        if (folders.Count < 2) throw new ArgumentException(L.T("Servono almeno due cartelle di sessione da fondere."));
        var inputs = folders.Select(f => SessionMerger.Load(f)).OrderBy(i => i.Session.StartLocal).ToList();
        foreach (var i in inputs) log?.Invoke(L.F("Sessione letta: {0} ({1}, {2} osservazioni, {3} servizi)", i.Folder, i.Label, i.Observations.Count, i.Session.Results.Count));
        var analysis = SessionMerger.Analyse(inputs);
        log?.Invoke(analysis.Summary());

        Directory.CreateDirectory(outputFolder);
        string folder = Path.Combine(outputFolder, $"{DateTime.Now:yyyyMMdd_HHmmss}_phpscan_fusione");
        Directory.CreateDirectory(folder);
        var merged = SessionMerger.Merge(inputs, folder);
        merged.Folder = folder;

        using (var writer = new SessionWriter(merged, consolidate: true))
        {
            writer.Log(L.F("Fusione di {0} sessioni: {1}", inputs.Count, string.Join("; ", inputs.Select(i => i.Label + " " + i.Folder))));
            writer.Log(analysis.Summary());
            foreach (var i in inputs) foreach (var o in i.Observations) writer.Upsert(o);
            writer.Finish(merged);
        }
        HostLists.Write(folder, merged.AppVersion, merged.Results);

        // report: completo con la sezione "Differenze", compatto accanto
        string diff = analysis.DifferencesHtml(inputs, merged);
        var full = SessionFiles.NextReportPath(folder, SessionFiles.FullReportPrefix, merged.AppVersion);
        File.WriteAllText(full, ReportGenerator.Build(merged, diff), new System.Text.UTF8Encoding(false));
        var compact = SessionFiles.NextReportPath(folder, SessionFiles.CompactReportPrefix, merged.AppVersion);
        File.WriteAllText(compact, CompactReportGenerator.Build(merged, Path.GetFileName(full)).Replace("</footer>", "</footer>" + diff), new System.Text.UTF8Encoding(false));
        log?.Invoke(L.F("Sessione fusa scritta in {0}: {1} servizi, report {2}", folder, merged.Results.Count, Path.GetFileName(compact)));
        return merged;
    }
}
