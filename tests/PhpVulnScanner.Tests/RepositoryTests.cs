using System.Text.RegularExpressions;

namespace PhpVulnScanner.Tests;

/// <summary>Controlli di coerenza del repository (regola del maintainer: ogni consegna ha un numero di versione nuovo e unico).</summary>
public class RepositoryTests
{
    private static string Read(params string[] p) => File.ReadAllText(Path.Combine(LocalizationTests.RepoRoot(), Path.Combine(p)));

    [Fact]
    public void VersionNumber_IsTheSameEverywhere()
    {
        var props = Read("Directory.Build.props");
        var m = Regex.Match(props, @"<Version>(\d+)\.(\d+)\.(\d+)</Version>");
        Assert.True(m.Success, "Version non trovata in Directory.Build.props");
        string full = $"{m.Groups[1].Value}.{m.Groups[2].Value}.{m.Groups[3].Value}";
        // Nome visibile: "1.2" per le versioni x.y.0, "1.2.1" altrimenti
        string v = m.Groups[3].Value == "0" ? $"{m.Groups[1].Value}.{m.Groups[2].Value}" : full;

        Assert.Contains($"<FileVersion>{full}.0</FileVersion>", props);
        Assert.Contains($"<AssemblyVersion>{full}.0</AssemblyVersion>", props);
        Assert.Matches(new Regex(@"^## v" + Regex.Escape(v) + " ", RegexOptions.Multiline), Read("CHANGELOG.md"));
        Assert.Contains("v" + v, Read("README.md").Split('\n')[0]);
        Assert.Contains("v" + v, Read("README.it.md").Split('\n')[0]);
        Assert.Contains($"\"app_version\": \"{v}\"", Read("lang", "en.json"));
        Assert.Contains("v" + v, Read("src", "PhpVulnScanner.App", "Help", "Guida.html"));
        Assert.Contains("v" + v, Read("src", "PhpVulnScanner.App", "Help", "Guide.html"));
    }

    [Fact]
    public void ReadmesLinkEachOther_AndLicenseIsMit()
    {
        Assert.Contains("README.it.md", Read("README.md"));
        Assert.Contains("README.md", Read("README.it.md"));
        Assert.StartsWith("MIT License", Read("LICENSE").TrimStart());
    }

    [Fact]
    public void NoPersonalDataTracked()
    {
        var ignore = Read(".gitignore");
        foreach (var pattern in new[] { "Sessioni/", "*.settings.json", "crash.log", "results.csv", "report_v*.html" })
            Assert.Contains(pattern, ignore);
    }
}
