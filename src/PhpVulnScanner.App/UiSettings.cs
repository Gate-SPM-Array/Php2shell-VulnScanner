using System.IO;
using System.Text.Json;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Output;

namespace PhpVulnScanner.App;

/// <summary>Ultima configurazione usata e lingua scelta, salvate in PhpVulnScanner.settings.json accanto all'eseguibile.</summary>
public sealed class UiSettings
{
    public ScanConfig Config { get; set; } = new();

    /// <summary>Lingua scelta dal menu 🌐 ("" = automatica: italiano se Windows è in italiano, altrimenti inglese).</summary>
    public string Language { get; set; } = "";

    public double WindowWidth { get; set; }
    public double WindowHeight { get; set; }

    private static UiSettings? _current;
    public static UiSettings Current => _current ??= Load();

    public static string FilePath => Path.Combine(AppPaths.DataFolder, "PhpVulnScanner.settings.json");

    public static UiSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<UiSettings>(File.ReadAllText(FilePath), ScanConfig.JsonOptions) ?? new UiSettings();
        }
        catch { /* impostazioni illeggibili: si riparte dai valori predefiniti */ }
        return new UiSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(AppPaths.DataFolder);
            SessionFiles.WriteAllTextAtomic(FilePath, JsonSerializer.Serialize(this, ScanConfig.JsonOptions));
        }
        catch { /* non critico */ }
    }
}
