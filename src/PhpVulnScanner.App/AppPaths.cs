using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace PhpVulnScanner.App;

/// <summary>Percorsi dell'applicazione portable: tutto accanto all'eseguibile, se la cartella è scrivibile.</summary>
public static class AppPaths
{
    public static string ExeFolder { get; } =
        Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;

    /// <summary>Versione mostrata: "X.Y" quando la patch è 0, altrimenti "X.Y.Z" (stessa regola degli altri progetti).</summary>
    public static string Version { get; } =
        Assembly.GetExecutingAssembly().GetName().Version is { } v ? (v.Build == 0 ? $"{v.Major}.{v.Minor}" : $"{v.Major}.{v.Minor}.{v.Build}") : "1.0";

    private static readonly Lazy<string> _data = new(() =>
        IsWritable(ExeFolder)
            ? ExeFolder
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PhpVulnScanner"));

    /// <summary>Cartella per impostazioni e crash log.</summary>
    public static string DataFolder => _data.Value;

    public static string SettingsFile => Path.Combine(DataFolder, "PhpVulnScanner.settings.json");

    public static string DefaultSessionsFolder =>
        IsWritable(ExeFolder)
            ? Path.Combine(ExeFolder, "Sessioni")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "PhpVulnScanner", "Sessioni");

    private static bool IsWritable(string dir)
    {
        try
        {
            var probe = Path.Combine(dir, $".write_test_{Environment.ProcessId}");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch { return false; }
    }
}

/// <summary>Chiamate Windows: evitare la sospensione del PC e migliorare la risoluzione del timer durante il test.</summary>
internal static class Native
{
    private const uint EsContinuous = 0x80000000, EsSystemRequired = 0x00000001;

    [DllImport("kernel32.dll")]
    private static extern uint SetThreadExecutionState(uint flags);

    [DllImport("winmm.dll")]
    private static extern uint timeBeginPeriod(uint ms);

    [DllImport("winmm.dll")]
    private static extern uint timeEndPeriod(uint ms);

    private static bool _active;

    /// <summary>Da chiamare dal thread UI (lo stato è per-thread).</summary>
    public static void KeepAwake(bool on)
    {
        if (on == _active) return;
        _active = on;
        try
        {
            SetThreadExecutionState(on ? EsContinuous | EsSystemRequired : EsContinuous);
            if (on) timeBeginPeriod(1); else timeEndPeriod(1);
        }
        catch { /* non critico */ }
    }
}
