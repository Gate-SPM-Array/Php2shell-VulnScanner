using System.IO;
using System.Windows;
using System.Windows.Threading;
using PhpVulnScanner.Core;

namespace PhpVulnScanner.App;

public partial class App : Application
{
    /// <summary>Messaggi del caricamento della lingua (file mancante, traduzioni scartate), mostrati nella barra di stato.</summary>
    public static IReadOnlyList<string> LanguageMessages { get; private set; } = [];

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool AttachConsole(int pid);

    protected override void OnStartup(StartupEventArgs e)
    {
        // La lingua va caricata prima di creare qualsiasi finestra: i testi XAML si traducono al caricamento.
        LanguageMessages = L.Load(UiSettings.Current.Language);
        // Database applicazioni (webappanalyzer + NCSC-NL) dalla cartella data\ accanto all'eseguibile; senza, restano le firme incorporate
        PhpVulnScanner.Core.Apps.TechnologyDatabase.Default = PhpVulnScanner.Core.Apps.TechnologyDatabase.TryLoad(Path.Combine(AppPaths.ExeFolder, "data"));

        if (PhpVulnScanner.Core.Cli.CliRunner.IsCliInvocation(e.Args))
        {
            // Riga di comando: nessuna finestra, output sulla console che ha lanciato il programma, esito nel codice di uscita.
            AttachConsole(-1);
            var stdout = new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true };
            int code = PhpVulnScanner.Core.Cli.CliRunner.RunAsync(e.Args, AppPaths.DefaultSessionsFolder, stdout, CancellationToken.None).GetAwaiter().GetResult();
            stdout.WriteLine();
            Shutdown(code);
            return;
        }
        DispatcherUnhandledException += OnUiException;
        AppDomain.CurrentDomain.UnhandledException += (_, ev) => WriteCrash(ev.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, ev) => { WriteCrash(ev.Exception); ev.SetObserved(); };
        base.OnStartup(e);
    }

    private void OnUiException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var path = WriteCrash(e.Exception);
        MessageBox.Show(L.F("Si è verificato un errore imprevisto nell'interfaccia:\n\n{0}\n\nLa scansione eventualmente in corso continua e i risultati restano salvati su disco.\nDettagli in: {1}",
                            e.Exception.Message, path),
                        "PHP Vuln Scanner", MessageBoxButton.OK, MessageBoxImage.Warning);
        e.Handled = true;
        if (MainWindow is not { IsLoaded: true }) Shutdown(1);   // errore all'avvio: non lasciare un processo invisibile
    }

    public static string WriteCrash(Exception? ex)
    {
        try
        {
            var dir = AppPaths.DataFolder;
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "crash.log");
            File.AppendAllText(path, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {ex}\n\n");
            return path;
        }
        catch { return L.T("(non scrivibile)"); }
    }
}
