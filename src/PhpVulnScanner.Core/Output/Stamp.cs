using System.Globalization;

namespace PhpVulnScanner.Core.Output;

/// <summary>Marche temporali del programma: ISO con millisecondi e virgola decimale, locale più UTC nel log.</summary>
public static class Stamp
{
    public const string Format = "yyyy-MM-dd HH:mm:ss,fff";

    /// <summary>"2026-10-22 16:07:12,243" (ora locale).</summary>
    public static string Local(DateTime t) => t.ToString(Format, CultureInfo.InvariantCulture);

    /// <summary>"2026-10-22 16:07:12,243 (14:07:12,243Z)": locale più UTC, per le righe di log.</summary>
    public static string Log(DateTime localTime)
    {
        var utc = localTime.Kind == DateTimeKind.Utc ? localTime : localTime.ToUniversalTime();
        return $"{Local(localTime)} ({utc:HH:mm:ss,fff}Z)";
    }

    public static string LogNow() => Log(DateTime.Now);
}
