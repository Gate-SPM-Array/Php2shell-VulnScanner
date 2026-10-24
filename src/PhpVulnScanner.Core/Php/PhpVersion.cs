using System.Text.RegularExpressions;

namespace PhpVulnScanner.Core.Php;

/// <summary>Posizione di una versione dichiarata rispetto alle correzioni di PHP2Shell.</summary>
public enum VersionStatus
{
    /// <summary>Nessuna versione letta.</summary>
    Unknown,
    /// <summary>Ramo supportato, numero uguale o successivo alla versione corretta.</summary>
    Fixed,
    /// <summary>Ramo supportato (8.2+), numero precedente alla versione corretta.</summary>
    VulnerableSupported,
    /// <summary>Ramo fuori supporto (5.4 … 8.1): vulnerabile per versione, ma le distribuzioni correggono senza cambiare il numero.</summary>
    EndOfLife,
    /// <summary>Ramo successivo a quelli corretti (nato dopo la correzione).</summary>
    Newer,
    /// <summary>Precedente a PHP 5.4: fuori dall'intervallo indicato dalle fonti.</summary>
    Ancient,
}

/// <summary>
/// Versione di PHP letta da un'intestazione o da una pagina, con il confronto contro le prime versioni corrette
/// pubblicate il 21/10/2026: 8.2.35, 8.3.36, 8.4.27, 8.5.12. Per i rami 5.4 … 8.1 non esiste una release ufficiale:
/// il numero da solo non basta a dire se il backport della distribuzione è installato.
/// </summary>
public sealed record PhpVersion(int Major, int Minor, int Patch, string Raw, string Suffix)
{
    public static readonly IReadOnlyDictionary<string, (int Patch, string Full)> FixedVersions = new Dictionary<string, (int, string)>
    {
        ["8.2"] = (35, "8.2.35"),
        ["8.3"] = (36, "8.3.36"),
        ["8.4"] = (27, "8.4.27"),
        ["8.5"] = (12, "8.5.12"),
    };

    public string Branch => $"{Major}.{Minor}";
    public string Normalized => $"{Major}.{Minor}.{Patch}";

    /// <summary>Vero se il numero porta un suffisso di pacchetto (Debian, Ubuntu, RHEL, Plesk…): possibile backport invisibile.</summary>
    public bool HasPackageSuffix => Suffix.Length > 0;

    private static readonly Regex Rx = new(@"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?([A-Za-z0-9~+._-]*)", RegexOptions.CultureInvariant);

    /// <summary>Estrae la versione da testi come <c>PHP/8.1.2-1ubuntu2.14</c>, <c>8.3.12</c>, <c>PHP Version 7.4.33</c>.</summary>
    public static PhpVersion? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        // preferisce l'occorrenza preceduta da "PHP"
        var m = Regex.Match(text, @"PHP[/ ]?(?:Version\s*)?(\d+\.\d+(?:\.\d+)?[A-Za-z0-9~+._-]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        string candidate = m.Success ? m.Groups[1].Value : text.Trim();
        var v = Rx.Match(candidate);
        if (!v.Success) return null;
        int major = int.Parse(v.Groups[1].Value), minor = int.Parse(v.Groups[2].Value);
        int patch = v.Groups[3].Success ? int.Parse(v.Groups[3].Value) : -1;
        string suffix = v.Groups[4].Value.Trim('.', '-', '_');
        if (major < 4 || major > 20) return null;
        return new PhpVersion(major, minor, patch, candidate.Trim(), suffix);
    }

    public VersionStatus Status()
    {
        if (Major < 5 || (Major == 5 && Minor < 4)) return VersionStatus.Ancient;
        if (Major > 8 || (Major == 8 && Minor > 5)) return VersionStatus.Newer;
        if (FixedVersions.TryGetValue(Branch, out var fix))
        {
            if (Patch < 0) return VersionStatus.VulnerableSupported;   // "8.3" senza patch: non dimostrabile corretta
            return Patch >= fix.Patch ? VersionStatus.Fixed : VersionStatus.VulnerableSupported;
        }
        return VersionStatus.EndOfLife;
    }

    /// <summary>Versione corretta del ramo, se esiste una release ufficiale.</summary>
    public string? FixedRelease => FixedVersions.TryGetValue(Branch, out var f) ? f.Full : null;

    public override string ToString() => Raw;
}
