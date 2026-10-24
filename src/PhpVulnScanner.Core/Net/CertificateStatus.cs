using PhpVulnScanner.Core.Engine;

namespace PhpVulnScanner.Core.Net;

/// <summary>
/// v1.6: stato del certificato TLS in una riga ("valido" oppure i problemi separati da "; "). Non tocca il verdetto PHP2Shell:
/// è un'informazione di igiene del servizio, utile per capire chi deve intervenire e per riconoscere nomi interni e certificati di default.
/// </summary>
public static class CertificateStatus
{
    /// <summary>Giorni entro i quali la scadenza imminente viene segnalata.</summary>
    public const int ExpiryWarningDays = 30;

    /// <summary>Chiavi RSA sotto questa lunghezza sono segnalate come deboli.</summary>
    public const int MinRsaBits = 2048;

    /// <summary>"" senza handshake, "valido" quando tutto è a posto, altrimenti i problemi in italiano separati da "; ".</summary>
    public static string Status(TlsInfo? t, string hostName) => Status(t, hostName, DateTime.UtcNow);

    /// <summary>Come <see cref="Status(TlsInfo?, string)"/> con l'istante di riferimento esplicito (per i test).</summary>
    public static string Status(TlsInfo? t, string hostName, DateTime nowUtc) => Evaluate(t, hostName, nowUtc).Text;

    /// <summary>Vero quando il certificato ha almeno un problema che merita un avviso (tutto tranne la sola scadenza imminente).</summary>
    public static bool IsWarning(TlsInfo? t, string hostName) => Evaluate(t, hostName, DateTime.UtcNow).Warn;

    public static bool IsWarning(TlsInfo? t, string hostName, DateTime nowUtc) => Evaluate(t, hostName, nowUtc).Warn;

    private static (string Text, bool Warn) Evaluate(TlsInfo? t, string hostName, DateTime nowUtc)
    {
        if (t == null || !t.Handshake) return ("", false);
        var issues = new List<string>();
        bool warn = false;
        if (t.NotAfter is DateTime na && na.ToUniversalTime() < nowUtc) { issues.Add(L.F("scaduto il {0:dd/MM/yyyy}", na)); warn = true; }
        else if (t.NotBefore is DateTime nb && nb.ToUniversalTime() > nowUtc) { issues.Add(L.F("non ancora valido (dal {0:dd/MM/yyyy})", nb)); warn = true; }
        else if (t.NotAfter is DateTime na2)
        {
            int days = (int)Math.Floor((na2.ToUniversalTime() - nowUtc).TotalDays);
            if (days <= ExpiryWarningDays) issues.Add(L.F("scade tra {0} giorni", days));   // informativo, non un avviso
        }
        if (t.SelfSigned) { issues.Add(L.T("autofirmato")); warn = true; }
        else if (t.ChainTrusted == false) { issues.Add(L.F("catena non attendibile ({0})", t.ChainError.Length > 0 ? t.ChainError : "?")); warn = true; }
        if (hostName.Length > 0 && !IsIpLiteral(hostName) && !t.NameMatches) { issues.Add(L.F("nome non corrispondente ({0})", hostName)); warn = true; }
        if (t.KeyBits > 0 && t.KeyBits < MinRsaBits && IsRsa(t.SignatureAlgorithm)) { issues.Add(L.F("chiave RSA di {0} bit", t.KeyBits)); warn = true; }
        if (IsWeakSignature(t.SignatureAlgorithm)) { issues.Add(L.F("firma {0}", t.SignatureAlgorithm)); warn = true; }
        return (issues.Count == 0 ? L.T("valido") : string.Join("; ", issues), warn);
    }

    /// <summary>Imposta <see cref="ScanResult.CertificateStatus"/> da <see cref="ScanResult.Tls"/> e aggiorna la riga di test TLS-CERT. Idempotente.</summary>
    public static void Apply(ScanResult r)
    {
        string name = r.NameRescan ? r.HostHeader : r.IsIpLiteral ? "" : r.Host;
        var (text, warn) = Evaluate(r.Tls, name, DateTime.UtcNow);
        r.CertificateStatus = text;
        r.Tests.RemoveAll(t => t.Id == "TLS-CERT");
        if (text.Length == 0) return;
        r.Add("TLS-CERT", L.T("Certificato TLS"), warn ? TestOutcome.Warn : TestOutcome.Info, text);
    }

    private static bool IsIpLiteral(string host) => System.Net.IPAddress.TryParse(host.Trim('[', ']'), out _);

    private static bool IsRsa(string sigAlg) => sigAlg.Length == 0 || sigAlg.Contains("RSA", StringComparison.OrdinalIgnoreCase);

    private static bool IsWeakSignature(string sigAlg) =>
        sigAlg.Contains("sha1", StringComparison.OrdinalIgnoreCase) || sigAlg.Contains("md5", StringComparison.OrdinalIgnoreCase) || sigAlg.Contains("md2", StringComparison.OrdinalIgnoreCase);
}
