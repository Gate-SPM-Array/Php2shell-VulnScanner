using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;
using PhpVulnScanner.Core.Waf;

namespace PhpVulnScanner.Core;

/// <summary>
/// Testi a video per i valori che il programma salva nei file (verdetti, stati, esiti): nei file restano i nomi
/// degli enum come chiavi stabili (CSV e JSON leggibili da SIEM e script), a video compaiono nella lingua attiva.
/// </summary>
public static class Labels
{
    public static string Verdict(Verdict v) => v switch
    {
        Engine.Verdict.NotReachable => L.T("Non raggiungibile"),
        Engine.Verdict.NoPhpDetected => L.T("PHP non rilevato"),
        Engine.Verdict.Undetermined => L.T("Non determinabile"),
        Engine.Verdict.FixedByVersion => L.T("Corretto per versione"),
        Engine.Verdict.VulnerableByVersion => L.T("Vulnerabile per versione"),
        Engine.Verdict.LikelyVulnerable => L.T("Probabilmente vulnerabile"),
        Engine.Verdict.MitigatedAtEdge => L.T("Mitigato al perimetro"),
        _ => v.ToString(),
    };

    /// <summary>Classe CSS / colore del verdetto: bad, warn, ok, muted.</summary>
    public static string VerdictClass(Verdict v) => v switch
    {
        Engine.Verdict.VulnerableByVersion => "bad",
        Engine.Verdict.LikelyVulnerable => "bad",
        Engine.Verdict.MitigatedAtEdge => "warn",
        Engine.Verdict.Undetermined => "warn",
        Engine.Verdict.FixedByVersion => "ok",
        _ => "muted",
    };

    public static string Priority(Priority p) => p switch
    {
        Engine.Priority.Critical => L.T("Critica"),
        Engine.Priority.High => L.T("Alta"),
        Engine.Priority.Medium => L.T("Media"),
        Engine.Priority.Low => L.T("Bassa"),
        Engine.Priority.None => L.T("Nessuna"),
        _ => p.ToString(),
    };

    public static string Sapi(string sapi) => sapi switch
    {
        "mod_php" => "mod_php",
        "fpm" => "PHP-FPM",
        "lsapi" => "LSAPI",
        "cgi" => "CGI/FastCGI",
        _ => L.T("n.d."),
    };

    public static string Alive(AliveState s) => s switch
    {
        AliveState.Alive => L.T("Attivo"),
        AliveState.NoResponse => L.T("Nessuna risposta"),
        AliveState.NotTested => L.T("Non verificato"),
        _ => s.ToString(),
    };

    public static string VersionStatus(VersionStatus s) => s switch
    {
        Php.VersionStatus.Unknown => L.T("non dichiarata"),
        Php.VersionStatus.Fixed => L.T("corretta"),
        Php.VersionStatus.VulnerableSupported => L.T("precedente alla correzione"),
        Php.VersionStatus.EndOfLife => L.T("ramo fuori supporto"),
        Php.VersionStatus.Newer => L.T("ramo successivo alla correzione"),
        Php.VersionStatus.Ancient => L.T("precedente a PHP 5.4"),
        _ => s.ToString(),
    };

    public static string Multipart(MultipartBarrier m) => m switch
    {
        MultipartBarrier.NotTested => L.T("non provato"),
        MultipartBarrier.Accepted => L.T("accettato"),
        MultipartBarrier.Blocked => L.T("bloccato"),
        MultipartBarrier.PartiallyBlocked => L.T("bloccato solo in parte"),
        MultipartBarrier.PostNotAllowed => L.T("POST non consentito"),
        MultipartBarrier.NoResponse => L.T("nessuna risposta"),
        _ => m.ToString(),
    };

    public static string WafCategory(WafCategory c) => c switch
    {
        Waf.WafCategory.Waf => L.T("WAF"),
        Waf.WafCategory.Cdn => L.T("CDN"),
        Waf.WafCategory.ReverseProxy => L.T("Reverse proxy"),
        Waf.WafCategory.LoadBalancer => L.T("Bilanciatore"),
        _ => c.ToString(),
    };

    public static string Confidence(Confidence c) => c switch
    {
        Waf.Confidence.High => L.T("alta"),
        Waf.Confidence.Medium => L.T("media"),
        Waf.Confidence.Low => L.T("bassa"),
        _ => c.ToString(),
    };

    public static string Outcome(TestOutcome o) => o switch
    {
        TestOutcome.Info => L.T("info"),
        TestOutcome.Pass => L.T("ok"),
        TestOutcome.Warn => L.T("attenzione"),
        TestOutcome.Fail => L.T("negativo"),
        TestOutcome.Skipped => L.T("saltato"),
        TestOutcome.Error => L.T("errore"),
        _ => o.ToString(),
    };
}
