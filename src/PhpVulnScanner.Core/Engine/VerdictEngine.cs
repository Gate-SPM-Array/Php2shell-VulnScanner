using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Php;

namespace PhpVulnScanner.Core.Engine;

/// <summary>
/// Regole di verdetto, nell'ordine. Ogni verdetto porta la motivazione con l'evidenza (P-024).
/// 1. Non raggiungibile: alive check negativo (se vincolante) o nessuna risposta HTTP.
/// 2. Mitigato al perimetro: barriera multipart completa (anche con versione vulnerabile dichiarata: il tampone c'è, la correzione no).
/// 3. Versione dichiarata: corretta / vulnerabile (ramo supportato) / probabilmente vulnerabile (ramo fuori supporto, backport non escludibile).
/// 4. PHP rilevato senza versione: non determinabile (nessun test esterno distingue un PHP corretto da uno vulnerabile).
/// 5. Nessun indizio di PHP: PHP non rilevato.
/// </summary>
public static class VerdictEngine
{
    /// <summary>
    /// v1.4: su un ramo fuori supporto un numero "puro" (senza suffisso di distribuzione, es. 7.4.33) viene da una build upstream
    /// (compilata, immagine ufficiale): nessun distributore può aver fatto backport, quindi il numero dice tutto → "Vulnerabile per versione".
    /// Con suffisso (7.4.3-4ubuntu2.29) il backport è possibile → "Probabilmente vulnerabile". Impostato dal motore da ScanConfig.PureVersionIsVulnerable.
    /// </summary>
    public static bool PureVersionIsVulnerable { get; set; } = true;

    public static void Apply(ScanResult r)
    {
        Decide(r);
        r.Priority = Prioritize(r);
        PhpHints.Compute(r);   // v1.5: ricalcolo dopo i test avanzati (esposizioni, tecnologie) e le copie a livello di host
        Verbosity.Compute(r);   // v1.5: indice di loquacità, dopo le sonde avanzate (idempotente)
        Net.CertificateStatus.Apply(r);   // v1.6: stato del certificato da r.Tls (idempotente)
    }

    /// <summary>
    /// Priorità di remediation, derivata (non è un verdetto): Critica = versione vulnerabile o probabilmente vulnerabile con mod_php
    /// e multipart che raggiunge PHP; Alta = versione vulnerabile con altra SAPI o SAPI ignota; Media = mitigato al perimetro con
    /// versione vulnerabile, oppure non determinabile con multipart accettato; Bassa = non determinabile dietro barriera, corretto con
    /// barriera aggirabile; Nessuna = corretto, PHP assente, non raggiungibile.
    /// </summary>
    public static Priority Prioritize(ScanResult r)
    {
        bool vulnerable = r.Verdict is Verdict.VulnerableByVersion or Verdict.LikelyVulnerable;
        bool reaches = r.Multipart is MultipartBarrier.Accepted or MultipartBarrier.PartiallyBlocked or MultipartBarrier.NotTested or MultipartBarrier.NoResponse;
        if (vulnerable && r.Sapi == "mod_php" && reaches) return Priority.Critical;
        if (vulnerable) return Priority.High;
        if (r.Verdict == Verdict.MitigatedAtEdge)
            return r.VersionStatus is VersionStatus.VulnerableSupported or VersionStatus.EndOfLife or VersionStatus.Ancient ? Priority.Medium : Priority.Low;
        if (r.Verdict == Verdict.Undetermined) return reaches ? Priority.Medium : Priority.Low;
        if (r.Verdict == Verdict.FixedByVersion) return r.Multipart == MultipartBarrier.PartiallyBlocked ? Priority.Low : Priority.None;
        return Priority.None;
    }

    private static void Decide(ScanResult r)
    {
        if (!r.HttpReachable)
        {
            r.Verdict = Verdict.NotReachable;
            r.VerdictReason = r.Alive == AliveState.NoResponse
                ? L.F("alive check senza risposta ({0})", r.AliveDetails)
                : L.F("nessuna risposta HTTP su {0}/{1}{2}", r.Port, r.Scheme, r.Error.Length > 0 ? ": " + r.Error : "");
            return;
        }

        bool phpByVersion = r.VersionStatus != VersionStatus.Unknown;
        string versionNote = r.VersionStatus switch
        {
            VersionStatus.VulnerableSupported => L.F("versione dichiarata {0} precedente alla correzione {1}", r.PhpVersionRaw, r.FixedRelease),
            VersionStatus.EndOfLife => L.F("versione dichiarata {0} di un ramo fuori supporto", r.PhpVersionRaw),
            VersionStatus.Ancient => L.F("versione dichiarata {0}, precedente a PHP 5.4", r.PhpVersionRaw),
            VersionStatus.Fixed => L.F("versione dichiarata {0}, uguale o successiva alla correzione {1}", r.PhpVersionRaw, r.FixedRelease),
            VersionStatus.Newer => L.F("versione dichiarata {0}, ramo nato dopo la correzione", r.PhpVersionRaw),
            _ => "",
        };

        if (r.Multipart == MultipartBarrier.Blocked && (r.PhpDetected || phpByVersion))
        {
            r.Verdict = Verdict.MitigatedAtEdge;
            r.VerdictReason = L.F("le richieste multipart non raggiungono PHP ({0}). È un tampone, non una correzione", r.MultipartDetail);
            if (r.VersionStatus is VersionStatus.VulnerableSupported or VersionStatus.EndOfLife or VersionStatus.Ancient)
                r.VerdictReason += "; " + versionNote + " " + L.T("(aggiornamento comunque necessario)");
            return;
        }
        if (r.Multipart == MultipartBarrier.PostNotAllowed && (r.PhpDetected || phpByVersion) && r.VersionStatus is not (VersionStatus.VulnerableSupported or VersionStatus.EndOfLife or VersionStatus.Ancient))
        {
            r.Verdict = phpByVersion ? Verdict.FixedByVersion : Verdict.Undetermined;
            r.VerdictReason = L.F("POST non consentito sul percorso sondato ({0}); solo il percorso sondato, altri percorsi possono accettare POST", r.MultipartDetail);
            if (phpByVersion) r.VerdictReason = versionNote + "; " + r.VerdictReason;
            return;
        }

        switch (r.VersionStatus)
        {
            case VersionStatus.Fixed:
            case VersionStatus.Newer:
                r.Verdict = Verdict.FixedByVersion;
                r.VerdictReason = versionNote + " " + L.F("(fonte: {0})", r.PhpVersionSource);
                if (r.Multipart == MultipartBarrier.PartiallyBlocked) r.VerdictReason += "; " + L.T("la barriera multipart è aggirabile, da sistemare comunque");
                return;
            case VersionStatus.VulnerableSupported:
                r.Verdict = Verdict.VulnerableByVersion;
                r.VerdictReason = versionNote + " " + L.F("(fonte: {0})", r.PhpVersionSource);
                if (r.PackageSuffix) r.VerdictReason += "; " + L.T("suffisso di pacchetto presente: possibile backport, verificare il changelog sull'host");
                AppendBarrier(r);
                return;
            case VersionStatus.EndOfLife:
            case VersionStatus.Ancient:
                if (PureVersionIsVulnerable && !r.PackageSuffix)
                {
                    r.Verdict = Verdict.VulnerableByVersion;
                    r.VerdictReason = versionNote + " " + L.F("(fonte: {0})", r.PhpVersionSource) + "; " + L.T("numero puro senza suffisso di distribuzione: build upstream, nessun backport possibile, la versione dice tutto");
                    AppendBarrier(r);
                    return;
                }
                r.Verdict = Verdict.LikelyVulnerable;
                r.VerdictReason = versionNote + " " + L.F("(fonte: {0})", r.PhpVersionSource) + "; " + L.T("backport di distribuzione non escludibile dal numero: verificare sull'host");
                AppendBarrier(r);
                return;
        }

        if (r.PhpDetected)
        {
            r.Verdict = Verdict.Undetermined;
            r.VerdictReason = L.F("PHP rilevato ({0}) ma versione non dichiarata: dall'esterno non si distingue un PHP corretto da uno vulnerabile", r.PhpEvidence);
            AppendBarrier(r);
            return;
        }

        r.Verdict = Verdict.NoPhpDetected;
        r.VerdictReason = r.ServerHeader.Length > 0
            ? L.F("nessun indizio di PHP (Server: {0}); se PHP è dietro un proxy che toglie le intestazioni, servono verifiche sull'host", r.ServerHeader)
            : L.T("nessun indizio di PHP nelle risposte; se PHP è dietro un proxy che toglie le intestazioni, servono verifiche sull'host");
    }

    private static void AppendBarrier(ScanResult r)
    {
        switch (r.Multipart)
        {
            case MultipartBarrier.Accepted: r.VerdictReason += "; " + L.T("multipart accettato: il vettore raggiunge PHP"); break;
            case MultipartBarrier.PartiallyBlocked: r.VerdictReason += "; " + L.T("barriera multipart presente ma aggirabile"); break;
            case MultipartBarrier.NoResponse: r.VerdictReason += "; " + L.T("POST senza risposta: barriera non classificabile"); break;
        }
    }
}
