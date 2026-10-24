using System.Security.Cryptography;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// Test facoltativo (v1.6, <c>AdvancedOptions.SessionIdProbe</c>) sull'adozione dell'ID di sessione: una sola GET al percorso
/// principale con un cookie <c>PHPSESSID</c> casuale appena generato (26 caratteri in [0-9a-v], il formato predefinito di PHP).
/// Se il server non riemette un PHPSESSID, o riemette lo stesso valore, ha adottato l'ID proposto: <c>session.use_strict_mode</c>
/// è spento (condizione che rende possibile la fissazione di sessione). Se emette un ID suo, strict mode è attivo.
/// Il test è una visita come un'altra: una GET con un cookie che sul server lascia al massimo ciò che lascia qualsiasi
/// visitatore (un file di sessione vuoto). Nessuna sessione di utenti viene toccata, nessun'altra richiesta viene inviata.
/// Ha senso solo se il percorso principale avvia una sessione (la risposta di riferimento porta un Set-Cookie PHPSESSID):
/// altrimenti l'esito è "non applicabile" (<see cref="ScanResult.SessionIdAdopted"/> = null).
/// </summary>
public static class SessionProbe
{
    public const string TestId = "ADV-SESSIONID";
    private static readonly Regex SessIdRx = new(@"^\s*PHPSESSID=([^;]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private const string Alphabet = "0123456789abcdefghijklmnopqrstuv";

    /// <summary>Genera un ID di sessione nel formato predefinito di PHP (26 caratteri, 5 bit ciascuno).</summary>
    public static string NewSessionId()
    {
        var bytes = RandomNumberGenerator.GetBytes(26);
        var chars = new char[26];
        for (int i = 0; i < 26; i++) chars[i] = Alphabet[bytes[i] & 0x1F];
        return new string(chars);
    }

    /// <summary>Valore del cookie PHPSESSID emesso dalla risposta, null se nessuno.</summary>
    public static string? IssuedSessionId(HttpSnapshot? snap)
    {
        if (snap == null) return null;
        foreach (var c in snap.HeaderValues("Set-Cookie"))
        {
            var m = SessIdRx.Match(c);
            if (m.Success) return m.Groups[1].Value.Trim();
        }
        return null;
    }

    /// <summary>Esegue il test quando è abilitato e il servizio risponde HTTP; una sola GET, con il cookie proposto.</summary>
    public static async Task RunAsync(ScanContext ctx)
    {
        var r = ctx.Result;
        if (!ctx.Config.Advanced.SessionIdProbe || !r.HttpReachable) return;
        string name = L.T("Adozione dell'ID di sessione");

        if (IssuedSessionId(ctx.Baseline) == null)
        {
            r.SessionIdAdopted = null;
            r.SessionIdDetail = L.T("il percorso principale non avvia una sessione: test non applicabile");
            r.Add(TestId, name, TestOutcome.Info, r.SessionIdDetail);
            return;
        }

        string id = NewSessionId();
        var snap = await ctx.GetAsync(ctx.PrimaryPath, [new KeyValuePair<string, string>("Cookie", "PHPSESSID=" + id)]).ConfigureAwait(false);
        if (!snap.HasResponse)
        {
            r.SessionIdAdopted = null;
            r.SessionIdDetail = L.F("nessuna risposta alla GET con il cookie proposto ({0}): test non concluso", snap.Error ?? "");
            r.Add(TestId, name, TestOutcome.Warn, r.SessionIdDetail, snap);
            return;
        }

        string? issued = IssuedSessionId(snap);
        if (issued == null && !r.PhpDetected)
        {
            r.SessionIdAdopted = null;
            r.SessionIdDetail = L.T("nessun cookie di sessione PHP: test non applicabile");
            r.Add(TestId, name, TestOutcome.Info, r.SessionIdDetail, snap);
            return;
        }
        if (issued == null || issued.Equals(id, StringComparison.Ordinal))
        {
            r.SessionIdAdopted = true;
            r.SessionIdDetail = L.T("ID di sessione proposto adottato dal server: session.use_strict_mode spento (o nessuna sessione avviata su questo percorso)");
            r.Add(TestId, name, TestOutcome.Warn, r.SessionIdDetail, snap);
            return;
        }
        r.SessionIdAdopted = false;
        r.SessionIdDetail = L.T("il server ha emesso un proprio ID: session.use_strict_mode attivo");
        r.Add(TestId, name, TestOutcome.Info, r.SessionIdDetail, snap);
    }
}
