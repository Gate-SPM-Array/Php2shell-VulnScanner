using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// Livello 1, passivo: richieste GET sui percorsi configurati e lettura di ciò che il server dichiara da solo
/// (X-Powered-By, Server, cookie PHPSESSID, messaggi di errore PHP nel corpo), più le pagine rivelatrici e
/// l'easter egg se abilitati. Nessuna scrittura, nessun corpo di richiesta.
/// </summary>
public static class PhpFingerprint
{
    public static readonly string[] InfoPages = ["/phpinfo.php", "/info.php", "/php.php", "/test.php"];
    public const string EasterEggQuery = "?=PHPE9568F34-D428-11d2-A769-00AA001ACF42";

    private static readonly Regex PhpErrorRx = new(@"(Fatal error|Warning|Notice|Parse error|Deprecated)</b>?:\s.*? in <b>?[^<\n]+\.php</b>? on line", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex PhpInfoRx = new(@"PHP Version\s*(?:</[^>]+>\s*)?(?:<[^>]+>\s*)*(\d+\.\d+\.\d+[A-Za-z0-9~+._-]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex PhpSessidRx = new(@"(?:^|;\s*)(PHPSESSID|PHPSESSION|sid|session)=([^;]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static async Task RunAsync(ScanContext ctx)
    {
        var r = ctx.Result;
        var snaps = new List<(string Path, HttpSnapshot Snap)>();
        foreach (var path in ctx.Paths)
        {
            HttpSnapshot s;
            if (ctx.Config.LightMode)
            {
                s = await ctx.HeadAsync(path).ConfigureAwait(false);
                if (s.HasResponse && s.Status is 405 or 501) s = await ctx.GetAsync(path).ConfigureAwait(false);
            }
            else s = await ctx.GetAsync(path).ConfigureAwait(false);
            snaps.Add((path, s));
            r.Add("L1-GET", L.F("{0} {1}", s.Method, path), s.HasResponse ? TestOutcome.Info : TestOutcome.Error,
                s.HasResponse ? DescribeHeaders(s) : s.Error ?? "", s);
            if (s.HasResponse && ctx.Baseline == null) { ctx.Baseline = s; ctx.PrimaryPath = path; }
            if (!s.HasResponse && s.ErrorKind is "connect" or "tls" or "dns") break;   // inutile insistere sugli altri percorsi
        }

        r.HttpReachable = ctx.Baseline != null;
        if (!r.HttpReachable)
        {
            r.Error = snaps.Count > 0 ? snaps[0].Snap.Error ?? "" : "";
            return;
        }

        // Intestazioni dichiarate
        foreach (var (_, s) in snaps.Where(x => x.Snap.HasResponse))
        {
            string? server = s.Header("Server");
            if (!string.IsNullOrEmpty(server) && r.ServerHeader.Length == 0) r.ServerHeader = server;
            string? pb = s.Header("X-Powered-By");
            if (!string.IsNullOrEmpty(pb) && r.PoweredBy.Length == 0) r.PoweredBy = pb;
        }

        var evidence = new List<string>();
        void Evidence(string e) { if (!evidence.Contains(e, StringComparer.Ordinal)) evidence.Add(e); }   // lo stesso indizio da più percorsi conta una volta
        PhpVersion? version = null;
        string source = "";

        // 1) X-Powered-By: PHP/x.y.z (fonte più diretta: lo scrive PHP stesso con expose_php=On)
        foreach (var (_, s) in snaps.Where(x => x.Snap.HasResponse))
        {
            foreach (var v in s.HeaderValues("X-Powered-By"))
            {
                if (!v.Contains("PHP", StringComparison.OrdinalIgnoreCase)) continue;
                Evidence("X-Powered-By: " + v);
                if (version == null && PhpVersion.Parse(v) is { } pv) { version = pv; source = "X-Powered-By"; }
            }
        }
        // 2) Server: Apache/2.4 (…) PHP/x.y.z (mod_php con ServerTokens Full)
        foreach (var (_, s) in snaps.Where(x => x.Snap.HasResponse))
        {
            string? server = s.Header("Server");
            if (server != null && Regex.IsMatch(server, @"PHP/\d", RegexOptions.IgnoreCase))
            {
                Evidence("Server: " + server);
                if (version == null && PhpVersion.Parse(server) is { } pv) { version = pv; source = "Server"; }
                break;
            }
        }
        // 3) Cookie di sessione
        foreach (var (_, s) in snaps.Where(x => x.Snap.HasResponse))
        {
            foreach (var c in s.HeaderValues("Set-Cookie"))
            {
                var m = Regex.Match(c, @"^\s*(PHPSESSID)=([^;]*)", RegexOptions.IgnoreCase);
                if (!m.Success) continue;
                r.SessionCookie = m.Groups[2].Value;
                Evidence("Set-Cookie: PHPSESSID");
                r.Add("L1-SESSID", L.T("Cookie di sessione PHPSESSID"), SidLooksNormal(r.SessionCookie) ? TestOutcome.Info : TestOutcome.Warn,
                    SidLooksNormal(r.SessionCookie)
                        ? L.F("formato regolare ({0} caratteri): sessioni PHP attive su questa pagina", r.SessionCookie.Length)
                        : L.F("formato ANOMALO ({0} caratteri): un SID irregolare è tra gli indicatori di lettura di memoria citati da Wiz e Blevene", r.SessionCookie.Length));
                break;
            }
            if (r.SessionCookie.Length > 0) break;
        }
        // 4) Messaggi di errore PHP nel corpo (display_errors attivo)
        foreach (var (path, s) in snaps.Where(x => x.Snap.HasResponse))
        {
            var m = PhpErrorRx.Match(s.Body);
            if (m.Success)
            {
                Evidence(L.F("messaggio di errore PHP nel corpo di {0}", path));
                r.Add("L1-ERRORS", L.T("Errori PHP visibili nel corpo"), TestOutcome.Warn,
                    L.T("display_errors è attivo: i warning dei percorsi preliminari sono il \"consumer\" descritto nell'avviso PHP per CVE-2026-109619") + " (" + Short(m.Value) + ")");
                break;
            }
        }
        // 5) Percorsi .php che rispondono 200: indizio debole (anche un server statico o un proxy può servire index.php), non basta da solo
        var weak = new List<string>();
        foreach (var (path, s) in snaps.Where(x => x.Snap.HasResponse && x.Path.EndsWith(".php", StringComparison.OrdinalIgnoreCase)))
            if (s.Status is >= 200 and < 400) weak.Add(L.F("{0} risponde {1}", path, s.Status));

        // Pagine rivelatrici (phpinfo e simili): solo lettura, contano solo se il corpo è davvero un phpinfo
        if (ctx.Config.Level1InfoPages)
        {
            foreach (var page in InfoPages)
            {
                ctx.Ct.ThrowIfCancellationRequested();
                var s = await ctx.GetAsync(page).ConfigureAwait(false);
                if (!s.HasResponse) { if (s.ErrorKind is "connect" or "tls") break; continue; }
                if (s.Status != 200) continue;
                var m = PhpInfoRx.Match(s.Body);
                bool isInfo = m.Success || s.Body.Contains("phpinfo()", StringComparison.OrdinalIgnoreCase) || s.Body.Contains("PHP License", StringComparison.Ordinal);
                if (!isInfo) continue;
                Evidence(L.F("pagina phpinfo esposta: {0}", page));
                if (m.Success && version == null && PhpVersion.Parse(m.Groups[1].Value) is { } pv) { version = pv; source = page; }
                r.Add("L1-PHPINFO", L.T("Pagina phpinfo esposta"), TestOutcome.Fail,
                    L.F("{0} mostra la configurazione completa di PHP{1}: da rimuovere o bloccare al proxy", page, m.Success ? " (" + m.Groups[1].Value + ")" : ""), s);
                PhpInfoParser.Apply(r);   // v1.5: impostazioni (session.upload_progress, serialize_handler, Server API…) dalla pagina già scaricata
                break;
            }
        }

        // Easter egg: le installazioni precedenti a PHP 5.5 con expose_php=On rispondono con un'immagine
        if (ctx.Config.Level1EasterEgg)
        {
            var s = await ctx.GetAsync(ctx.PrimaryPath + EasterEggQuery).ConfigureAwait(false);
            if (s.HasResponse)
            {
                string ctype = s.Header("Content-Type") ?? "";
                bool egg = s.Status == 200 && ctype.StartsWith("image/", StringComparison.OrdinalIgnoreCase);
                if (egg)
                {
                    Evidence(L.T("easter egg PHP attivo (PHP < 5.5)"));
                    r.Add("L1-EGG", L.T("Easter egg di PHP"), TestOutcome.Fail, L.T("risposta con immagine: PHP precedente alla 5.5 con expose_php attivo, ramo fuori da ogni supporto"), s);
                    version ??= new PhpVersion(5, 4, -1, "< 5.5 (easter egg)", "");
                    if (source.Length == 0) source = L.T("easter egg");
                }
                else r.Add("L1-EGG", L.T("Easter egg di PHP"), TestOutcome.Info, L.F("nessuna immagine ({0}): PHP >= 5.5 o expose_php disattivo", s.Status), s);
            }
        }

        // Scoperta della superficie PHP (sonda del file inesistente, punti di ingresso, link): solo HEAD/GET
        // Un errore nella scoperta della superficie non deve cancellare le deduzioni passive che seguono (lezione della v1.3)
        if (ctx.Config.SurfaceDiscovery)
        {
            try
            {
                ctx.SurfacePhpPaths = await SurfaceDiscovery.RunAsync(ctx).ConfigureAwait(false);
                if (r.PhpSurfaceProbe.Length > 0)
                    Evidence(L.F("file .php inesistente gestito da PHP ({0})", Labels.Sapi(r.Sapi)));
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { r.Add("L1-SURFACE", L.T("Superficie PHP scoperta"), TestOutcome.Error, L.F("scoperta della superficie non completata: {0}", ex.GetBaseException().Message)); }
        }

        // Deduzioni passive su SAPI, sistema operativo e applicazione (nessuna richiesta in più)
        StackFingerprint.Apply(r, snaps.Select(x => x.Snap).ToList());
        if (r.SapiEvidence.Length > 0)
            r.Add("L1-SAPI", L.T("SAPI dedotta"), r.Sapi == "mod_php" ? TestOutcome.Warn : TestOutcome.Info,
                (r.Sapi.Length > 0 ? r.Sapi + ": " : "") + r.SapiEvidence + (r.Sapi == "mod_php" ? " " + L.T("(caso a rischio massimo secondo l'avviso PHP: esecuzione prima del codice applicativo)") : ""));
        if (r.OsHint.Length > 0)
            r.Add("L1-OS", L.T("Sistema operativo dichiarato"), TestOutcome.Info, r.OsHint + " " + L.T("(orienta la verifica dei backport di distribuzione)"));
        if (r.Application.Length > 0)
        {
            Evidence(L.F("applicazione PHP riconosciuta: {0}", r.Application));
            r.Add("L1-APP", L.T("Applicazione riconosciuta"), TestOutcome.Info, L.F("{0} ({1}); inventario NCSC-NL: {2}", r.Application, r.ApplicationEvidence, r.ApplicationReference));
        }

        r.PhpDetected = evidence.Count > 0;
        r.PhpEvidence = string.Join("; ", evidence.Count > 0 ? evidence.Concat(weak) : weak.Select(w => w + " " + L.T("(indizio debole)")));
        if (version != null)
        {
            r.PhpVersionRaw = version.Raw;
            r.PhpVersionSource = source;
            r.VersionStatus = version.Status();
            r.FixedRelease = version.FixedRelease ?? "";
            r.PackageSuffix = version.HasPackageSuffix;
            var outcome = version.Status() switch
            {
                VersionStatus.Fixed => TestOutcome.Pass,
                VersionStatus.Newer => TestOutcome.Pass,
                VersionStatus.VulnerableSupported => TestOutcome.Fail,
                VersionStatus.EndOfLife => TestOutcome.Fail,
                VersionStatus.Ancient => TestOutcome.Warn,
                _ => TestOutcome.Info,
            };
            string detail = version.Status() switch
            {
                VersionStatus.Fixed => L.F("{0} è uguale o successiva alla correzione {1}", version.Normalized, version.FixedRelease),
                VersionStatus.Newer => L.F("{0}: ramo nato dopo la correzione", version.Normalized),
                VersionStatus.VulnerableSupported => L.F("{0} precede la correzione {1} del suo ramo", version.Raw, version.FixedRelease),
                VersionStatus.EndOfLife => L.F("{0}: ramo fuori supporto, vulnerabile per versione; i backport di distribuzione (Debian, RHEL, Plesk, Sury) non cambiano il numero", version.Raw),
                VersionStatus.Ancient => L.F("{0}: precedente a PHP 5.4, fuori dall'intervallo indicato dalle fonti ma fuori da ogni supporto", version.Raw),
                _ => version.Raw,
            };
            if (version.HasPackageSuffix) detail += " " + L.F("(suffisso di pacchetto \"{0}\": verificare il changelog del pacchetto)", version.Suffix);
            r.Add("L1-VERSION", L.F("Versione PHP dichiarata ({0})", source), outcome, detail);
        }
        else
        {
            r.Add("L1-VERSION", L.T("Versione PHP dichiarata"), r.PhpDetected ? TestOutcome.Warn : TestOutcome.Info,
                r.PhpDetected ? L.T("PHP rilevato ma nessuna versione dichiarata (expose_php=Off o header rimosso al proxy)") : L.T("nessun indizio di PHP nelle risposte"));
        }

        // v1.5: indizi passivi e presenza a tre valori (yes/maybe/no), da ciò che è già stato raccolto; idempotente
        PhpHints.Compute(r);
    }

    /// <summary>Il SID di PHP ha 22…256 caratteri in [0-9a-zA-Z,-] (session.sid_length, sid_bits_per_character).</summary>
    public static bool SidLooksNormal(string sid) =>
        sid.Length is >= 22 and <= 256 && sid.All(c => char.IsAsciiLetterOrDigit(c) || c == ',' || c == '-');

    private static string DescribeHeaders(HttpSnapshot s)
    {
        var parts = new List<string> { $"{s.Status} {s.Reason}".Trim() };
        foreach (var name in new[] { "Server", "X-Powered-By", "Content-Type", "Location" })
        {
            var v = s.Header(name);
            if (!string.IsNullOrEmpty(v)) parts.Add($"{name}: {Short(v)}");
        }
        if (s.HeaderValues("Set-Cookie").Any()) parts.Add("Set-Cookie: " + string.Join(", ", s.HeaderValues("Set-Cookie").Select(c => c.Split('=')[0])));
        return string.Join("; ", parts);
    }

    private static string Short(string v) => v.Length <= 100 ? v : v[..97] + "...";
}
