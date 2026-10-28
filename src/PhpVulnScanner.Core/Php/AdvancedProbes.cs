using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using PhpVulnScanner.Core.Apps;
using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;
using PhpVulnScanner.Core.Targets;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// Sezione "Avanzate" (v1.4): test aggiuntivi in sola lettura, uno per casella di <see cref="AdvancedOptions"/>.
/// <see cref="RunAsync"/> lavora sul servizio HTTP già raggiunto (dopo il livello 1 e la scoperta della superficie);
/// <see cref="RunHostLevelAsync"/> esegue le sonde per host che non passano da HTTP (FastCGI sulla 9000, PTR, crt.sh).
/// Regole: solo GET/HEAD/OPTIONS e, per il livello 2 sugli altri percorsi, le stesse due POST minime del livello 2;
/// mai il contenuto di file sensibili (solo HEAD: esistenza), mai richieste che portino PHP in esaurimento memoria.
/// Ogni sonda cattura le proprie eccezioni (l'annullamento si propaga) e lascia una riga di evidenza "ADV-…".
/// </summary>
public static class AdvancedProbes
{
    /// <summary>User-Agent del secondo giro: da browser, ma con il nome dello strumento in coda (uso responsabile: la sorgente resta riconoscibile nei log).</summary>
    public static string BrowserUserAgent => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36 PhpVulnScanner/" + HttpProbe.AppVersion;

    /// <summary>Porta della sonda FastCGI (9000; modificabile solo per i test).</summary>
    public static int FastCgiPort { get; set; } = FastCgiProbe.DefaultPort;
    public const int FastCgiTimeoutMs = 2000;
    public const int PtrTimeoutMs = 3000;
    public const int MaxLibraries = 50;
    public const int MaxComponents = 60;
    public const int MaxCtDomains = 3;
    public const int MaxCtNames = 50;

    public static readonly string[] ExtraInfoPages = ["/i.php", "/pi.php", "/phpversion.php", "/info1.php", "/phpinfo1.php", "/test1.php"];
    public static readonly string[] SourceSuffixes = ["s", "~", ".bak", ".save", ".orig"];
    public static readonly string[] FpmStatusPages = ["/status", "/fpm-status", "/php-fpm/status"];

    private static readonly Regex PhpInfoRx = new(@"PHP Version\s*(?:</[^>]+>\s*)?(?:<[^>]+>\s*)*(\d+\.\d+\.\d+[A-Za-z0-9~+._-]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex PhpErrorRx = new(@"(Fatal error|Warning|Notice|Parse error|Deprecated)</b>?:\s.*? in <b>?[^<\n]+\.php</b>? on line", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex ApacheModuleRx = new(@"\b([a-z][a-z0-9_]*)\.c\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex ApacheAddressRx = new(@"<address>[^<]*?Server at ([A-Za-z0-9.-]+) Port \d+\s*</address>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex TitleRx = new(@"<title[^>]*>\s*([^<]{0,120})", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex RandomProbeRx = new(@"/pvs[0-9a-f]{12}\.php$", RegexOptions.CultureInvariant);

    // componenti (nessuna richiesta: solo i corpi già scaricati)
    private static readonly Regex WpComponentRx = new(@"/wp-content/(plugins|themes)/([A-Za-z0-9_.-]+)/([^""'\s<>()]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex VerRx = new(@"[?&]ver=([0-9][A-Za-z0-9._-]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex JoomlaOptionRx = new(@"option=com_([a-z0-9_]+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex JoomlaPathRx = new(@"/(?:components|media)/com_([a-z0-9_]+)/", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex DrupalModuleRx = new(@"/(?:modules/(?:contrib|custom)|sites/all/modules)/([A-Za-z0-9_-]+)/", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Typo3ExtRx = new(@"/typo3conf/ext/([A-Za-z0-9_-]+)/", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    /// <summary>Stato condiviso tra le sonde di un bersaglio: server catch-all, stato della 404, connessione persa.</summary>
    private sealed class State
    {
        public bool CatchAll;
        public int MissStatus = -1;
        public bool ConnectionLost;
    }

    // =====================================================================================================================
    // Sonde HTTP (per servizio)
    // =====================================================================================================================

    /// <summary>Esegue i test avanzati abilitati sul servizio HTTP del contesto. Da chiamare dopo il livello 1 (e la scoperta della superficie) quando <c>Result.HttpReachable</c> è vero.</summary>
    public static async Task RunAsync(ScanContext ctx)
    {
        var o = ctx.Config.Advanced;
        var r = ctx.Result;
        if (!r.HttpReachable) return;
        var st = new State();
        bool pathProbes = o.Composer || o.StatusPages || o.AppVersionFiles || o.PhpBehaviours || o.Level2AllPaths || o.BrowserUserAgent || o.Exposures;
        if (pathProbes)
            await Step(ctx, "ADV-CATCHALL", L.T("Riferimento per i percorsi inesistenti"), c => CatchAllAsync(c, st)).ConfigureAwait(false);

        // v1.6: backend morto o solo gateway (stesso 5xx su /, /index.php e file inesistente): le sonde su percorso riceverebbero
        // tutte la stessa pagina di errore; restano HEAD/OPTIONS (economiche) e le analisi senza richieste
        if (pathProbes && IsCatchAllServerError(ctx))
        {
            int status = st.MissStatus > 0 ? st.MissStatus : ctx.Baseline?.Status ?? 0;
            r.Add("ADV-SKIP", L.T("Sonde su percorso"), TestOutcome.Info, L.F("sonde su percorso saltate: il server risponde {0} a qualunque percorso", status));
            pathProbes = false;
        }

        // v1.6: ogni gruppo di sonde controlla il budget di tempo del servizio; i gruppi senza richieste (componenti, ServerName) costano nulla e restano
        async Task Budgeted(string id, string name, Func<ScanContext, Task> probe)
        {
            if (ctx.OverBudget) { r.SkippedForBudget.Add(name); return; }
            await Step(ctx, id, name, probe).ConfigureAwait(false);
        }

        if (o.HeadVsGet) await Budgeted("ADV-HEAD", L.T("HEAD contro GET"), c => HeadVsGetAsync(c, st)).ConfigureAwait(false);
        if (pathProbes && o.Composer) await Budgeted("ADV-COMPOSER", L.T("Composer"), c => ComposerAsync(c, st)).ConfigureAwait(false);
        if (pathProbes && o.StatusPages) await Budgeted("ADV-STATUS", L.T("Pagine di stato"), c => StatusPagesAsync(c, st)).ConfigureAwait(false);
        if (pathProbes && o.AppVersionFiles) await Budgeted("ADV-APPVERSION", L.T("File di versione dell'applicazione"), c => AppVersionFilesAsync(c, st)).ConfigureAwait(false);
        if (pathProbes && o.PhpBehaviours) await Budgeted("ADV-BEHAVIOURS", L.T("Comportamenti tipici di PHP"), c => PhpBehavioursAsync(c, st)).ConfigureAwait(false);
        if (pathProbes && o.Level2AllPaths) await Budgeted("ADV-L2-ALL", L.T("Livello 2 sugli altri percorsi"), c => Level2AllPathsAsync(c, st)).ConfigureAwait(false);
        if (pathProbes && o.BrowserUserAgent) await Budgeted("ADV-BROWSERUA", L.T("Secondo giro con User-Agent da browser"), c => BrowserUserAgentAsync(c, st)).ConfigureAwait(false);
        if (o.Components) await Step(ctx, "ADV-COMPONENTS", L.T("Componenti dell'applicazione"), ComponentsAsync).ConfigureAwait(false);
        if (pathProbes && o.Exposures) await Budgeted("ADV-EXPOSURES", L.T("Esposizioni accessorie"), c => ExposuresAsync(c, st)).ConfigureAwait(false);
        if (o.ReverseDns) await Step(ctx, "ADV-SERVERNAME", L.T("ServerName nelle pagine di errore di Apache"), ServerNameAsync).ConfigureAwait(false);
        if (o.SessionIdProbe) await Step(ctx, SessionProbe.TestId, L.T("Adozione dell'ID di sessione"), SessionProbe.RunAsync).ConfigureAwait(false);   // v1.6
    }

    /// <summary>
    /// Vero (v1.6) quando il file .php inesistente (sonda della superficie o di <see cref="CatchAllAsync"/>) e le pagine configurate rispondono
    /// con lo stesso 5xx: regola di <see cref="SurfaceDiscovery.IsServerErrorEverywhere"/>, sulle risposte già in <c>Result.Requests</c>.
    /// Un host 200 normale non è toccato (la regola richiede uno stato ≥ 500 ovunque).
    /// </summary>
    public static bool IsCatchAllServerError(ScanContext ctx)
    {
        var miss = ctx.Result.Requests.FirstOrDefault(q => q.Method == "GET" && q.HasResponse && RandomProbeRx.IsMatch(PathOf(q.Url)));
        return miss != null && SurfaceDiscovery.IsServerErrorEverywhere(miss, SurfaceDiscovery.PageSnapshots(ctx));
    }

    private static async Task Step(ScanContext ctx, string id, string name, Func<ScanContext, Task> probe)
    {
        try { await probe(ctx).ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            ctx.Result.Add(id, name, TestOutcome.Error, L.F("errore interno della sonda: {0}", ex.GetBaseException().Message));
            ctx.Log(L.F("{0}: {1} — errore {2}", ctx.Endpoint, name, ex.GetBaseException().Message));
        }
    }

    // ---- riferimento: come risponde il server a un percorso inesistente --------------------------------------------------

    private static async Task CatchAllAsync(ScanContext ctx, State st)
    {
        // la scoperta della superficie ha già chiesto un .php casuale: si riusa quella risposta, altrimenti se ne chiede una
        var prev = ctx.Result.Requests.FirstOrDefault(q => q.Method == "GET" && RandomProbeRx.IsMatch(PathOf(q.Url)));
        if (prev == null)
        {
            Span<byte> b = stackalloc byte[6];
            RandomNumberGenerator.Fill(b);
            prev = await ctx.GetAsync("/pvs" + Convert.ToHexString(b).ToLowerInvariant() + ".php").ConfigureAwait(false);
            if (Lost(prev, st)) return;
        }
        if (!prev.HasResponse) return;
        st.MissStatus = prev.Status;
        var kind = SurfaceDiscovery.ClassifyMissingPhp(prev);
        st.CatchAll = kind is SurfaceDiscovery.MissingFileKind.CatchAll or SurfaceDiscovery.MissingFileKind.RedirectAll or SurfaceDiscovery.MissingFileKind.ForbiddenAll
            || SurfaceDiscovery.IsServerErrorEverywhere(prev, SurfaceDiscovery.PageSnapshots(ctx));
    }

    // ---- 1. HEAD contro GET, OPTIONS -------------------------------------------------------------------------------------

    private static async Task HeadVsGetAsync(ScanContext ctx, State st)
    {
        var r = ctx.Result;
        var b = ctx.Baseline;
        string path = ctx.PrimaryPath;

        var head = await ctx.HeadAsync(path).ConfigureAwait(false);
        if (!head.HasResponse)
        {
            r.HeadVsGet = L.F("HEAD senza risposta ({0})", head.Error);
            r.Add("ADV-HEAD", L.T("HEAD contro GET"), TestOutcome.Warn, r.HeadVsGet, head);
            if (Lost(head, st)) return;
        }
        else if (b == null || !b.HasResponse)
        {
            r.HeadVsGet = L.F("HEAD {0}, nessuna GET di riferimento", head.Status);
            r.Add("ADV-HEAD", L.T("HEAD contro GET"), TestOutcome.Info, r.HeadVsGet, head);
        }
        else
        {
            var diffs = new List<string>();
            if (head.Status != b.Status)
                diffs.Add(head.Status is 405 or 501
                    ? L.F("HEAD non consentito ({0}) mentre GET risponde {1}", head.Status, b.Status)
                    : L.F("stato {0} su HEAD contro {1} su GET", head.Status, b.Status));
            foreach (var h in new[] { "Server", "X-Powered-By", "Content-Type" })
            {
                string hv = head.Header(h) ?? "", bv = b.Header(h) ?? "";
                if (!hv.Equals(bv, StringComparison.Ordinal)) diffs.Add(L.F("{0} \"{1}\" su HEAD contro \"{2}\" su GET", h, Short(hv), Short(bv)));
            }
            string? hl = head.Header("Content-Length"), bl = b.Header("Content-Length");
            if (hl != null && bl != null && hl != bl) diffs.Add(L.F("Content-Length {0} su HEAD contro {1} su GET", hl, bl));
            var hc = CookieNames(head); var bc = CookieNames(b);
            if (!hc.SetEquals(bc)) diffs.Add(L.F("cookie {0} su HEAD contro {1} su GET", hc.Count == 0 ? "-" : string.Join(",", hc), bc.Count == 0 ? "-" : string.Join(",", bc)));
            r.HeadVsGet = diffs.Count == 0 ? L.T("uguali") : string.Join("; ", diffs);

            // intestazioni PHP che la GET non aveva: filtro sulle GET o cache davanti alle GET
            bool revealed = false;
            bool getHasPhpPb = b.HeaderValues("X-Powered-By").Any(v => v.Contains("PHP", StringComparison.OrdinalIgnoreCase));
            foreach (var v in head.HeaderValues("X-Powered-By").Where(v => v.Contains("PHP", StringComparison.OrdinalIgnoreCase)))
            {
                if (getHasPhpPb) break;
                revealed = true;
                AddPhpEvidence(r, "X-Powered-By (HEAD): " + v);
                if (r.PoweredBy.Length == 0) r.PoweredBy = v;
                if (SetVersion(r, PhpVersion.Parse(v), "X-Powered-By (HEAD)")) AddVersionLine(r, "X-Powered-By (HEAD)");
            }
            string hs = head.Header("Server") ?? "", bs = b.Header("Server") ?? "";
            if (Regex.IsMatch(hs, @"PHP/\d", RegexOptions.IgnoreCase) && !Regex.IsMatch(bs, @"PHP/\d", RegexOptions.IgnoreCase))
            {
                revealed = true;
                AddPhpEvidence(r, "Server (HEAD): " + hs);
                if (SetVersion(r, PhpVersion.Parse(hs), "Server (HEAD)")) AddVersionLine(r, "Server (HEAD)");
            }
            if (hc.Contains("PHPSESSID") && !bc.Contains("PHPSESSID")) { revealed = true; AddPhpEvidence(r, "Set-Cookie: PHPSESSID (HEAD)"); }

            string detail = r.HeadVsGet;
            if (revealed) detail += " — " + L.T("la HEAD rivela PHP dove la GET non lo faceva (filtro o cache solo sulle GET)");
            r.Add("ADV-HEAD", L.T("HEAD contro GET"), diffs.Count == 0 ? TestOutcome.Info : TestOutcome.Warn, detail, head);
        }

        // OPTIONS: metodi dichiarati
        var opt = await SendAsync(ctx, HttpMethod.Options, path).ConfigureAwait(false);
        if (!opt.HasResponse)
        {
            r.Add("ADV-OPTIONS", L.T("OPTIONS (metodi dichiarati)"), TestOutcome.Warn, opt.Error ?? "", opt);
            Lost(opt, st);
            return;
        }
        var allow = opt.HeaderValues("Allow").SelectMany(v => v.Split(',')).Select(m => m.Trim().ToUpperInvariant()).Where(m => m.Length > 0).Distinct().ToList();
        if (allow.Count == 0)
        {
            r.Add("ADV-OPTIONS", L.T("OPTIONS (metodi dichiarati)"), TestOutcome.Info, L.F("stato {0}, nessuna intestazione Allow", opt.Status), opt);
            return;
        }
        r.AllowedMethods = string.Join(", ", allow);
        bool trace = allow.Contains("TRACE");
        if (trace) AddExposure(r, path, opt.Status, L.T("metodo TRACE abilitato (intestazione Allow): da disattivare, consente il cross-site tracing"));
        r.Add("ADV-OPTIONS", L.T("OPTIONS (metodi dichiarati)"), trace ? TestOutcome.Warn : TestOutcome.Info,
            L.F("Allow: {0}", r.AllowedMethods) + (trace ? " — " + L.T("TRACE abilitato") : ""), opt);
    }

    // ---- 2. Composer -----------------------------------------------------------------------------------------------------

    private static async Task ComposerAsync(ScanContext ctx, State st)
    {
        var r = ctx.Result;
        if (st.ConnectionLost) return;

        var cj = await ctx.GetAsync("/composer.json").ConfigureAwait(false);
        if (Lost(cj, st)) return;
        if (cj.HasResponse && cj.Status == 200 && TryParseJson(cj.Body, out var doc) && doc != null)
        {
            using (doc)
            {
                var root = doc.RootElement;
                bool looksComposer = root.ValueKind == JsonValueKind.Object && (root.TryGetProperty("require", out _) || root.TryGetProperty("autoload", out _) || root.TryGetProperty("require-dev", out _));
                if (looksComposer)
                {
                    string name = root.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() ?? "" : "";
                    string floor = root.TryGetProperty("require", out var req) && req.ValueKind == JsonValueKind.Object && req.TryGetProperty("php", out var php) && php.ValueKind == JsonValueKind.String ? (php.GetString() ?? "").Trim() : "";
                    if (floor.Length > 0 && r.PhpVersionFloor.Length == 0) { r.PhpVersionFloor = floor; r.PhpVersionFloorSource = "/composer.json"; }
                    AddPhpEvidence(r, L.T("composer.json esposto (applicazione Composer)"));
                    AddExposure(r, "/composer.json", 200, L.T("manifest Composer pubblico: nome del progetto e dipendenze dichiarate"));
                    r.Add("ADV-COMPOSER", L.T("composer.json"), TestOutcome.Warn,
                        (name.Length > 0 ? L.F("progetto \"{0}\"; ", name) : "") + (floor.Length > 0 ? L.F("vincolo php \"{0}\" (versione minima dichiarata dall'applicazione, non quella in esecuzione)", floor) : L.T("nessun vincolo php dichiarato")), cj);
                }
                else r.Add("ADV-COMPOSER", L.T("composer.json"), TestOutcome.Info, L.T("200 ma non è un manifest Composer"), cj);
            }
        }
        else r.Add("ADV-COMPOSER", L.T("composer.json"), TestOutcome.Info, L.F("non esposto ({0})", cj.Summary), cj);

        var al = await ctx.HeadAsync("/vendor/autoload.php").ConfigureAwait(false);
        if (Lost(al, st)) return;
        if (Exists(al, st) && al.Status is 200 or 403)
        {
            AddPhpEvidence(r, L.F("/vendor/autoload.php presente ({0}): applicazione Composer", al.Status));
            if (al.Status == 200) AddExposure(r, "/vendor/autoload.php", 200, L.T("cartella vendor raggiungibile dal web"));
            r.Add("ADV-AUTOLOAD", L.T("vendor/autoload.php"), al.Status == 200 ? TestOutcome.Warn : TestOutcome.Info,
                al.Status == 200 ? L.T("200: la cartella vendor è servita dal web (prova di PHP e di Composer)") : L.T("403: presente ma protetto (prova di un'applicazione Composer)"), al);
        }

        var inst = await ctx.GetAsync("/vendor/composer/installed.json").ConfigureAwait(false);
        if (Lost(inst, st)) return;
        if (inst.HasResponse && inst.Status == 200 && TryParseJson(inst.Body, out var idoc) && idoc != null)
        {
            using (idoc)
            {
                var libs = ReadInstalledPackages(idoc.RootElement);
                if (libs.Count > 0)
                {
                    foreach (var l in libs.Take(MaxLibraries)) if (!r.Libraries.Contains(l)) r.Libraries.Add(l);
                    AddPhpEvidence(r, L.F("vendor/composer/installed.json esposto: {0} librerie PHP", libs.Count));
                    AddExposure(r, "/vendor/composer/installed.json", 200, L.F("elenco delle librerie installate con versione pubblico ({0} pacchetti)", libs.Count));
                    r.Add("ADV-INSTALLED", L.T("vendor/composer/installed.json"), TestOutcome.Fail,
                        L.F("{0} librerie con versione: {1}", libs.Count, string.Join(", ", libs.Take(8)) + (libs.Count > 8 ? " …" : "")) + (inst.BodyTruncated ? " " + L.T("(file troncato al limite di lettura)") : ""), inst);
                }
            }
        }
    }

    /// <summary>Pacchetti "nome versione" da installed.json (Composer 1: elenco; Composer 2: oggetto con "packages").</summary>
    public static List<string> ReadInstalledPackages(JsonElement root)
    {
        var list = new List<string>();
        JsonElement arr = root;
        if (root.ValueKind == JsonValueKind.Object) { if (!root.TryGetProperty("packages", out arr)) return list; }
        if (arr.ValueKind != JsonValueKind.Array) return list;
        foreach (var p in arr.EnumerateArray())
        {
            if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty("name", out var n) || n.ValueKind != JsonValueKind.String) continue;
            string name = n.GetString() ?? "";
            string ver = p.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String ? (v.GetString() ?? "").TrimStart('v', 'V') : "";
            if (name.Length == 0) continue;
            string item = ver.Length > 0 ? name + " " + ver : name;
            if (!list.Contains(item)) list.Add(item);
        }
        return list;
    }

    // ---- 3. Pagine di stato ----------------------------------------------------------------------------------------------

    private static async Task StatusPagesAsync(ScanContext ctx, State st)
    {
        var r = ctx.Result;
        int found = 0, tried = 0;
        if (st.ConnectionLost) return;

        // Apache mod_info
        var si = await ctx.GetAsync("/server-info").ConfigureAwait(false); tried++;
        if (Lost(si, st)) return;
        if (si.HasResponse && si.Status == 200 && IsApacheInfo(si.Body))
        {
            found++;
            var modules = ApacheModuleRx.Matches(si.Body).Select(m => m.Groups[1].Value.ToLowerInvariant()).Distinct().ToList();
            string sapi = SapiFromModules(si.Body);
            string detail = L.F("{0} moduli caricati", modules.Count);
            if (sapi.Length > 0)
            {
                string mod = sapi == "mod_php" ? "mod_php" : sapi == "fpm" ? "mod_proxy_fcgi" : "mod_fcgid";
                r.Sapi = sapi;
                r.SapiEvidence = L.F("/server-info elenca il modulo {0} tra quelli caricati", mod);
                detail += "; " + L.F("SAPI certa dai moduli: {0} ({1})", Labels.Sapi(sapi), mod);
                if (sapi == "mod_php") AddPhpEvidence(r, L.T("mod_php tra i moduli caricati (/server-info)"));
            }
            var sv = Regex.Match(si.Body, @"Server Version:\s*(?:</[^>]+>\s*)*(?:<[^>]+>\s*)*([^<\n]+)", RegexOptions.IgnoreCase);
            if (sv.Success)
            {
                string banner = WebUtility.HtmlDecode(sv.Groups[1].Value.Trim());
                if (r.ServerHeader.Length == 0) r.ServerHeader = banner;
                if (Regex.IsMatch(banner, @"PHP/\d", RegexOptions.IgnoreCase))
                {
                    AddPhpEvidence(r, "Server Version (/server-info): " + banner);
                    if (SetVersion(r, PhpVersion.Parse(banner), "/server-info")) AddVersionLine(r, "/server-info");
                }
            }
            AddExposure(r, "/server-info", 200, L.F("configurazione di Apache pubblica (mod_info), {0} moduli elencati", modules.Count));
            r.Add("ADV-STATUS-INFO", L.T("/server-info (Apache mod_info)"), TestOutcome.Fail, detail, si);
        }

        // Apache mod_status
        var ss = await ctx.GetAsync("/server-status").ConfigureAwait(false); tried++;
        if (Lost(ss, st)) return;
        if (ss.HasResponse && ss.Status == 200 && IsApacheStatus(ss.Body))
        {
            found++;
            var sv = Regex.Match(ss.Body, @"Server Version:\s*(?:</[^>]+>\s*)*(?:<[^>]+>\s*)*([^<\n]+)", RegexOptions.IgnoreCase);
            string banner = sv.Success ? WebUtility.HtmlDecode(sv.Groups[1].Value.Trim()) : "";
            if (banner.Length > 0 && r.ServerHeader.Length == 0) r.ServerHeader = banner;
            if (Regex.IsMatch(banner, @"PHP/\d", RegexOptions.IgnoreCase))
            {
                AddPhpEvidence(r, "Server Version (/server-status): " + banner);
                if (r.Sapi.Length == 0) { r.Sapi = "mod_php"; r.SapiEvidence = L.F("la versione completa di Apache in /server-status include PHP: {0}", banner); }
                if (SetVersion(r, PhpVersion.Parse(banner), "/server-status")) AddVersionLine(r, "/server-status");
            }
            AddExposure(r, "/server-status", 200, L.T("stato di Apache pubblico (mod_status): richieste in corso, client e URL"));
            r.Add("ADV-STATUS-SERVER", L.T("/server-status (Apache mod_status)"), TestOutcome.Fail, banner.Length > 0 ? L.F("Server Version: {0}", banner) : L.T("pagina di stato leggibile"), ss);
        }

        // nginx stub_status
        var ns = await ctx.GetAsync("/nginx_status").ConfigureAwait(false); tried++;
        if (Lost(ns, st)) return;
        if (ns.HasResponse && ns.Status == 200 && ns.Body.TrimStart().StartsWith("Active connections:", StringComparison.Ordinal))
        {
            found++;
            AddExposure(r, "/nginx_status", 200, L.T("stub_status di nginx pubblico (connessioni e richieste)"));
            r.Add("ADV-STATUS-NGINX", L.T("/nginx_status (nginx stub_status)"), TestOutcome.Warn, Short(ns.Body.Trim().Replace('\n', ' ')), ns);
        }

        // PHP-FPM status page
        foreach (var p in FpmStatusPages)
        {
            ctx.Ct.ThrowIfCancellationRequested();
            var fs = await ctx.GetAsync(p).ConfigureAwait(false); tried++;
            if (Lost(fs, st)) return;
            if (!fs.HasResponse || fs.Status != 200 || !IsFpmStatus(fs.Body)) continue;
            found++;
            var pool = Regex.Match(fs.Body, @"pool:\s*(\S+)|""pool""\s*:\s*""([^""]+)""", RegexOptions.IgnoreCase);
            string poolName = pool.Success ? (pool.Groups[1].Success ? pool.Groups[1].Value : pool.Groups[2].Value) : "?";
            var pm = Regex.Match(fs.Body, @"process manager:\s*(\S+)|""process manager""\s*:\s*""([^""]+)""", RegexOptions.IgnoreCase);
            string pmName = pm.Success ? (pm.Groups[1].Success ? pm.Groups[1].Value : pm.Groups[2].Value) : "?";
            r.Sapi = "fpm";
            r.SapiEvidence = L.F("pagina di stato di PHP-FPM esposta su {0} (pool {1})", p, poolName);
            AddPhpEvidence(r, L.F("pagina di stato di PHP-FPM esposta: {0}", p));
            AddExposure(r, p, 200, L.F("stato di PHP-FPM pubblico: pool {0}, process manager {1}", poolName, pmName));
            r.Add("ADV-STATUS-FPM", L.T("Pagina di stato di PHP-FPM"), TestOutcome.Fail, L.F("{0}: pool {1}, process manager {2} (prova diretta di PHP-FPM)", p, poolName, pmName), fs);
            break;
        }

        if (found == 0) r.Add("ADV-STATUS", L.T("Pagine di stato"), TestOutcome.Info, L.F("nessuna pagina di stato esposta tra le {0} provate", tried));
    }

    private static bool IsApacheInfo(string body) =>
        body.Contains("Apache", StringComparison.OrdinalIgnoreCase) &&
        (body.Contains("Loaded Modules", StringComparison.OrdinalIgnoreCase) || body.Contains("Module Name:", StringComparison.OrdinalIgnoreCase) || (body.Contains("Server Version:", StringComparison.OrdinalIgnoreCase) && body.Contains("Server Settings", StringComparison.OrdinalIgnoreCase)));

    private static bool IsApacheStatus(string body) =>
        body.Contains("Apache Server Status", StringComparison.OrdinalIgnoreCase) ||
        (body.Contains("Server Version:", StringComparison.OrdinalIgnoreCase) && body.Contains("Server MPM", StringComparison.OrdinalIgnoreCase));

    private static bool IsFpmStatus(string body) =>
        (body.Contains("pool:", StringComparison.OrdinalIgnoreCase) && body.Contains("process manager:", StringComparison.OrdinalIgnoreCase)) ||
        (body.Contains("\"pool\"", StringComparison.OrdinalIgnoreCase) && body.Contains("\"process manager\"", StringComparison.OrdinalIgnoreCase)) ||
        (body.Contains("<th>pool</th>", StringComparison.OrdinalIgnoreCase) && body.Contains("process manager", StringComparison.OrdinalIgnoreCase));

    /// <summary>SAPI dall'elenco dei moduli di mod_info: "mod_php", "fpm" (mod_proxy_fcgi), "cgi" (mod_fcgid), "" se nessuno.</summary>
    public static string SapiFromModules(string body)
    {
        if (Regex.IsMatch(body, @"\bmod_php\d*\.c\b|\bphp\d*_module\b", RegexOptions.IgnoreCase)) return "mod_php";
        if (Regex.IsMatch(body, @"\bmod_proxy_fcgi\.c\b|\bproxy_fcgi_module\b", RegexOptions.IgnoreCase)) return "fpm";
        if (Regex.IsMatch(body, @"\bmod_fcgid\.c\b|\bfcgid_module\b", RegexOptions.IgnoreCase)) return "cgi";
        return "";
    }

    // ---- 4. File di versione delle applicazioni ---------------------------------------------------------------------------

    private sealed record VersionFile(string App, string Path, string Letter, Func<string, string?> Extract);

    private static string? Rx(string body, string pattern, string? mustContain = null)
    {
        if (mustContain != null && !body.Contains(mustContain, StringComparison.OrdinalIgnoreCase)) return null;
        var m = Regex.Match(body, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static readonly VersionFile[] VersionFiles =
    [
        new("WordPress", "/readme.html", "w", b => Rx(b, @"Version\s+(\d+\.\d+(?:\.\d+)?)", "WordPress")),
        new("Joomla", "/administrator/manifests/files/joomla.xml", "j", b => Rx(b, @"<version>\s*([\d.]+)\s*</version>", "<extension")),
        new("Drupal", "/core/CHANGELOG.txt", "d", b => Rx(b, @"Drupal\s+(\d+\.\d+(?:\.\d+)?)")),
        new("Drupal", "/CHANGELOG.txt", "d", b => Rx(b, @"Drupal\s+(\d+\.\d+(?:\.\d+)?)")),
        new("Moodle", "/lib/upgrade.txt", "m", b => Rx(b, @"===\s*(\d+\.\d+(?:\.\d+)?)\s*===", "moodle")),
        new("phpMyAdmin", "/ChangeLog", "p", b => Rx(b, @"^(\d+\.\d+\.\d+)\s*\(", "phpMyAdmin")),
        new("TYPO3", "/typo3/sysext/core/composer.json", "t", b => b.Contains("typo3/cms-core", StringComparison.OrdinalIgnoreCase) ? (Rx(b, @"""version""\s*:\s*""([^""]+)""") ?? "") : null),
    ];

    private sealed record DebugPage(string App, string Path, Func<HttpSnapshot, bool> Matches, Func<string> Description);

    private static readonly DebugPage[] DebugPages =
    [
        new("Symfony", "/_profiler/phpinfo", s => s.Status == 200 && PhpInfoRx.IsMatch(s.Body), () => L.T("phpinfo del profiler di Symfony esposto (ambiente di sviluppo in produzione)")),
        new("Laravel", "/telescope", s => s.Status == 200 && s.Body.Contains("Telescope", StringComparison.Ordinal), () => L.T("Laravel Telescope raggiungibile (richieste, query e log dell'applicazione)")),
        new("Laravel", "/horizon", s => s.Status == 200 && s.Body.Contains("Horizon", StringComparison.Ordinal), () => L.T("Laravel Horizon raggiungibile (code e job dell'applicazione)")),
        new("Yii", "/debug/default/view", s => s.Status == 200 && (s.Body.Contains("yii-debug", StringComparison.OrdinalIgnoreCase) || s.Body.Contains("Yii Debug", StringComparison.OrdinalIgnoreCase)), () => L.T("modulo di debug di Yii raggiungibile")),
    ];

    private static async Task AppVersionFilesAsync(ScanContext ctx, State st)
    {
        var r = ctx.Result;
        if (st.ConnectionLost) return;
        string app = r.Application;
        bool blind = app.Length == 0;
        var files = blind ? VersionFiles : VersionFiles.Where(f => f.App.Equals(app, StringComparison.OrdinalIgnoreCase) || app.StartsWith(f.App, StringComparison.OrdinalIgnoreCase)).ToArray();
        bool got = false;
        int tried = 0;
        foreach (var f in files)
        {
            ctx.Ct.ThrowIfCancellationRequested();
            var s = await ctx.GetAsync(f.Path).ConfigureAwait(false); tried++;
            if (Lost(s, st)) return;
            if (!s.HasResponse || s.Status != 200) continue;
            string? ver = f.Extract(s.Body);
            if (ver == null) continue;
            got = true;
            if (r.Application.Length == 0)
            {
                r.Application = f.App;
                r.ApplicationEvidence = L.F("file di versione {0}", f.Path);
                r.ApplicationReference = StackFingerprint.NcscInventoryBase + f.Letter + ".md";
            }
            if (ver.Length > 0 && r.ApplicationVersion.Length == 0) r.ApplicationVersion = ver;
            if (f.App == "TYPO3" && r.PhpVersionFloor.Length == 0 && TryParseJson(s.Body, out var tdoc) && tdoc != null)
            {
                using (tdoc)
                    if (tdoc.RootElement.ValueKind == JsonValueKind.Object && tdoc.RootElement.TryGetProperty("require", out var req) && req.ValueKind == JsonValueKind.Object && req.TryGetProperty("php", out var php) && php.ValueKind == JsonValueKind.String)
                    { r.PhpVersionFloor = (php.GetString() ?? "").Trim(); r.PhpVersionFloorSource = f.Path; }
            }
            AddPhpEvidence(r, L.F("file di versione di {0}: {1}", f.App, f.Path));
            AddExposure(r, f.Path, 200, ver.Length > 0 ? L.F("file di versione di {0} leggibile ({1})", f.App, ver) : L.F("file di versione di {0} leggibile", f.App));
            r.Add("ADV-APPVERSION", L.T("File di versione dell'applicazione"), TestOutcome.Warn,
                ver.Length > 0 ? L.F("{0} {1} dichiarato da {2}", f.App, ver, f.Path) : L.F("{0} confermato da {1} (senza numero di versione)", f.App, f.Path), s);
            break;
        }
        if (!got && tried > 0)
            r.Add("ADV-APPVERSION", L.T("File di versione dell'applicazione"), TestOutcome.Info,
                blind ? L.F("nessun file di versione noto tra i {0} provati", tried) : L.F("nessun file di versione di {0} leggibile ({1} provati)", app, tried));

        // confronto con l'inventario NCSC-NL
        if (r.ApplicationVersion.Length > 0 && r.Application.Length > 0 && TechnologyDatabase.Default?.Inventory.Find(r.Application) is { } pkg)
        {
            string check = CompareAppVersion(r.ApplicationVersion, pkg);
            if (check.Length > 0)
            {
                r.AppVersionCheck = check;
                r.Add("ADV-APPCHECK", L.T("Versione dell'applicazione contro l'inventario NCSC-NL"), check.Contains('<') ? TestOutcome.Fail : TestOutcome.Pass, L.F("{0}: {1} ({2})", r.Application, check, pkg.Name));
            }
        }

        // pagine di debug dei framework (esposizioni; il phpinfo di Symfony è anche fonte di versione)
        var techs = string.Join(" ", r.Technologies) + " " + r.Application;
        foreach (var d in DebugPages)
        {
            if (!blind && !techs.Contains(d.App, StringComparison.OrdinalIgnoreCase)) continue;
            ctx.Ct.ThrowIfCancellationRequested();
            var s = await ctx.GetAsync(d.Path).ConfigureAwait(false);
            if (Lost(s, st)) return;
            if (!s.HasResponse || !d.Matches(s)) continue;
            AddExposure(r, d.Path, s.Status, d.Description());
            AddPhpEvidence(r, L.F("pagina di debug di {0} raggiungibile: {1}", d.App, d.Path));
            if (r.Application.Length == 0) { r.Application = d.App; r.ApplicationEvidence = L.F("pagina di debug {0}", d.Path); }
            var m = PhpInfoRx.Match(s.Body);
            if (m.Success && SetVersion(r, PhpVersion.Parse(m.Groups[1].Value), d.Path)) AddVersionLine(r, d.Path);
            r.Add("ADV-DEBUGPAGE", L.F("Pagina di debug di {0}", d.App), TestOutcome.Fail, L.F("{0} ({1}): {2}", d.Path, s.Status, d.Description()) + (m.Success ? " — PHP " + m.Groups[1].Value : ""), s);
        }
    }

    /// <summary>
    /// Confronta la versione osservata con le versioni corrette dichiarate nell'inventario NCSC-NL (stato Fixed): "6.4.2 &lt; corretto in 6.4.3",
    /// "6.4.3 ≥ corretto in 6.4.3". Con più rami corretti (es. "8.4.27, 8.3.36") conta quello con lo stesso major.minor; se nessuno
    /// coincide, solo i casi non ambigui (sotto il minimo, sopra il massimo). "" quando non confrontabile.
    /// </summary>
    public static string CompareAppVersion(string observed, NcscPackage pkg)
    {
        var obs = ParseNumeric(observed);
        if (obs == null) return "";
        var fixedAll = pkg.Vex.Values.Where(v => v.Status.Equals("Fixed", StringComparison.OrdinalIgnoreCase) && v.FixedVersion.Length > 0)
            .SelectMany(v => v.FixedVersion.Split([',', ';', '/'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(s => (Text: s, Num: ParseNumeric(s))).Where(x => x.Num != null).DistinctBy(x => x.Text).ToList();
        if (fixedAll.Count == 0) return "";
        var sameBranch = fixedAll.Where(f => f.Num!.Length >= 2 && obs.Length >= 2 && f.Num[0] == obs[0] && f.Num[1] == obs[1]).ToList();
        if (sameBranch.Count > 0)
        {
            var f = sameBranch.OrderBy(x => x.Num!, NumericComparer.Instance).First();
            return Compare(obs, f.Num!) < 0 ? L.F("{0} < corretto in {1}", observed, f.Text) : L.F("{0} ≥ corretto in {1}", observed, f.Text);
        }
        var min = fixedAll.OrderBy(x => x.Num!, NumericComparer.Instance).First();
        var max = fixedAll.OrderByDescending(x => x.Num!, NumericComparer.Instance).First();
        if (Compare(obs, min.Num!) < 0) return L.F("{0} < corretto in {1}", observed, min.Text);
        if (Compare(obs, max.Num!) >= 0) return L.F("{0} ≥ corretto in {1}", observed, max.Text);
        return "";
    }

    private static int[]? ParseNumeric(string s)
    {
        var m = Regex.Match(s ?? "", @"(\d+(?:\.\d+)*)");
        if (!m.Success) return null;
        return m.Groups[1].Value.Split('.').Select(int.Parse).ToArray();
    }

    private static int Compare(int[] a, int[] b)
    {
        for (int i = 0; i < Math.Max(a.Length, b.Length); i++)
        {
            int x = i < a.Length ? a[i] : 0, y = i < b.Length ? b[i] : 0;
            if (x != y) return x.CompareTo(y);
        }
        return 0;
    }

    private sealed class NumericComparer : IComparer<int[]>
    {
        public static readonly NumericComparer Instance = new();
        public int Compare(int[]? x, int[]? y) => AdvancedProbes.Compare(x ?? [], y ?? []);
    }

    // ---- 6. Comportamenti tipici di PHP ----------------------------------------------------------------------------------

    private static async Task PhpBehavioursAsync(ScanContext ctx, State st)
    {
        var r = ctx.Result;
        var b = ctx.Baseline;
        string p = ctx.PrimaryPath;
        bool primaryIsPhp = p.EndsWith(".php", StringComparison.OrdinalIgnoreCase);
        if (st.ConnectionLost) return;

        // PATH_INFO: /index.php/x risponde come /index.php
        if (primaryIsPhp && b is { HasResponse: true } && b.Status is >= 200 and < 400)
        {
            if (st.CatchAll)
                r.Add("ADV-PATHINFO", L.T("PATH_INFO"), TestOutcome.Skipped, L.T("server catch-all (ogni percorso risponde): PATH_INFO non distinguibile"));
            else
            {
                var s = await ctx.GetAsync(p + "/x").ConfigureAwait(false);
                if (Lost(s, st)) return;
                if (s.HasResponse)
                {
                    bool same = s.Status == b.Status && (s.Header("Content-Type") ?? "") == (b.Header("Content-Type") ?? "") &&
                                (s.Status >= 300 ? (s.Header("Location") ?? "") == (b.Header("Location") ?? "") : Hash(s.Body) == Hash(b.Body) || Math.Abs(s.BodyLength - b.BodyLength) <= Math.Max(64, b.BodyLength / 50));
                    if (same)
                    {
                        AddPhpEvidence(r, L.F("PATH_INFO accettato: {0}/x risponde come {0}", p));
                        r.Add("ADV-PATHINFO", L.T("PATH_INFO"), TestOutcome.Warn, L.F("{0}/x risponde {1} con lo stesso contenuto di {0}: lo script riceve il resto del percorso come PATH_INFO (comportamento tipico di PHP)", p, s.Status), s);
                    }
                    else r.Add("ADV-PATHINFO", L.T("PATH_INFO"), TestOutcome.Info, L.F("{0}/x risponde {1} (riferimento {2}): PATH_INFO non attivo o percorso riscritto", p, s.Summary, b.Status), s);
                }
                else r.Add("ADV-PATHINFO", L.T("PATH_INFO"), TestOutcome.Warn, s.Error ?? "", s);
            }
        }

        // xmlrpc.php di WordPress
        var x = await ctx.GetAsync("/xmlrpc.php").ConfigureAwait(false);
        if (Lost(x, st)) return;
        if (x.HasResponse && x.Body.Contains("XML-RPC server accepts POST requests only", StringComparison.Ordinal))
        {
            AddPhpEvidence(r, L.T("xmlrpc.php di WordPress risponde (\"XML-RPC server accepts POST requests only\")"));
            if (r.Application.Length == 0) { r.Application = "WordPress"; r.ApplicationEvidence = L.T("risposta di /xmlrpc.php"); r.ApplicationReference = StackFingerprint.NcscInventoryBase + "w.md"; }
            AddExposure(r, "/xmlrpc.php", x.Status, L.T("XML-RPC di WordPress attivo (amplificazione di brute force e pingback): da disattivare se non serve"));
            r.Add("ADV-XMLRPC", L.T("xmlrpc.php"), TestOutcome.Warn, L.F("{0}: risposta tipica di WordPress, PHP in esecuzione", x.Status), x);
        }
        else if (r.Application.Equals("WordPress", StringComparison.OrdinalIgnoreCase))
            r.Add("ADV-XMLRPC", L.T("xmlrpc.php"), TestOutcome.Info, L.F("non risponde come XML-RPC ({0}): disattivato o bloccato", x.Summary), x);

        // sorgenti esposti accanto al .php principale (solo HEAD: mai il contenuto)
        string? phpPath = primaryIsPhp ? p : ctx.SurfacePhpPaths.FirstOrDefault() ?? ctx.Paths.FirstOrDefault(q => q.EndsWith(".php", StringComparison.OrdinalIgnoreCase));
        if (phpPath != null)
        {
            if (st.CatchAll)
                r.Add("ADV-SOURCE", L.T("Copie del sorgente PHP"), TestOutcome.Skipped, L.T("server catch-all (ogni percorso risponde): la verifica per esistenza non è attendibile"));
            else
            {
                var leaked = new List<string>();
                int tried = 0;
                foreach (var suf in SourceSuffixes)
                {
                    ctx.Ct.ThrowIfCancellationRequested();
                    string sp = phpPath + suf;
                    var s = await ctx.HeadAsync(sp).ConfigureAwait(false); tried++;
                    if (Lost(s, st)) break;
                    if (!s.HasResponse || s.Status != 200 || s.Status == st.MissStatus) continue;
                    leaked.Add(sp);
                    AddExposure(r, sp, 200, L.T("copia del sorgente PHP scaricabile (credenziali e logica applicativa in chiaro)"));
                    AddPhpEvidence(r, L.F("sorgente PHP esposto: {0}", sp));
                }
                if (leaked.Count > 0) r.Add("ADV-SOURCE", L.T("Copie del sorgente PHP"), TestOutcome.Fail, L.F("{0} copie del sorgente rispondono 200 (solo HEAD, contenuto non scaricato): {1}", leaked.Count, string.Join(", ", leaked)));
                else if (tried > 0) r.Add("ADV-SOURCE", L.T("Copie del sorgente PHP"), TestOutcome.Info, L.F("nessuna copia del sorgente di {0} raggiungibile ({1} suffissi provati)", phpPath, tried));
            }
        }
        if (st.ConnectionLost) return;

        // altre pagine phpinfo
        foreach (var page in ExtraInfoPages)
        {
            ctx.Ct.ThrowIfCancellationRequested();
            var s = await ctx.GetAsync(page).ConfigureAwait(false);
            if (Lost(s, st)) return;
            if (!s.HasResponse || s.Status != 200) continue;
            var m = PhpInfoRx.Match(s.Body);
            bool isInfo = m.Success || s.Body.Contains("phpinfo()", StringComparison.OrdinalIgnoreCase) || s.Body.Contains("PHP License", StringComparison.Ordinal);
            if (!isInfo) continue;
            AddPhpEvidence(r, L.F("pagina phpinfo esposta: {0}", page));
            AddExposure(r, page, 200, L.T("phpinfo: configurazione completa di PHP pubblica"));
            if (m.Success && SetVersion(r, PhpVersion.Parse(m.Groups[1].Value), page)) AddVersionLine(r, page);
            r.Add("ADV-PHPINFO", L.T("Pagina phpinfo esposta"), TestOutcome.Fail, L.F("{0} mostra la configurazione completa di PHP{1}: da rimuovere o bloccare al proxy", page, m.Success ? " (" + m.Groups[1].Value + ")" : ""), s);
            PhpInfoParser.Apply(r);   // v1.5: impostazioni dalla pagina già scaricata
            break;
        }
    }

    // ---- 7. Livello 2 sugli altri percorsi --------------------------------------------------------------------------------

    private static async Task Level2AllPathsAsync(ScanContext ctx, State st)
    {
        var r = ctx.Result;
        if (!ctx.Config.Level2)
        {
            r.Add("ADV-L2-ALL", L.T("Livello 2 sugli altri percorsi"), TestOutcome.Skipped, L.T("livello 2 disattivato: nessuna POST sugli altri percorsi"));
            return;
        }
        var others = ctx.SurfacePhpPaths.Where(q => !q.Equals(ctx.PrimaryPath, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(0, ctx.Config.Advanced.Level2MaxPaths)).ToList();
        if (others.Count == 0)
        {
            r.Add("ADV-L2-ALL", L.T("Livello 2 sugli altri percorsi"), TestOutcome.Info, L.T("nessun altro .php scoperto oltre al percorso principale"));
            return;
        }
        int blocked = 0, accepted = 0, silent = 0;
        var field = new[] { new KeyValuePair<string, string>("a", "1") };
        foreach (var path in others)
        {
            ctx.Ct.ThrowIfCancellationRequested();
            if (st.ConnectionLost) break;
            string boundary = "----PhpVulnScanner" + Guid.NewGuid().ToString("N")[..12];
            var form = await ctx.PostAsync(path, HttpProbe.FormContent()).ConfigureAwait(false);
            var multi = await ctx.PostAsync(path, HttpProbe.MultipartContent(field, boundary)).ConfigureAwait(false);
            r.Requests.Add(form);
            bool formBlocked = form.HasResponse && MitigationProbe.BlockCodes.Contains(form.Status);
            bool multiBlocked = (multi.HasResponse && MitigationProbe.BlockCodes.Contains(multi.Status)) || (!multi.HasResponse && form.HasResponse && multi.ErrorKind is "reset" or "timeout" or "invalid");
            string label; TestOutcome outcome;
            if (!form.HasResponse && !multi.HasResponse) { silent++; label = L.F("nessuna risposta alle POST ({0})", multi.Error); outcome = TestOutcome.Warn; Lost(multi, st); }
            else if (form.HasResponse && multi.HasResponse && form.Status == 405 && multi.Status == 405) { blocked++; label = L.T("POST non consentito (405): il vettore non si applica a questo percorso"); outcome = TestOutcome.Pass; }
            else if (multiBlocked && !formBlocked) { blocked++; label = L.F("multipart respinto ({0}) mentre la POST url-encoded passa ({1})", multi.Summary, form.Status); outcome = TestOutcome.Pass; }
            else if (multiBlocked && formBlocked) { blocked++; label = L.F("tutte le POST respinte ({0}): barriera generica", multi.Summary); outcome = TestOutcome.Pass; }
            else { accepted++; label = L.F("multipart accettato ({0}): il corpo raggiunge PHP su questo percorso", multi.Summary); outcome = TestOutcome.Fail; }
            r.Add("ADV-L2-" + path, L.F("Barriera multipart su {0}", path), outcome, label, multi);
        }
        // il riepilogo va nel dettaglio della barriera solo se il livello 2 sul percorso principale è già stato eseguito
        // (MitigationProbe riscrive MultipartDetail: se il motore lo chiama dopo, il riepilogo resta nella riga di evidenza)
        if (r.Multipart != MultipartBarrier.NotTested)
        {
            r.MultipartDetail += L.F("; altri percorsi: {0} bloccati su {1}", blocked, others.Count);
            if (accepted > 0 && r.Multipart == MultipartBarrier.Blocked)
            {
                // il percorso principale è protetto ma un altro .php accetta il multipart: la barriera non copre tutto il servizio
                r.Multipart = MultipartBarrier.PartiallyBlocked;
                r.MultipartDetail += " " + L.T("(barriera incompleta: almeno un altro percorso accetta il multipart)");
            }
        }
        r.Add("ADV-L2-ALL", L.T("Livello 2 sugli altri percorsi"), accepted > 0 ? TestOutcome.Warn : TestOutcome.Info,
            L.F("{0} percorsi: {1} con multipart bloccato, {2} accettato, {3} senza risposta", others.Count, blocked, accepted, silent));
    }

    // ---- 8. Secondo giro con User-Agent da browser -------------------------------------------------------------------------

    private static async Task BrowserUserAgentAsync(ScanContext ctx, State st)
    {
        var r = ctx.Result;
        var b = ctx.Baseline;
        string p = ctx.PrimaryPath;
        if (st.ConnectionLost) return;
        var s = await ctx.GetAsync(p, [new("User-Agent", BrowserUserAgent)]).ConfigureAwait(false);
        if (!s.HasResponse)
        {
            r.BrowserUaResult = L.F("nessuna risposta ({0})", s.Error);
            r.Add("ADV-BROWSERUA", L.T("Secondo giro con User-Agent da browser"), TestOutcome.Warn, r.BrowserUaResult, s);
            Lost(s, st);
            return;
        }
        if (b == null || !b.HasResponse)
        {
            r.BrowserUaResult = L.F("stato {0}, nessuna GET di riferimento", s.Status);
            r.Add("ADV-BROWSERUA", L.T("Secondo giro con User-Agent da browser"), TestOutcome.Info, r.BrowserUaResult, s);
            return;
        }
        var diffs = new List<string>();
        if (s.Status != b.Status) diffs.Add(L.F("stato {0} contro {1}", s.Status, b.Status));
        foreach (var h in new[] { "Server", "X-Powered-By", "Content-Type" })
        {
            string sv = s.Header(h) ?? "", bv = b.Header(h) ?? "";
            if (!sv.Equals(bv, StringComparison.Ordinal)) diffs.Add(L.F("{0} \"{1}\" contro \"{2}\"", h, Short(sv), Short(bv)));
        }
        if (Math.Abs(s.BodyLength - b.BodyLength) > Math.Max(256, b.BodyLength / 10)) diffs.Add(L.F("corpo di {0} B contro {1} B", s.BodyLength, b.BodyLength));
        string st1 = Title(s.Body), bt = Title(b.Body);
        if (!st1.Equals(bt, StringComparison.Ordinal)) diffs.Add(L.F("titolo \"{0}\" contro \"{1}\"", st1, bt));
        r.BrowserUaResult = diffs.Count == 0 ? L.T("uguale") : string.Join("; ", diffs);

        // segnali PHP che la prima risposta non aveva
        var revealed = new List<string>();
        bool basePhpPb = b.HeaderValues("X-Powered-By").Any(v => v.Contains("PHP", StringComparison.OrdinalIgnoreCase));
        foreach (var v in s.HeaderValues("X-Powered-By").Where(v => v.Contains("PHP", StringComparison.OrdinalIgnoreCase)))
        {
            if (basePhpPb) break;
            revealed.Add("X-Powered-By: " + v);
            AddPhpEvidence(r, "X-Powered-By (UA browser): " + v);
            if (r.PoweredBy.Length == 0) r.PoweredBy = v;
            if (SetVersion(r, PhpVersion.Parse(v), "X-Powered-By (UA browser)")) AddVersionLine(r, "X-Powered-By (UA browser)");
        }
        var sc = CookieNames(s); var bc = CookieNames(b);
        if (sc.Contains("PHPSESSID") && !bc.Contains("PHPSESSID")) { revealed.Add("Set-Cookie: PHPSESSID"); AddPhpEvidence(r, "Set-Cookie: PHPSESSID (UA browser)"); }
        if (PhpErrorRx.IsMatch(s.Body) && !PhpErrorRx.IsMatch(b.Body)) { revealed.Add(L.T("errore PHP nel corpo")); AddPhpEvidence(r, L.T("messaggio di errore PHP nel corpo (UA browser)")); }
        var m = PhpInfoRx.Match(s.Body);
        if (m.Success && !PhpInfoRx.IsMatch(b.Body) && SetVersion(r, PhpVersion.Parse(m.Groups[1].Value), L.T("corpo (UA browser)"))) { revealed.Add("PHP Version " + m.Groups[1].Value); AddVersionLine(r, L.T("corpo (UA browser)")); }

        // applicazione: solo se la prima passata non l'aveva riconosciuta e la risposta è davvero diversa
        if (diffs.Count > 0 && r.Application.Length == 0)
        {
            var techs = r.Technologies.ToList();
            StackFingerprint.Apply(r, [s]);
            foreach (var t in techs) if (!r.Technologies.Contains(t)) r.Technologies.Add(t);
            if (r.Application.Length > 0)
            {
                revealed.Add(L.F("applicazione {0}", r.Application));
                r.ApplicationEvidence += " " + L.T("(risposta allo User-Agent da browser)");
                AddPhpEvidence(r, L.F("applicazione PHP riconosciuta: {0}", r.Application));
            }
        }

        string detail = r.BrowserUaResult + (revealed.Count > 0 ? " — " + L.F("la risposta al browser rivela: {0}", string.Join(", ", revealed)) : "");
        r.Add("ADV-BROWSERUA", L.T("Secondo giro con User-Agent da browser"), diffs.Count == 0 ? TestOutcome.Info : TestOutcome.Warn, detail, s);
    }

    // ---- 9. Componenti (nessuna richiesta) ---------------------------------------------------------------------------------

    private static Task ComponentsAsync(ScanContext ctx)
    {
        var r = ctx.Result;
        var comps = ExtractComponents(r.Requests.Where(q => q.HasResponse && q.Body.Length > 0).Select(q => q.Body));
        foreach (var c in comps) if (!r.Components.Contains(c)) r.Components.Add(c);
        if (r.Components.Count > MaxComponents) r.Components.RemoveRange(MaxComponents, r.Components.Count - MaxComponents);
        if (comps.Count > 0)
        {
            r.Add("ADV-COMPONENTS", L.T("Componenti dell'applicazione"), TestOutcome.Info,
                L.F("{0} componenti dalle pagine scaricate: {1}", comps.Count, string.Join(", ", comps.Take(10)) + (comps.Count > 10 ? " …" : "")));
            if (r.Application.Length == 0)
            {
                string? app = comps[0].StartsWith("plugin:") || comps[0].StartsWith("theme:") ? "WordPress" : comps[0].StartsWith("component:") ? "Joomla" : comps[0].StartsWith("module:") ? "Drupal" : comps[0].StartsWith("extension:") ? "TYPO3" : null;
                if (app != null) { r.Application = app; r.ApplicationEvidence = L.F("percorsi dei componenti ({0})", comps[0]); r.ApplicationReference = StackFingerprint.NcscInventoryBase + char.ToLowerInvariant(app[0]) + ".md"; AddPhpEvidence(r, L.F("applicazione PHP riconosciuta: {0}", app)); }
            }
        }
        return Task.CompletedTask;
    }

    /// <summary>Componenti "tipo:nome [versione]" dai corpi: plugin e temi WordPress (versione da ?ver=), componenti Joomla, moduli Drupal, estensioni TYPO3. Distinti, max 60.</summary>
    public static List<string> ExtractComponents(IEnumerable<string> bodies)
    {
        var found = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);   // "tipo:nome" → versione
        var order = new List<string>();
        void Add(string type, string name, string ver = "")
        {
            name = name.Trim().TrimEnd('.');
            if (name.Length is 0 or > 80) return;
            string key = type + ":" + name;
            if (!found.TryGetValue(key, out var old)) { if (order.Count >= MaxComponents) return; found[key] = ver; order.Add(key); }
            else if (old.Length == 0 && ver.Length > 0) found[key] = ver;
        }
        foreach (var body in bodies)
        {
            foreach (Match m in WpComponentRx.Matches(body))
            {
                var v = VerRx.Match(m.Groups[3].Value);
                Add(m.Groups[1].Value.Equals("plugins", StringComparison.OrdinalIgnoreCase) ? "plugin" : "theme", m.Groups[2].Value, v.Success ? v.Groups[1].Value : "");
            }
            foreach (Match m in JoomlaOptionRx.Matches(body)) Add("component", "com_" + m.Groups[1].Value.ToLowerInvariant());
            foreach (Match m in JoomlaPathRx.Matches(body)) Add("component", "com_" + m.Groups[1].Value.ToLowerInvariant());
            foreach (Match m in DrupalModuleRx.Matches(body)) Add("module", m.Groups[1].Value);
            foreach (Match m in Typo3ExtRx.Matches(body)) Add("extension", m.Groups[1].Value);
        }
        return order.Select(k => found[k].Length > 0 ? k + " " + found[k] : k).ToList();
    }

    // ---- 10. Esposizioni accessorie (solo HEAD, solo esistenza) --------------------------------------------------------------

    private sealed record ExposurePath(string Path, Func<string> Description, bool ProtectedCounts, bool PhpHint);

    private static readonly ExposurePath[] ExposurePaths =
    [
        new("/.env", () => L.T("file di ambiente con credenziali e chiavi dell'applicazione"), false, true),
        new("/.git/HEAD", () => L.T("repository Git esposto (storia e sorgenti ricostruibili)"), true, false),
        new("/.svn/entries", () => L.T("repository Subversion esposto"), true, false),
        new("/.DS_Store", () => L.T("indice dei file della cartella (macOS)"), false, false),
        new("/backup.zip", () => L.T("archivio di backup scaricabile"), false, false),
        new("/site.zip", () => L.T("archivio di backup scaricabile"), false, false),
        new("/www.zip", () => L.T("archivio di backup scaricabile"), false, false),
        new("/backup.sql", () => L.T("dump del database scaricabile"), false, false),
        new("/db.sql", () => L.T("dump del database scaricabile"), false, false),
        new("/dump.sql", () => L.T("dump del database scaricabile"), false, false),
        new("/.htpasswd", () => L.T("file delle password HTTP leggibile"), false, false),
        new("/config.php.bak", () => L.T("copia della configurazione con credenziali"), false, true),
        new("/wp-config.php.bak", () => L.T("copia della configurazione di WordPress con credenziali del database"), false, true),
        new("/composer.lock", () => L.T("versioni esatte delle librerie PHP installate"), false, true),
        new("/package.json", () => L.T("manifest Node: nomi e versioni dei pacchetti front-end"), false, false),
        new("/.gitignore", () => L.T("struttura del progetto e nomi dei file sensibili"), false, false),
    ];

    private static async Task ExposuresAsync(ScanContext ctx, State st)
    {
        var r = ctx.Result;
        if (st.ConnectionLost) return;
        if (st.CatchAll)
        {
            r.Add("ADV-EXPOSURES", L.T("Esposizioni accessorie"), TestOutcome.Skipped, L.T("server catch-all (ogni percorso risponde): la verifica per esistenza non è attendibile"));
            return;
        }
        var hits = new List<string>();
        int tried = 0, headRefused = 0;
        foreach (var e in ExposurePaths)
        {
            ctx.Ct.ThrowIfCancellationRequested();
            bool git = e.Path == "/.git/HEAD";
            var s = git ? await ctx.GetAsync(e.Path).ConfigureAwait(false) : await ctx.HeadAsync(e.Path).ConfigureAwait(false);
            tried++;
            if (Lost(s, st)) break;
            if (!s.HasResponse) continue;
            if (s.Status is 405 or 501) { headRefused++; continue; }
            if (s.Status == st.MissStatus) continue;
            if (s.Status == 200)
            {
                if (git)
                {
                    string body = s.Body.Trim();
                    if (!(body.StartsWith("ref:", StringComparison.Ordinal) || Regex.IsMatch(body, @"^[0-9a-f]{40}$"))) continue;
                }
                hits.Add($"{e.Path} (200)");
                AddExposure(r, e.Path, 200, e.Description());
                if (e.PhpHint) AddPhpEvidence(r, L.F("{0} presente (file di un'applicazione PHP)", e.Path));
            }
            else if (s.Status == 403 && e.ProtectedCounts)
            {
                hits.Add($"{e.Path} (403)");
                AddExposure(r, e.Path, 403, e.Description() + " — " + L.T("presente ma protetto (403)"));
            }
        }
        if (hits.Count > 0)
            r.Add("ADV-EXPOSURES", L.T("Esposizioni accessorie"), TestOutcome.Fail, L.F("{0} su {1} percorsi provati (solo HEAD, contenuto non scaricato): {2}", hits.Count, tried, string.Join(", ", hits)));
        else
            r.Add("ADV-EXPOSURES", L.T("Esposizioni accessorie"), TestOutcome.Info, L.F("nessuna delle {0} esposizioni comuni", tried) + (headRefused > 0 ? " " + L.F("({0} HEAD non consentite: non verificabili senza scaricare il contenuto)", headRefused) : ""));
    }

    // ---- 11b. ServerName nelle pagine di errore di Apache (nessuna richiesta) ----------------------------------------------------

    private static Task ServerNameAsync(ScanContext ctx)
    {
        var r = ctx.Result;
        var names = new List<string>();
        foreach (var q in r.Requests.Where(q => q.HasResponse && q.Body.Length > 0))
            foreach (Match m in ApacheAddressRx.Matches(q.Body))
            {
                string n = m.Groups[1].Value.Trim().TrimEnd('.').ToLowerInvariant();
                if (!NameDiscovery.IsValidHostName(n) || n.Equals(ctx.Endpoint.Host, StringComparison.OrdinalIgnoreCase)) continue;
                if (!names.Contains(n)) names.Add(n);
            }
        if (names.Count == 0) return Task.CompletedTask;
        int added = 0;
        foreach (var n in names) if (!r.DiscoveredNames.Contains(n, StringComparer.OrdinalIgnoreCase)) { r.DiscoveredNames.Add(n); added++; }
        r.Add("ADV-SERVERNAME", L.T("ServerName nelle pagine di errore di Apache"), TestOutcome.Info, L.F("{0} ({1} nuovi)", string.Join(", ", names), added));
        return Task.CompletedTask;
    }

    // =====================================================================================================================
    // Sonde per host (non HTTP)
    // =====================================================================================================================

    /// <summary>
    /// Sonde per host: FastCGI su tcp/9000 (un solo FCGI_GET_VALUES), PTR dell'indirizzo, Certificate Transparency per i domini scoperti.
    /// Da chiamare una volta per host (prima porta), con il risultato che riceverà le evidenze.
    /// </summary>
    public static async Task RunHostLevelAsync(ScanConfig cfg, ScanResult r, CancellationToken ct)
    {
        var o = cfg.Advanced;
        string? ip = r.IsIpLiteral ? r.Host : r.ResolvedIps.FirstOrDefault();

        if (o.FastCgiProbe && ip != null)
        {
            try
            {
                var f = await FastCgiProbe.ProbeAsync(ip, FastCgiPort, FastCgiTimeoutMs, ct).ConfigureAwait(false);
                r.FastCgiExposed = f.Exposed;
                r.FastCgiDetail = f.Detail;
                if (f.Exposed == true)
                {
                    AddExposure(r, $"tcp/{FastCgiPort}", 0, L.F("php-fpm esposto su TCP/{0}: risponde a FCGI_GET_VALUES ({1})", FastCgiPort, string.Join(", ", f.Values.Select(v => v.Key + "=" + v.Value))));
                    AddPhpEvidence(r, L.F("server FastCGI (php-fpm) in ascolto su tcp/{0}", FastCgiPort));
                    if (r.Sapi.Length == 0) { r.Sapi = "fpm"; r.SapiEvidence = L.F("FastCGI risponde su tcp/{0} dell'host", FastCgiPort); }
                    r.Add("ADV-HOST-FASTCGI", L.F("Sonda FastCGI (tcp/{0})", FastCgiPort), TestOutcome.Fail, f.Detail + " — " + L.T("la porta FastCGI non deve essere raggiungibile dall'esterno: chiunque può far eseguire script al pool") + L.F(" [{0:F0} ms]", f.ElapsedMs));
                }
                else r.Add("ADV-HOST-FASTCGI", L.F("Sonda FastCGI (tcp/{0})", FastCgiPort), f.Exposed == false ? TestOutcome.Info : TestOutcome.Error, f.Detail + L.F(" [{0:F0} ms]", f.ElapsedMs));
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { r.Add("ADV-HOST-FASTCGI", L.F("Sonda FastCGI (tcp/{0})", FastCgiPort), TestOutcome.Error, L.F("errore interno della sonda: {0}", ex.GetBaseException().Message)); }
        }

        if (o.ReverseDns && ip != null)
        {
            try
            {
                var names = await ReverseLookupAsync(ip, ct).ConfigureAwait(false);
                int added = 0;
                foreach (var n in names) if (!r.DiscoveredNames.Contains(n, StringComparer.OrdinalIgnoreCase)) { r.DiscoveredNames.Add(n); added++; }
                r.Add("ADV-HOST-PTR", L.T("Nome inverso (PTR)"), TestOutcome.Info, names.Count > 0 ? L.F("PTR di {0}: {1} ({2} nuovi)", ip, string.Join(", ", names), added) : L.F("PTR di {0}: nessun nome valido", ip));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { r.Add("ADV-HOST-PTR", L.T("Nome inverso (PTR)"), TestOutcome.Info, L.F("PTR di {0}: nessun nome ({1})", ip, ex.GetBaseException().Message)); }
        }

        if (o.CertificateTransparency)
        {
            try
            {
                var seeds = new List<string>();
                if (!r.IsIpLiteral) seeds.Add(r.Host);
                if (r.NameRescan && r.HostHeader.Length > 0) seeds.Add(r.HostHeader);
                seeds.AddRange(r.DiscoveredNames);
                var domains = seeds.Select(CertificateTransparency.RegistrableDomain).Where(d => d != null).Select(d => d!).Distinct(StringComparer.OrdinalIgnoreCase).Take(MaxCtDomains).ToList();
                if (domains.Count == 0)
                    r.Add("ADV-HOST-CT", L.T("Certificate Transparency (crt.sh)"), TestOutcome.Skipped, L.T("nessun dominio scoperto da interrogare"));
                else
                {
                    int total = 0, added = 0;
                    var asked = new List<string>();
                    foreach (var d in domains)
                    {
                        // v1.8: prima il dominio a tre etichette più frequente tra i nomi (ente.example.it), poi quello registrabile (example.it):
                        // su un dominio largo crt.sh non risponde in tempo e tornava vuoto (misurato sulla /20)
                        var specific = CertificateTransparency.MostCommonSubdomain(seeds, d);
                        IReadOnlyList<string> names = [];
                        if (specific != null) { names = await CertificateTransparency.QueryAsync(specific, ct).ConfigureAwait(false); asked.Add(specific); }
                        if (names.Count == 0) { names = await CertificateTransparency.QueryAsync(d, ct).ConfigureAwait(false); asked.Add(d); }
                        total += names.Count;
                        foreach (var n in names)
                        {
                            if (added >= MaxCtNames) break;
                            if (r.DiscoveredNames.Contains(n, StringComparer.OrdinalIgnoreCase)) continue;
                            r.DiscoveredNames.Add(n); r.CtNames.Add(n); added++;
                        }
                    }
                    r.Add("ADV-HOST-CT", L.T("Certificate Transparency (crt.sh)"), TestOutcome.Info,
                        total > 0 ? L.F("{0}: {1} nomi nei certificati, {2} nuovi aggiunti ai nomi scoperti (max {3})", string.Join(", ", asked), total, added, MaxCtNames)
                                  : L.F("{0}: nessun nome restituito (servizio non raggiungibile o nessun certificato)", string.Join(", ", asked)));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex) { r.Add("ADV-HOST-CT", L.T("Certificate Transparency (crt.sh)"), TestOutcome.Error, L.F("errore interno della sonda: {0}", ex.GetBaseException().Message)); }
        }
    }

    /// <summary>PTR dell'indirizzo con timeout: nomi validi (<see cref="NameDiscovery.IsValidHostName"/>), minuscoli, distinti.</summary>
    public static async Task<List<string>> ReverseLookupAsync(string ip, CancellationToken ct)
    {
        var list = new List<string>();
        if (!IPAddress.TryParse(ip, out var addr)) return list;
        IPHostEntry entry;
        try { entry = await Dns.GetHostEntryAsync(addr).WaitAsync(TimeSpan.FromMilliseconds(PtrTimeoutMs), ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return list; }   // timeout, NXDOMAIN, resolver assente: nessun nome
        foreach (var n in new[] { entry.HostName }.Concat(entry.Aliases))
        {
            string name = (n ?? "").Trim().TrimEnd('.').ToLowerInvariant();
            if (!NameDiscovery.IsValidHostName(name) || list.Contains(name)) continue;
            list.Add(name);
        }
        return list;
    }

    // =====================================================================================================================
    // Utilità
    // =====================================================================================================================

    private static async Task<HttpSnapshot> SendAsync(ScanContext ctx, HttpMethod method, string path, IEnumerable<KeyValuePair<string, string>>? headers = null)
    {
        if (ctx.Pacer != null) await ctx.Pacer.WaitAsync(ctx.Ct).ConfigureAwait(false);
        return await ctx.Http.SendAsync(ctx.Endpoint, method, path, null, ctx.Ct, ctx.HostHeader, headers).ConfigureAwait(false);
    }

    /// <summary>Vero (e memorizzato) quando la risposta mancante indica che il servizio non è più raggiungibile: le sonde successive non insistono.</summary>
    private static bool Lost(HttpSnapshot s, State st)
    {
        if (!s.HasResponse && s.ErrorKind is "connect" or "tls" or "reset" or "dns") st.ConnectionLost = true;
        return st.ConnectionLost;
    }

    /// <summary>Esistenza di un percorso per confronto con la 404 di riferimento: 200/401/403 diversi dallo stato del percorso inesistente, mai su un server catch-all.</summary>
    private static bool Exists(HttpSnapshot s, State st) =>
        s.HasResponse && !st.CatchAll && s.Status is 200 or 401 or 403 && s.Status != st.MissStatus;

    /// <summary>Aggiunge un'evidenza di PHP (una volta) e segna PHP come rilevato; gli indizi deboli perdono l'etichetta.</summary>
    public static void AddPhpEvidence(ScanResult r, string evidence)
    {
        var parts = r.PhpEvidence.Split("; ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
        if (!r.PhpDetected)
        {
            string weak = " " + L.T("(indizio debole)");
            parts = parts.Select(p => p.EndsWith(weak, StringComparison.Ordinal) ? p[..^weak.Length] : p).ToList();
        }
        if (!parts.Contains(evidence, StringComparer.Ordinal)) parts.Add(evidence);
        r.PhpEvidence = string.Join("; ", parts);
        r.PhpDetected = true;
    }

    /// <summary>Esposizione "percorso (stato): descrizione" (stato 0 = non HTTP), una volta sola.</summary>
    public static void AddExposure(ScanResult r, string path, int status, string description)
    {
        string line = status > 0 ? $"{path} ({status}): {description}" : $"{path}: {description}";
        if (!r.Exposures.Contains(line)) r.Exposures.Add(line);
    }

    /// <summary>Registra la versione PHP quando il risultato non ne ha ancora una; vero se registrata.</summary>
    public static bool SetVersion(ScanResult r, PhpVersion? v, string source)
    {
        if (v == null || r.PhpVersionRaw.Length > 0) return false;
        r.PhpVersionRaw = v.Raw;
        r.PhpVersionSource = source;
        r.VersionStatus = v.Status();
        r.FixedRelease = v.FixedRelease ?? "";
        r.PackageSuffix = v.HasPackageSuffix;
        return true;
    }

    private static void AddVersionLine(ScanResult r, string source)
    {
        var outcome = r.VersionStatus switch
        {
            VersionStatus.Fixed or VersionStatus.Newer => TestOutcome.Pass,
            VersionStatus.VulnerableSupported or VersionStatus.EndOfLife => TestOutcome.Fail,
            VersionStatus.Ancient => TestOutcome.Warn,
            _ => TestOutcome.Info,
        };
        r.Add("ADV-VERSION", L.F("Versione PHP dichiarata ({0})", source), outcome,
            L.F("{0}: {1}", r.PhpVersionRaw, Labels.VersionStatus(r.VersionStatus)) + (r.FixedRelease.Length > 0 ? L.F(" (correzione del ramo: {0})", r.FixedRelease) : ""));
    }

    private static HashSet<string> CookieNames(HttpSnapshot s) =>
        s.HeaderValues("Set-Cookie").Select(c => c.Split('=')[0].Trim()).Where(n => n.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static bool TryParseJson(string text, out JsonDocument? doc)
    {
        doc = null;
        text = text.TrimStart();
        if (text.Length == 0 || (text[0] != '{' && text[0] != '[')) return false;
        try { doc = JsonDocument.Parse(text, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip }); return true; }
        catch (JsonException) { return false; }
    }

    private static string Hash(string body) => Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(body)));

    private static string Title(string body)
    {
        var m = TitleRx.Match(body);
        return m.Success ? WebUtility.HtmlDecode(m.Groups[1].Value.Trim()) : "";
    }

    private static string PathOf(string url)
    {
        int i = url.IndexOf("://", StringComparison.Ordinal);
        if (i < 0) return url;
        int s = url.IndexOf('/', i + 3);
        return s < 0 ? "/" : url[s..];
    }

    private static string Short(string v) => v.Length <= 80 ? v : v[..77] + "...";
}
