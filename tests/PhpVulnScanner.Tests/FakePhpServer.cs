using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PhpVulnScanner.Tests;

/// <summary>
/// Server HTTP finto su loopback (HttpListener) che simula le risposte di un server PHP in diverse configurazioni:
/// versione dichiarata o no, multipart bloccato (tutto, solo la stringa esatta, nessuno), cookie di sessione, WAF.
/// </summary>
public sealed class FakePhpServer : IDisposable
{
    public enum MultipartPolicy { Accept, BlockAll, BlockExactOnly, BlockUploadProgressField }

    public string? PoweredBy { get; set; }
    public string Server { get; set; } = "Apache/2.4.58 (Debian)";
    public bool SessionCookie { get; set; }
    /// <summary>v1.6: con <see cref="SessionCookie"/>, comportamento quando la richiesta porta già un cookie PHPSESSID: true riemette un ID nuovo
    /// (session.use_strict_mode attivo), false non emette nulla (ID adottato).</summary>
    public bool StrictMode { get; set; }
    /// <summary>Ultimo valore di PHPSESSID ricevuto nell'intestazione Cookie, null se nessuno.</summary>
    public string? LastSessionIdReceived;
    /// <summary>Intestazioni aggiuntive sulla pagina principale (es. Set-Cookie di un'applicazione).</summary>
    public List<KeyValuePair<string, string>> ExtraHeaders { get; } = [];
    public MultipartPolicy Multipart { get; set; } = MultipartPolicy.Accept;
    public bool Waf { get; set; }                       // 403 sui parametri ostili + header cf-ray
    public int SizeLimitBytes { get; set; } = 0;        // >0: 413 oltre questa dimensione
    public bool ExposePhpinfo { get; set; }
    public bool PostNotAllowed { get; set; }
    /// <summary>Risposta ai .php inesistenti (predefinita 404 "Not Found"; es. 404 "File not found." per simulare PHP-FPM).</summary>
    public (int Status, string Body) MissingPhp { get; set; } = (404, "Not Found");
    /// <summary>Percorsi che "esistono" oltre a /index.php, con lo stato da restituire (es. /wp-login.php → 200).</summary>
    public Dictionary<string, int> ExistingPaths { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Se valorizzato, "/" risponde 302 verso questa URL (simula un redirect al nome del sito).</summary>
    public string? RedirectRootTo { get; set; }
    /// <summary>Vhost per nome: con Host uguale a VhostName la risposta usa VhostBody e VhostPoweredBy.</summary>
    public string? VhostName { get; set; }
    public string VhostBody { get; set; } = "<html><body>vhost</body></html>";
    public string? VhostPoweredBy { get; set; }
    /// <summary>Numero di richieste ricevute con un header Host diverso da 127.0.0.1.</summary>
    public int VhostRequests;
    /// <summary>v1.4: percorsi con risposta completa (stato, corpo, Content-Type), es. /composer.json → (200, "{...}", "application/json"). Prevale su ExistingPaths.</summary>
    public Dictionary<string, (int Status, string Body, string? ContentType)> PathBodies { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>v1.4: valore dell'intestazione Allow restituita a OPTIONS (null = OPTIONS risponde 200 senza Allow).</summary>
    public string? AllowHeader { get; set; }
    /// <summary>v1.4: intestazioni aggiunte solo alle risposte HEAD della pagina principale (simula un filtro o una cache che agisce solo sulle GET).</summary>
    public List<KeyValuePair<string, string>> HeadOnlyHeaders { get; } = [];
    /// <summary>v1.4: corpo della pagina principale quando lo User-Agent contiene "Mozilla" (simula un filtro sugli User-Agent).</summary>
    public string? BrowserUaBody { get; set; }
    /// <summary>v1.4: /index.php/qualcosa risponde come /index.php (PATH_INFO).</summary>
    public bool PathInfo { get; set; }
    /// <summary>Ultimo User-Agent ricevuto.</summary>
    public string? LastUserAgent;
    /// <summary>v1.6: se &gt; 0, ogni richiesta (qualunque metodo e percorso) riceve questo stato con il corpo AllStatusBody: simula un gateway con il backend morto (502/503/504).</summary>
    public int AllStatus { get; set; }
    /// <summary>v1.7: con AllStatus, "/" risponde invece 302 verso questo URL (gateway vivo che redirige la radice, backend morto su tutto il resto).</summary>
    public string? AllStatusRootRedirect { get; set; }
    /// <summary>v1.7: ritardo in millisecondi prima di ogni risposta (misura del parallelismo).</summary>
    public int DelayMs { get; set; }
    /// <summary>v1.7: percorsi che rispondono 302 verso l'URL indicato (fonte di nomi scoperti).</summary>
    public Dictionary<string, string> Redirects { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string AllStatusBody { get; set; } = "<html><head><title>502 Bad Gateway</title></head><body><center><h1>502 Bad Gateway</h1></center><hr><center>nginx</center></body></html>";

    public int Port { get; }
    public string BaseUrl => $"http://127.0.0.1:{Port}/";
    public List<string> Requests { get; } = [];

    private readonly HttpListener _listener = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public FakePhpServer(bool anyHost = false)
    {
        Port = FreePort();
        _listener.Prefixes.Add(anyHost ? $"http://*:{Port}/" : BaseUrl);
        _listener.Start();
        _loop = Task.Run(LoopAsync);
    }

    public static int FreePort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        int p = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return p;
    }

    private async Task LoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync().ConfigureAwait(false); }
            catch { break; }
            _ = Task.Run(() => Handle(ctx));
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var resp = ctx.Response;
        try
        {
            string ct = req.ContentType ?? "";
            byte[] body = [];
            if (req.HasEntityBody)
            {
                using var ms = new MemoryStream();
                req.InputStream.CopyTo(ms);
                body = ms.ToArray();
            }
            lock (Requests) Requests.Add($"{req.HttpMethod} {req.RawUrl} [{ct}] {body.Length}");

            resp.Headers["Server"] = Server;
            if (DelayMs > 0) Thread.Sleep(DelayMs);
            if (AllStatus > 0 && AllStatusRootRedirect != null && req.Url!.AbsolutePath == "/") { resp.Headers["Location"] = AllStatusRootRedirect; Write(resp, 302, "Moved", head: req.HttpMethod == "HEAD"); return; }
            if (AllStatus > 0) { Write(resp, AllStatus, AllStatusBody, head: req.HttpMethod == "HEAD"); return; }
            if (PoweredBy != null) resp.Headers["X-Powered-By"] = PoweredBy;
            if (Waf) resp.Headers["cf-ray"] = "8a1b2c3d4e5f-FCO";

            string path = req.Url!.AbsolutePath;
            string query = req.Url.Query;
            LastUserAgent = req.UserAgent;
            if (req.HttpMethod == "OPTIONS")
            {
                if (AllowHeader != null) resp.Headers["Allow"] = AllowHeader;
                Write(resp, AllowHeader != null ? 204 : 200, "", head: true);
                return;
            }
            if (Redirects.TryGetValue(path, out var to)) { resp.Headers["Location"] = to; Write(resp, 302, "Moved", head: req.HttpMethod == "HEAD"); return; }
            if (PathBodies.TryGetValue(path, out var pb)) { Write(resp, pb.Status, pb.Body, head: req.HttpMethod == "HEAD", contentType: pb.ContentType); return; }
            if (PathInfo && path.StartsWith("/index.php/", StringComparison.Ordinal)) path = "/index.php";
            string hostHeader = req.Headers["Host"] ?? "";
            bool vhost = VhostName != null && (VhostName == "*" ? hostHeader.Length > 0 && !hostHeader.StartsWith("127.0.0.1", StringComparison.Ordinal) : hostHeader.StartsWith(VhostName, StringComparison.OrdinalIgnoreCase));
            if (!hostHeader.StartsWith("127.0.0.1", StringComparison.Ordinal) && hostHeader.Length > 0) Interlocked.Increment(ref VhostRequests);
            if (vhost && VhostPoweredBy != null) resp.Headers["X-Powered-By"] = VhostPoweredBy;

            if (Waf && (query.Contains("script", StringComparison.OrdinalIgnoreCase) || query.Contains("passwd")))
            { Write(resp, 403, "<html>Attention Required! | Cloudflare</html>"); return; }

            if (req.HttpMethod == "POST")
            {
                if (PostNotAllowed) { Write(resp, 405, "Method Not Allowed"); return; }
                bool isMultipart = ct.Trim().StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase) || ct.Contains("multipart", StringComparison.OrdinalIgnoreCase);
                bool exact = ct.StartsWith("multipart/form-data; boundary=", StringComparison.Ordinal) && !ct.Contains('"') && ct.Count(c => c == ';') == 1;
                if (isMultipart && Multipart == MultipartPolicy.BlockAll) { Write(resp, 403, "Forbidden"); return; }
                if (isMultipart && Multipart == MultipartPolicy.BlockExactOnly && exact) { Write(resp, 403, "Forbidden"); return; }
                if (isMultipart && Multipart == MultipartPolicy.BlockUploadProgressField && Encoding.ASCII.GetString(body).Contains("PHP_SESSION_UPLOAD_PROGRESS")) { Write(resp, 406, "Not Acceptable"); return; }
                if (SizeLimitBytes > 0 && body.Length > SizeLimitBytes) { Write(resp, 413, "Payload Too Large"); return; }
            }

            if (path.EndsWith("/phpinfo.php", StringComparison.Ordinal) && ExposePhpinfo)
            { Write(resp, 200, "<html><h1 class=\"p\">PHP Version 8.1.2-1ubuntu2.14</h1>phpinfo()</html>"); return; }
            if (ExistingPaths.TryGetValue(path, out int st)) { Write(resp, st, st == 200 ? "<html>exists</html>" : "", head: req.HttpMethod == "HEAD"); return; }
            if (path.EndsWith(".php", StringComparison.Ordinal) && path != "/index.php") { Write(resp, MissingPhp.Status, MissingPhp.Body, head: req.HttpMethod == "HEAD"); return; }
            if (path != "/" && path != "/index.php") { Write(resp, 404, "Not Found", head: req.HttpMethod == "HEAD"); return; }
            if (path == "/" && RedirectRootTo != null && !vhost) { resp.Headers["Location"] = RedirectRootTo; Write(resp, 302, "Moved", head: req.HttpMethod == "HEAD"); return; }

            if (SessionCookie)
            {
                string? incoming = (req.Headers["Cookie"] ?? "").Split(';', StringSplitOptions.TrimEntries).FirstOrDefault(c => c.StartsWith("PHPSESSID=", StringComparison.OrdinalIgnoreCase));
                if (incoming != null) LastSessionIdReceived = incoming["PHPSESSID=".Length..];
                if (incoming == null) resp.Headers.Add("Set-Cookie", "PHPSESSID=q1w2e3r4t5y6u7i8o9p0a1s2d3f4g5h6; path=/; HttpOnly");
                else if (StrictMode) resp.Headers.Add("Set-Cookie", "PHPSESSID=" + Guid.NewGuid().ToString("N")[..26] + "; path=/; HttpOnly");
            }
            foreach (var h in ExtraHeaders) resp.Headers.Add(h.Key, h.Value);
            if (req.HttpMethod == "HEAD") { Interlocked.Increment(ref HeadRequests); foreach (var h in HeadOnlyHeaders) resp.Headers.Add(h.Key, h.Value); }
            bool browser = BrowserUaBody != null && (req.UserAgent ?? "").Contains("Mozilla", StringComparison.Ordinal);
            Write(resp, 200, vhost ? VhostBody : browser ? BrowserUaBody! : HomeBody, head: req.HttpMethod == "HEAD");
        }
        catch { try { resp.Abort(); } catch { } }
    }

    /// <summary>Corpo della pagina principale (per simulare un'applicazione riconoscibile, es. un meta generator).</summary>
    public string HomeBody { get; set; } = "<html><body>Hello</body></html>";
    public int HeadRequests;

    private static void Write(HttpListenerResponse resp, int status, string body, bool head = false, string? contentType = null)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        resp.StatusCode = status;
        resp.ContentType = contentType ?? "text/html; charset=utf-8";
        resp.ContentLength64 = bytes.Length;
        if (!head) resp.OutputStream.Write(bytes);
        resp.Close();
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); _listener.Close(); } catch { }
        try { _loop.Wait(1000); } catch { }
    }
}
