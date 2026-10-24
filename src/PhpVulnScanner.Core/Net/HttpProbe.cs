using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Text;

namespace PhpVulnScanner.Core.Net;

/// <summary>Punto di contatto HTTP di un bersaglio: schema, host (IP o nome), porta.</summary>
public sealed record HttpEndpoint(string Scheme, string Host, int Port)
{
    /// <summary>Indirizzo a cui connettersi davvero quando <see cref="Host"/> è un nome scoperto (vhost su un IP): la URL, l'header Host e lo SNI portano il nome, il TCP va all'IP.</summary>
    public string? ConnectHost { get; init; }
    public string BaseUrl => $"{Scheme}://{FormatHost(Host)}:{Port}";
    public string Url(string path) => BaseUrl + (path.StartsWith('/') ? path : "/" + path);
    public static string FormatHost(string host) => host.Contains(':') && !host.StartsWith('[') ? $"[{host}]" : host;
    public override string ToString() => $"{Host}:{Port} ({Scheme})";
}

/// <summary>Fotografia di una risposta HTTP: ciò che serve per ragionare sui risultati e per il report.</summary>
public sealed class HttpSnapshot
{
    /// <summary>v1.6: istante locale (UTC) in cui la risposta è arrivata, per confrontare l'header Date con il nostro orologio.</summary>
    public DateTime? ReceivedUtc { get; set; }

    public string Method { get; init; } = "GET";
    public string Url { get; init; } = "";
    public int Status { get; init; }                      // 0 = nessuna risposta (errore in Error)
    public string Reason { get; init; } = "";
    public string Version { get; init; } = "";
    public List<KeyValuePair<string, string>> Headers { get; init; } = [];
    public string Body { get; init; } = "";               // primi byte decodificati (max MaxBody)
    public long BodyLength { get; init; }                 // byte letti (fino al limite)
    public bool BodyTruncated { get; init; }
    public double ElapsedMs { get; init; }
    public string? Error { get; init; }
    public string? ErrorKind { get; init; }               // "timeout", "connect", "tls", "reset", "other"
    /// <summary>Intestazioni inviate (solo in modalità debug), per riprodurre la richiesta.</summary>
    public List<KeyValuePair<string, string>>? RequestHeaders { get; init; }

    public bool HasResponse => Status > 0;

    public string? Header(string name) =>
        Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    public IEnumerable<string> HeaderValues(string name) =>
        Headers.Where(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value);

    public string Summary => HasResponse ? $"{Status} {Reason}".Trim() : (Error ?? "?");
}

/// <summary>Client HTTP con timeout separati di connessione e lettura, nessun redirect automatico, certificati non verificati
/// (lo scopo è osservare, non fidarsi) e cattura di stato, intestazioni, inizio del corpo e tempi.</summary>
public sealed class HttpProbe : IDisposable
{
    public const int MaxBody = 64 * 1024;
    /// <summary>User-Agent dichiarato: lo scanner non si nasconde (uso responsabile, tracciabilità nei log del bersaglio).</summary>
    public static string UserAgent { get; } = "PhpVulnScanner/" + AppVersion + " (+defensive scan; https://github.com/Gate-SPM-Array/PhpVulnScanner)";

    /// <summary>Versione del programma: "X.Y" quando la patch è 0, altrimenti "X.Y.Z".</summary>
    public static string AppVersion { get; } =
        typeof(HttpProbe).Assembly.GetName().Version is { } v ? (v.Build == 0 ? $"{v.Major}.{v.Minor}" : $"{v.Major}.{v.Minor}.{v.Build}") : "1.0";

    /// <summary>Limite del corpo in modalità debug.</summary>
    public const int MaxBodyDebug = 1024 * 1024;

    private static readonly HttpRequestOptionsKey<string> ConnectToKey = new("PhpVulnScanner.ConnectTo");

    private readonly HttpClient _client;
    private readonly int _readTimeoutMs;
    private readonly int _maxBody;
    private readonly bool _debug;

    public HttpProbe(int connectTimeoutMs, int readTimeoutMs, string? proxyUrl = null, bool debug = false)
    {
        _debug = debug;
        _maxBody = debug ? MaxBodyDebug : MaxBody;
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = !string.IsNullOrWhiteSpace(proxyUrl),
            Proxy = string.IsNullOrWhiteSpace(proxyUrl) ? null : new WebProxy(proxyUrl),
            ConnectTimeout = TimeSpan.FromMilliseconds(connectTimeoutMs),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            AutomaticDecompression = DecompressionMethods.None,
            MaxResponseHeadersLength = 256,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            },
            // Connessione a un indirizzo diverso dal nome nella URL (vhost scoperto su un IP): la URL porta il nome,
            // quindi Host e SNI sono il nome, mentre il TCP va all'IP indicato nelle opzioni della richiesta.
            ConnectCallback = static async (ctx, ct) =>
            {
                string host = ctx.DnsEndPoint.Host;
                if (ctx.InitialRequestMessage.Options.TryGetValue(ConnectToKey, out var to) && !string.IsNullOrEmpty(to)) host = to;
                var sock = new System.Net.Sockets.Socket(System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await sock.ConnectAsync(host, ctx.DnsEndPoint.Port, ct).ConfigureAwait(false);
                    return new System.Net.Sockets.NetworkStream(sock, ownsSocket: true);
                }
                catch { sock.Dispose(); throw; }
            },
        };
        _client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        _client.DefaultRequestVersion = HttpVersion.Version11;
        _client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
        _readTimeoutMs = readTimeoutMs;
    }

    public Task<HttpSnapshot> GetAsync(HttpEndpoint ep, string path, CancellationToken ct, string? hostHeader = null,
                                       IEnumerable<KeyValuePair<string, string>>? headers = null, int? readTimeoutMs = null) =>
        SendAsync(ep, HttpMethod.Get, path, null, ct, hostHeader, headers, readTimeoutMs);

    public Task<HttpSnapshot> PostAsync(HttpEndpoint ep, string path, HttpContent content, CancellationToken ct, string? hostHeader = null,
                                        IEnumerable<KeyValuePair<string, string>>? headers = null, int? readTimeoutMs = null) =>
        SendAsync(ep, HttpMethod.Post, path, content, ct, hostHeader, headers, readTimeoutMs);

    public async Task<HttpSnapshot> SendAsync(HttpEndpoint ep, HttpMethod method, string path, HttpContent? content, CancellationToken ct,
                                              string? hostHeader = null, IEnumerable<KeyValuePair<string, string>>? headers = null, int? readTimeoutMs = null)
    {
        string url = ep.Url(path);
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(readTimeoutMs ?? _readTimeoutMs);
        try
        {
            using var req = new HttpRequestMessage(method, url);
            req.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            req.Headers.TryAddWithoutValidation("Accept", "*/*");
            req.Headers.TryAddWithoutValidation("Connection", "close");
            if (!string.IsNullOrEmpty(hostHeader)) req.Headers.Host = hostHeader;
            if (headers != null) foreach (var h in headers) req.Headers.TryAddWithoutValidation(h.Key, h.Value);
            if (!string.IsNullOrEmpty(ep.ConnectHost)) req.Options.Set(ConnectToKey, ep.ConnectHost);
            req.Content = content;
            List<KeyValuePair<string, string>>? sent = null;
            if (_debug)
            {
                sent = [];
                sent.Add(new("Host", hostHeader ?? HttpEndpoint.FormatHost(ep.Host) + (ep.Port is 80 or 443 ? "" : ":" + ep.Port)));
                foreach (var h in req.Headers.NonValidated) foreach (var v in h.Value) sent.Add(new(h.Key, v));
                if (content != null) foreach (var h in content.Headers.NonValidated) foreach (var v in h.Value) sent.Add(new(h.Key, v));
                if (!string.IsNullOrEmpty(ep.ConnectHost)) sent.Add(new("(connect-to)", ep.ConnectHost));
            }

            using var resp = await _client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
            var receivedUtc = DateTime.UtcNow;   // v1.6: ora di ricezione delle intestazioni, per confrontare l'header Date con il nostro orologio
            var hdrs = new List<KeyValuePair<string, string>>();
            // NonValidated: valori grezzi come ricevuti. L'enumerazione normale spezza "Server: Apache/2.4 (Debian) PHP/8.3" in tre valori
            // e nasconderebbe la versione di PHP nel banner.
            foreach (var h in resp.Headers.NonValidated) foreach (var v in h.Value) hdrs.Add(new(h.Key, v));
            foreach (var h in resp.Content.Headers.NonValidated) foreach (var v in h.Value) hdrs.Add(new(h.Key, v));

            byte[] buf = new byte[_maxBody];
            int total = 0;
            bool truncated = false;
            try
            {
                await using var stream = await resp.Content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
                while (total < buf.Length)
                {
                    int n = await stream.ReadAsync(buf.AsMemory(total), cts.Token).ConfigureAwait(false);
                    if (n <= 0) break;
                    total += n;
                }
                if (total >= buf.Length)
                {
                    truncated = true;
                    // scarta il resto senza tenerlo in memoria, entro il timeout
                    byte[] sink = new byte[16 * 1024];
                    while (await stream.ReadAsync(sink, cts.Token).ConfigureAwait(false) > 0) { }
                }
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { truncated = true; }   // corpo lento: teniamo ciò che abbiamo
            catch (IOException) { truncated = true; }
            catch (HttpRequestException) { truncated = true; }

            return new HttpSnapshot
            {
                Method = method.Method, Url = url, Status = (int)resp.StatusCode, Reason = resp.ReasonPhrase ?? "",
                Version = "HTTP/" + resp.Version, Headers = hdrs, Body = Decode(buf, total), BodyLength = total,
                BodyTruncated = truncated, ElapsedMs = sw.Elapsed.TotalMilliseconds, RequestHeaders = sent, ReceivedUtc = receivedUtc,
            };
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException)
        {
            return Fail(method, url, sw, L.T("timeout di lettura"), "timeout");
        }
        catch (HttpRequestException ex)
        {
            var baseEx = ex.GetBaseException();
            string kind = ex.HttpRequestError switch
            {
                HttpRequestError.ConnectionError => "connect",
                HttpRequestError.SecureConnectionError => "tls",
                HttpRequestError.NameResolutionError => "dns",
                HttpRequestError.ResponseEnded => "reset",
                HttpRequestError.InvalidResponse => "invalid",
                _ => baseEx is System.Net.Sockets.SocketException ? "connect" : "other",
            };
            if (baseEx is TaskCanceledException or TimeoutException) kind = "timeout";
            return Fail(method, url, sw, baseEx.Message, kind);
        }
        catch (Exception ex)
        {
            return Fail(method, url, sw, ex.GetBaseException().Message, "other");
        }
    }

    private static HttpSnapshot Fail(HttpMethod m, string url, Stopwatch sw, string error, string kind) =>
        new() { Method = m.Method, Url = url, Error = error, ErrorKind = kind, ElapsedMs = sw.Elapsed.TotalMilliseconds };

    private static string Decode(byte[] buf, int len)
    {
        if (len == 0) return "";
        try { return new UTF8Encoding(false, false).GetString(buf, 0, len); }
        catch { return Encoding.Latin1.GetString(buf, 0, len); }
    }

    /// <summary>Corpo url-encoded <c>a=1</c>.</summary>
    public static HttpContent FormContent(string body = "a=1")
    {
        var c = new ByteArrayContent(Encoding.ASCII.GetBytes(body));
        c.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
        return c;
    }

    /// <summary>Corpo multipart con i campi indicati e il Content-Type esatto richiesto (anche varianti non canoniche).</summary>
    public static HttpContent MultipartContent(IEnumerable<KeyValuePair<string, string>> fields, string boundary, string? contentTypeOverride = null)
    {
        var sb = new StringBuilder();
        foreach (var f in fields)
        {
            sb.Append("--").Append(boundary).Append("\r\n");
            sb.Append("Content-Disposition: form-data; name=\"").Append(f.Key).Append("\"\r\n\r\n");
            sb.Append(f.Value).Append("\r\n");
        }
        sb.Append("--").Append(boundary).Append("--\r\n");
        var c = new ByteArrayContent(Encoding.ASCII.GetBytes(sb.ToString()));
        c.Headers.TryAddWithoutValidation("Content-Type", contentTypeOverride ?? ("multipart/form-data; boundary=" + boundary));
        return c;
    }

    /// <summary>Corpo multipart già costruito in byte (per i corpi grandi del livello 3).</summary>
    public static HttpContent RawContent(byte[] body, string contentType)
    {
        var c = new ByteArrayContent(body);
        c.Headers.TryAddWithoutValidation("Content-Type", contentType);
        return c;
    }

    public void Dispose() => _client.Dispose();
}
