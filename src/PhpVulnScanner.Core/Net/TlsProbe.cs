using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace PhpVulnScanner.Core.Net;

/// <summary>Dati del certificato e della sessione TLS osservati, usati per decidere lo schema e come indizi di CDN/WAF.</summary>
public sealed class TlsInfo
{
    public bool Handshake { get; init; }
    public string? Error { get; init; }
    public string Protocol { get; init; } = "";
    public string Subject { get; init; } = "";
    public string Issuer { get; init; } = "";
    public DateTime? NotAfter { get; init; }
    public List<string> SubjectAltNames { get; init; } = [];
    public string Thumbprint { get; init; } = "";
    public bool NameMatches { get; init; }
    // ---- v1.6: stato del certificato ----
    public DateTime? NotBefore { get; init; }
    /// <summary>Emittente uguale al soggetto, oppure catena di un solo elemento con la foglia come radice.</summary>
    public bool SelfSigned { get; init; }
    /// <summary>Catena verificata con le radici del sistema (senza revoca): null quando non verificata.</summary>
    public bool? ChainTrusted { get; init; }
    public string ChainError { get; init; } = "";
    /// <summary>Lunghezza della chiave pubblica in bit (0 se ignota).</summary>
    public int KeyBits { get; init; }
    /// <summary>Algoritmo di firma del certificato (nome amichevole, es. sha256RSA).</summary>
    public string SignatureAlgorithm { get; init; } = "";
    /// <summary>Giorni alla scadenza al momento dell'osservazione (negativi se scaduto); null senza certificato.</summary>
    public int? DaysToExpiry { get; init; }
    /// <summary>Porta chiusa (RST) o nessuna risposta al SYN: inutile tentare HTTP sulla stessa porta.</summary>
    public bool ConnectFailed { get; init; }
    /// <summary>Connessione accettata ma nessuna risposta all'handshake entro il timeout (porta aperta ma muta, tarpit, filtro).</summary>
    public bool Silent { get; init; }
    public double ElapsedMs { get; init; }

    public string Summary => Handshake ? $"{Protocol}; CN={Subject}; {L.T("emesso da")} {Issuer}" : (Error ?? "");
}

/// <summary>Handshake TLS separato (SslStream): certificato e protocollo, senza verificare la catena.</summary>
public static class TlsProbe
{
    public static async Task<TlsInfo> ProbeAsync(string host, int port, string sniName, int timeoutMs, CancellationToken ct)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            using var tcp = new TcpClient();
            try { await tcp.ConnectAsync(host, port, cts.Token).ConfigureAwait(false); }
            catch (SocketException ex) { return new TlsInfo { Error = ex.Message, ConnectFailed = true, ElapsedMs = sw.Elapsed.TotalMilliseconds }; }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return new TlsInfo { Error = L.T("timeout di connessione"), ConnectFailed = true, ElapsedMs = sw.Elapsed.TotalMilliseconds }; }
            X509Certificate2? cert = null;
            var extra = new List<X509Certificate2>();
            await using var ssl = new SslStream(tcp.GetStream(), false, (_, c, ch, _) =>
            {
                if (c != null) cert = new X509Certificate2(c);
                // intermedi inviati dal server: servono alla verifica offline della catena (nessun download)
                if (ch != null) foreach (var el in ch.ChainElements) extra.Add(el.Certificate);
                return true;
            });
            var opts = new SslClientAuthenticationOptions
            {
                TargetHost = sniName,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            };
            await ssl.AuthenticateAsClientAsync(opts, cts.Token).ConfigureAwait(false);
            return Describe(cert, sniName, ssl.SslProtocol.ToString(), sw.Elapsed.TotalMilliseconds, extra);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return new TlsInfo { Error = L.T("timeout dell'handshake (porta aperta ma muta)"), Silent = true, ElapsedMs = sw.Elapsed.TotalMilliseconds }; }
        catch (Exception ex) { return new TlsInfo { Error = ex.GetBaseException().Message, ElapsedMs = sw.Elapsed.TotalMilliseconds }; }
    }

    private static readonly System.Text.RegularExpressions.Regex SanPrefixRx = new(@"^(?:DNS|IP(?: Address)?|URI|email|othername|DirName|RID)\s*:\s*", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>Descrive il certificato presentato: nomi, validità, autofirma, catena (verificata offline, senza revoca), chiave e firma.</summary>
    public static TlsInfo Describe(X509Certificate2? cert, string hostName, string protocol = "", double elapsedMs = 0, IReadOnlyList<X509Certificate2>? intermediates = null)
    {
        var sans = new List<string>();
        bool nameOk = false;
        bool selfSigned = false;
        bool? trusted = null;
        string chainError = "";
        int keyBits = 0;
        string sigAlg = "";
        int? days = null;
        if (cert != null)
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid?.Value != "2.5.29.17") continue;
                foreach (var line in ext.Format(true).Split(['\n', '\r', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    int eq = line.IndexOf('=');
                    string v = eq >= 0 ? line[(eq + 1)..].Trim() : SanPrefixRx.Replace(line, "").Trim();   // Windows "DNS Name=x", Linux/OpenSSL "DNS:x"
                    if (v.Length > 0 && !sans.Contains(v)) sans.Add(v);
                }
            }
            try { nameOk = hostName.Length > 0 && cert.MatchesHostname(hostName, true, false); } catch { nameOk = false; }
            selfSigned = string.Equals(cert.SubjectName.Name, cert.IssuerName.Name, StringComparison.Ordinal);
            try { sigAlg = cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? ""; } catch { }
            try { keyBits = cert.PublicKey.GetRSAPublicKey()?.KeySize ?? cert.PublicKey.GetECDsaPublicKey()?.KeySize ?? cert.PublicKey.GetDSAPublicKey()?.KeySize ?? 0; } catch { }
            days = (int)Math.Floor((cert.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays);
            try
            {
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.DisableCertificateDownloads = true;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(2);
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;   // la scadenza è riportata a parte
                if (intermediates != null) foreach (var ic in intermediates) if (ic.Thumbprint != cert.Thumbprint) chain.ChainPolicy.ExtraStore.Add(ic);
                trusted = chain.Build(cert);
                if (chain.ChainElements.Count == 1 && chain.ChainElements[0].Certificate.Thumbprint == cert.Thumbprint) selfSigned = true;
                if (trusted == false)
                {
                    var statuses = chain.ChainStatus.Select(st => st.Status.ToString()).Where(x => x.Length > 0).Distinct().ToList();
                    chainError = statuses.Count > 0 ? string.Join(", ", statuses) : "UntrustedRoot";
                }
            }
            catch (Exception ex) { trusted = null; chainError = ex.GetBaseException().Message; }
        }
        return new TlsInfo
        {
            Handshake = true,
            Protocol = protocol,
            Subject = cert?.GetNameInfo(X509NameType.SimpleName, false) ?? "",
            Issuer = cert?.GetNameInfo(X509NameType.SimpleName, true) ?? "",
            NotAfter = cert?.NotAfter,
            NotBefore = cert?.NotBefore,
            SubjectAltNames = sans,
            Thumbprint = cert?.Thumbprint ?? "",
            NameMatches = nameOk,
            SelfSigned = selfSigned,
            ChainTrusted = trusted,
            ChainError = chainError,
            KeyBits = keyBits,
            SignatureAlgorithm = sigAlg,
            DaysToExpiry = days,
            ElapsedMs = elapsedMs,
        };
    }
}
