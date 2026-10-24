using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace PhpVulnScanner.Core.Net;

/// <summary>Esito della sonda FastCGI: <see cref="Exposed"/> null = non concluso (errore), true = un server FastCGI ha risposto, false = nessuna risposta FastCGI.</summary>
public sealed record FastCgiResult(bool? Exposed, string Detail, string ErrorKind, double ElapsedMs, IReadOnlyList<KeyValuePair<string, string>> Values);

/// <summary>
/// Sonda FastCGI in sola lettura: un unico record FCGI_GET_VALUES (tipo 9, requestId 0) con i tre nomi di gestione previsti
/// dalla specifica (FCGI_MAX_CONNS, FCGI_MAX_REQS, FCGI_MPXS_CONNS). Un server FastCGI risponde con FCGI_GET_VALUES_RESULT
/// (tipo 10): la risposta prova che php-fpm (o un altro server FastCGI) è esposto sulla porta TCP. Non viene mai inviato
/// un FCGI_BEGIN_REQUEST, quindi nessuno script viene eseguito e nessun parametro arriva a PHP.
/// </summary>
public static class FastCgiProbe
{
    public const int DefaultPort = 9000;
    public const byte TypeGetValues = 9;
    public const byte TypeGetValuesResult = 10;
    public static readonly string[] Names = ["FCGI_MAX_CONNS", "FCGI_MAX_REQS", "FCGI_MPXS_CONNS"];

    /// <summary>Record FCGI_GET_VALUES completo (intestazione di 8 byte, coppie nome-valore con valore vuoto, riempimento a multipli di 8).</summary>
    public static byte[] BuildGetValues()
    {
        var content = new List<byte>();
        foreach (var n in Names)
        {
            var nb = Encoding.ASCII.GetBytes(n);
            content.Add((byte)nb.Length);   // nameLength (< 128: un byte)
            content.Add(0);                 // valueLength = 0
            content.AddRange(nb);
        }
        int pad = (8 - content.Count % 8) % 8;
        var rec = new byte[8 + content.Count + pad];
        rec[0] = 1;                                  // version
        rec[1] = TypeGetValues;                      // type
        BinaryPrimitives.WriteUInt16BigEndian(rec.AsSpan(2), 0);                       // requestId 0 (gestione)
        BinaryPrimitives.WriteUInt16BigEndian(rec.AsSpan(4), (ushort)content.Count);   // contentLength
        rec[6] = (byte)pad;                          // paddingLength
        rec[7] = 0;                                  // reserved
        content.CopyTo(rec, 8);
        return rec;
    }

    /// <summary>
    /// Interpreta i byte ricevuti: vero se contengono un record FCGI_GET_VALUES_RESULT ben formato (versione 1, tipo 10, requestId 0);
    /// le coppie nome-valore lette finiscono in <paramref name="values"/>.
    /// </summary>
    public static bool TryParseResult(ReadOnlySpan<byte> data, out List<KeyValuePair<string, string>> values)
    {
        values = [];
        if (data.Length < 8) return false;
        if (data[0] != 1 || data[1] != TypeGetValuesResult) return false;
        if (BinaryPrimitives.ReadUInt16BigEndian(data.Slice(2)) != 0) return false;
        int len = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(4));
        if (len > data.Length - 8) len = data.Length - 8;   // risposta troncata: si legge ciò che c'è
        var body = data.Slice(8, len);
        int p = 0;
        while (p < body.Length)
        {
            if (!ReadLength(body, ref p, out int nl) || !ReadLength(body, ref p, out int vl)) break;
            if (nl < 0 || vl < 0 || p + nl + vl > body.Length) break;
            string name = Encoding.ASCII.GetString(body.Slice(p, nl));
            string value = Encoding.ASCII.GetString(body.Slice(p + nl, vl));
            p += nl + vl;
            if (name.Length > 0) values.Add(new(name, value));
        }
        return true;
    }

    private static bool ReadLength(ReadOnlySpan<byte> b, ref int p, out int len)
    {
        len = -1;
        if (p >= b.Length) return false;
        if ((b[p] & 0x80) == 0) { len = b[p]; p++; return true; }
        if (p + 4 > b.Length) return false;
        len = (int)(BinaryPrimitives.ReadUInt32BigEndian(b.Slice(p)) & 0x7FFFFFFF);
        p += 4;
        return true;
    }

    /// <summary>Connessione TCP a <paramref name="host"/>:<paramref name="port"/>, invio del solo FCGI_GET_VALUES, lettura della risposta entro il timeout.</summary>
    public static async Task<FastCgiResult> ProbeAsync(string host, int port, int timeoutMs, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        using var sock = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await sock.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException)
        {
            return new FastCgiResult(false, L.F("nessuna connessione a tcp/{0} entro {1} ms (porta filtrata o host muto)", port, timeoutMs), "timeout", sw.Elapsed.TotalMilliseconds, []);
        }
        catch (SocketException ex)
        {
            return new FastCgiResult(false, L.F("tcp/{0} chiusa ({1})", port, ex.SocketErrorCode), "connect", sw.Elapsed.TotalMilliseconds, []);
        }
        catch (Exception ex)
        {
            return new FastCgiResult(null, ex.GetBaseException().Message, "other", sw.Elapsed.TotalMilliseconds, []);
        }

        try
        {
            await sock.SendAsync(BuildGetValues(), SocketFlags.None, cts.Token).ConfigureAwait(false);
            var buf = new byte[4096];
            int total = 0;
            // si legge finché il record annunciato è completo, la connessione si chiude o scade il timeout
            while (total < buf.Length)
            {
                int n = await sock.ReceiveAsync(buf.AsMemory(total), SocketFlags.None, cts.Token).ConfigureAwait(false);
                if (n <= 0) break;
                total += n;
                if (total >= 8)
                {
                    int want = 8 + BinaryPrimitives.ReadUInt16BigEndian(buf.AsSpan(4)) + buf[6];
                    if (total >= want) break;
                }
            }
            if (total == 0)
                return new FastCgiResult(false, L.F("tcp/{0} aperta ma nessun record FastCGI in risposta (altro servizio sulla porta)", port), "silent", sw.Elapsed.TotalMilliseconds, []);
            if (TryParseResult(buf.AsSpan(0, total), out var values))
            {
                string shown = values.Count > 0 ? string.Join(", ", values.Select(v => v.Key + "=" + v.Value)) : L.T("(nessun valore restituito)");
                return new FastCgiResult(true, L.F("FCGI_GET_VALUES_RESULT ricevuto da tcp/{0}: {1}", port, shown), "", sw.Elapsed.TotalMilliseconds, values);
            }
            return new FastCgiResult(false, L.F("tcp/{0} risponde ma non con un record FastCGI ({1} byte, primo byte 0x{2:X2})", port, total, buf[0]), "invalid", sw.Elapsed.TotalMilliseconds, []);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (OperationCanceledException)
        {
            return new FastCgiResult(false, L.F("tcp/{0} aperta, nessuna risposta FastCGI entro {1} ms", port, timeoutMs), "timeout", sw.Elapsed.TotalMilliseconds, []);
        }
        catch (SocketException ex)
        {
            return new FastCgiResult(false, L.F("tcp/{0}: connessione chiusa dal server ({1})", port, ex.SocketErrorCode), "reset", sw.Elapsed.TotalMilliseconds, []);
        }
        catch (Exception ex)
        {
            return new FastCgiResult(null, ex.GetBaseException().Message, "other", sw.Elapsed.TotalMilliseconds, []);
        }
    }
}
