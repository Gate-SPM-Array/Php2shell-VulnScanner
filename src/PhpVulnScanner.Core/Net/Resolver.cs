using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace PhpVulnScanner.Core.Net;

/// <summary>Esito della risoluzione di un nome: indirizzi trovati e come sono stati ottenuti.</summary>
public sealed record ResolveResult(IReadOnlyList<IPAddress> Addresses, string Source, string? Error);

/// <summary>
/// Risoluzione dei nomi. Per impostazione predefinita usa il resolver di sistema; se l'utente indica un resolver
/// esplicito (es. 1.1.1.1) le query A/AAAA vengono inviate direttamente a quel server in UDP, così l'esito non
/// dipende dal DNS interno della rete da cui si lancia la scansione (regola nata da un caso reale di risposte
/// diverse tra resolver interno e pubblici).
/// </summary>
public static class Resolver
{
    public static async Task<ResolveResult> ResolveAsync(string host, IPAddress? server, bool includeIpv6, int timeoutMs, CancellationToken ct)
    {
        if (IPAddress.TryParse(host, out var ip)) return new ResolveResult([ip], "ip", null);
        if (server is null)
        {
            try
            {
                var all = await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
                var list = all.Where(a => a.AddressFamily == AddressFamily.InterNetwork || (includeIpv6 && a.AddressFamily == AddressFamily.InterNetworkV6))
                              .Distinct().ToList();
                return new ResolveResult(list, L.T("resolver di sistema"), list.Count == 0 ? L.T("nessun indirizzo") : null);
            }
            catch (Exception ex) { return new ResolveResult([], L.T("resolver di sistema"), ex.Message); }
        }

        var result = new List<IPAddress>();
        string? err = null;
        try
        {
            result.AddRange(await QueryAsync(host, 1, server, timeoutMs, ct).ConfigureAwait(false));
            if (includeIpv6) result.AddRange(await QueryAsync(host, 28, server, timeoutMs, ct).ConfigureAwait(false));
        }
        catch (Exception ex) { err = ex.Message; }
        if (result.Count == 0 && err is null) err = L.T("nessun indirizzo");
        return new ResolveResult(result.Distinct().ToList(), server.ToString(), err);
    }

    /// <summary>Query DNS minimale (A = 1, AAAA = 28) in UDP con un solo tentativo e timeout.</summary>
    internal static async Task<List<IPAddress>> QueryAsync(string name, ushort qtype, IPAddress server, int timeoutMs, CancellationToken ct)
    {
        var query = BuildQuery(name, qtype, out ushort id);
        using var udp = new UdpClient(server.AddressFamily);
        udp.Connect(server, 53);
        await udp.SendAsync(query, ct).ConfigureAwait(false);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        UdpReceiveResult r;
        try { r = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new TimeoutException(L.T("timeout DNS")); }
        return ParseAnswers(r.Buffer, id, qtype);
    }

    private static byte[] BuildQuery(string name, ushort qtype, out ushort id)
    {
        id = (ushort)Random.Shared.Next(1, 65535);
        var ms = new MemoryStream();
        Span<byte> hdr = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(hdr, id);
        BinaryPrimitives.WriteUInt16BigEndian(hdr[2..], 0x0100);   // RD
        BinaryPrimitives.WriteUInt16BigEndian(hdr[4..], 1);
        ms.Write(hdr);
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var b = Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)b.Length);
            ms.Write(b);
        }
        ms.WriteByte(0);
        Span<byte> q = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(q, qtype);
        BinaryPrimitives.WriteUInt16BigEndian(q[2..], 1);
        ms.Write(q);
        return ms.ToArray();
    }

    internal static List<IPAddress> ParseAnswers(byte[] msg, ushort expectedId, ushort qtype)
    {
        var list = new List<IPAddress>();
        if (msg.Length < 12) throw new InvalidDataException(L.T("risposta DNS troncata"));
        if (BinaryPrimitives.ReadUInt16BigEndian(msg) != expectedId) throw new InvalidDataException(L.T("ID DNS non corrispondente"));
        int rcode = msg[3] & 0x0F;
        if (rcode == 3) return list;                         // NXDOMAIN: nessun indirizzo
        if (rcode != 0) throw new InvalidDataException(L.F("RCODE DNS {0}", rcode));
        int qd = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(4));
        int an = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(6));
        int p = 12;
        for (int i = 0; i < qd; i++) { p = SkipName(msg, p); p += 4; }
        for (int i = 0; i < an; i++)
        {
            p = SkipName(msg, p);
            if (p + 10 > msg.Length) break;
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(p));
            ushort rdlen = BinaryPrimitives.ReadUInt16BigEndian(msg.AsSpan(p + 8));
            p += 10;
            if (p + rdlen > msg.Length) break;
            if (type == qtype && ((qtype == 1 && rdlen == 4) || (qtype == 28 && rdlen == 16)))
                list.Add(new IPAddress(msg.AsSpan(p, rdlen)));
            p += rdlen;
        }
        return list;
    }

    private static int SkipName(byte[] msg, int p)
    {
        while (p < msg.Length)
        {
            int len = msg[p];
            if (len == 0) return p + 1;
            if ((len & 0xC0) == 0xC0) return p + 2;
            p += len + 1;
        }
        return p;
    }
}
