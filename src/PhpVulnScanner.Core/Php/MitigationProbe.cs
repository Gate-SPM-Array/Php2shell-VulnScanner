using PhpVulnScanner.Core.Engine;
using PhpVulnScanner.Core.Net;

namespace PhpVulnScanner.Core.Php;

/// <summary>
/// Livello 2: precondizioni e barriere. Richieste piccole e inerti: una POST url-encoded e una multipart minime sul
/// percorso principale, le varianti di Content-Type se il multipart è bloccato, il nome di campo
/// PHP_SESSION_UPLOAD_PROGRESS senza cookie (PHP non scrive nulla senza sessione), un multipart di dimensione
/// configurabile per scoprire i limiti al perimetro. Nessuna di queste richieste porta PHP in esaurimento memoria.
/// </summary>
public static class MitigationProbe
{
    public static readonly int[] BlockCodes = [403, 406, 418, 429, 501, 503];

    /// <summary>Varianti di Content-Type che un blocco al proxy scritto sulla stringa esatta può lasciar passare.</summary>
    public static IReadOnlyList<(string Label, string ContentType)> Variants(string b) =>
    [
        ("maiuscole", $"MULTIPART/FORM-DATA; boundary={b}"),
        ("iniziali maiuscole", $"Multipart/Form-Data; boundary={b}"),
        ("senza spazio", $"multipart/form-data;boundary={b}"),
        ("charset prima del boundary", $"multipart/form-data; charset=utf-8; boundary={b}"),
        ("boundary tra virgolette", $"multipart/form-data; boundary=\"{b}\""),
        ("spazio prima del punto e virgola", $"multipart/form-data ; boundary={b}"),
        ("parametro aggiuntivo", $"multipart/form-data; boundary={b}; x=y"),
        ("tabulazione", $"multipart/form-data;\tboundary={b}"),
    ];

    public static async Task RunAsync(ScanContext ctx)
    {
        var r = ctx.Result;
        string path = ctx.PrimaryPath;
        string boundary = "----PhpVulnScanner" + Guid.NewGuid().ToString("N")[..12];
        var field = new[] { new KeyValuePair<string, string>("a", "1") };

        var form = await ctx.PostAsync(path, HttpProbe.FormContent()).ConfigureAwait(false);
        r.Add("L2-POST", L.T("POST url-encoded di controllo"), form.HasResponse ? TestOutcome.Info : TestOutcome.Error, form.HasResponse ? L.F("stato {0}", form.Status) : form.Error ?? "", form);

        var multi = await ctx.PostAsync(path, HttpProbe.MultipartContent(field, boundary)).ConfigureAwait(false);
        r.Add("L2-MULTIPART", L.T("POST multipart minimo"), multi.HasResponse ? TestOutcome.Info : TestOutcome.Error, multi.HasResponse ? L.F("stato {0}", multi.Status) : multi.Error ?? "", multi);

        if (!form.HasResponse && !multi.HasResponse)
        {
            r.Multipart = MultipartBarrier.NoResponse;
            r.MultipartDetail = L.T("nessuna risposta alle POST");
            return;
        }

        bool formBlocked = form.HasResponse && BlockCodes.Contains(form.Status);
        bool multiBlocked = (multi.HasResponse && BlockCodes.Contains(multi.Status)) || (!multi.HasResponse && form.HasResponse && multi.ErrorKind is "reset" or "timeout" or "invalid");

        if (form.HasResponse && multi.HasResponse && form.Status == 405 && multi.Status == 405)
        {
            r.Multipart = MultipartBarrier.PostNotAllowed;
            r.MultipartDetail = L.F("POST non consentito su {0} (405): PHP legge il corpo solo delle POST, su questo percorso il vettore non si applica", path);
            r.Add("L2-BARRIER", L.T("Barriera multipart"), TestOutcome.Pass, r.MultipartDetail);
            return;
        }

        if (multiBlocked && !formBlocked)
        {
            // c'è una barriera specifica sul multipart: quanto è robusta?
            var variants = Variants(boundary);
            int blocked = 0;
            var passed = new List<string>();
            foreach (var (label, ctype) in variants)
            {
                ctx.Ct.ThrowIfCancellationRequested();
                var s = await ctx.PostAsync(path, HttpProbe.MultipartContent(field, boundary, ctype)).ConfigureAwait(false);
                bool b = (s.HasResponse && BlockCodes.Contains(s.Status)) || (!s.HasResponse && s.ErrorKind is "reset" or "timeout" or "invalid");
                if (b) blocked++; else passed.Add(label);
                r.Add("L2-VARIANT", L.F("Variante Content-Type: {0}", label), b ? TestOutcome.Pass : TestOutcome.Fail,
                    b ? L.F("bloccata ({0})", s.Summary) : L.F("PASSA ({0}): il blocco confronta la stringa esatta", s.Summary), s);
            }
            r.VariantsTotal = variants.Count;
            r.VariantsBlocked = blocked;
            if (passed.Count == 0)
            {
                r.Multipart = MultipartBarrier.Blocked;
                r.MultipartDetail = L.F("multipart respinto ({0}) mentre la POST url-encoded passa ({1}); tutte le {2} varianti di Content-Type bloccate", multi.Summary, form.Status, variants.Count);
                r.Add("L2-BARRIER", L.T("Barriera multipart"), TestOutcome.Pass, r.MultipartDetail);
            }
            else
            {
                r.Multipart = MultipartBarrier.PartiallyBlocked;
                r.MultipartDetail = L.F("multipart canonico respinto ({0}) ma {1} varianti su {2} passano: {3}", multi.Summary, passed.Count, variants.Count, string.Join(", ", passed));
                r.Add("L2-BARRIER", L.T("Barriera multipart"), TestOutcome.Warn, r.MultipartDetail);
            }
            return;
        }

        if (formBlocked && multiBlocked)
        {
            r.Multipart = MultipartBarrier.Blocked;
            r.MultipartDetail = L.F("tutte le POST respinte ({0}): barriera generica sul metodo o sul percorso, non specifica del multipart", multi.Summary);
            r.Add("L2-BARRIER", L.T("Barriera multipart"), TestOutcome.Pass, r.MultipartDetail);
            return;
        }

        // multipart accettato: il corpo raggiunge PHP (se PHP c'è)
        r.Multipart = MultipartBarrier.Accepted;
        r.MultipartDetail = multi.HasResponse
            ? L.F("multipart accettato ({0}): nessuna barriera al perimetro su {1}", multi.Summary, path)
            : L.F("multipart senza risposta ({0}) ma url-encoded {1}: non classificabile come barriera", multi.Error, form.Status);
        r.Add("L2-BARRIER", L.T("Barriera multipart"), multi.HasResponse ? TestOutcome.Fail : TestOutcome.Warn, r.MultipartDetail);

        // Nome di campo dell'upload progress, senza cookie di sessione: PHP ignora il campo, un WAF che lo filtra lo respinge
        var up = await ctx.PostAsync(path, HttpProbe.MultipartContent(
            [new("PHP_SESSION_UPLOAD_PROGRESS", "probe"), new("a", "1")], boundary)).ConfigureAwait(false);
        if (up.HasResponse)
        {
            bool blocked = BlockCodes.Contains(up.Status) && !BlockCodes.Contains(multi.Status);
            r.UploadProgressFieldBlocked = blocked;
            r.Add("L2-UPLOADPROGRESS", L.T("Campo PHP_SESSION_UPLOAD_PROGRESS"), blocked ? TestOutcome.Pass : TestOutcome.Info,
                blocked ? L.F("respinto ({0}): regola specifica sul nome del campo", up.Summary)
                        : L.F("accettato ({0}): nessun filtro sul nome del campo (inviato senza cookie: PHP non ha scritto alcuna sessione)", up.Summary), up);
        }
        else r.Add("L2-UPLOADPROGRESS", L.T("Campo PHP_SESSION_UPLOAD_PROGRESS"), TestOutcome.Error, up.Error ?? "", up);

        // Limite di dimensione al perimetro
        int kib = Math.Max(1, ctx.Config.SizeProbeKiB);
        var big = HttpProbe.MultipartContent([new("a", new string('A', kib * 1024))], boundary);
        var sz = await ctx.PostAsync(path, big, Math.Max(ctx.Config.ReadTimeoutMs, 15000)).ConfigureAwait(false);
        if (sz.HasResponse)
        {
            if (sz.Status == 413 || (BlockCodes.Contains(sz.Status) && !BlockCodes.Contains(multi.Status)))
            {
                r.SizeLimit = L.F("respinto a {0} KiB ({1})", kib, sz.Summary);
                r.Add("L2-SIZE", L.F("Multipart di {0} KiB", kib), TestOutcome.Pass, L.F("limite di dimensione al perimetro sotto {0} KiB ({1})", kib, sz.Summary), sz);
            }
            else
            {
                r.SizeLimit = L.F("accettato {0} KiB ({1})", kib, sz.Summary);
                r.Add("L2-SIZE", L.F("Multipart di {0} KiB", kib), TestOutcome.Info, L.F("accettato ({0}): nessun limite di dimensione sotto {1} KiB", sz.Summary, kib), sz);
            }
        }
        else
        {
            r.SizeLimit = L.F("nessuna risposta a {0} KiB ({1})", kib, sz.Error);
            r.Add("L2-SIZE", L.F("Multipart di {0} KiB", kib), TestOutcome.Warn, L.F("nessuna risposta ({0}): connessione chiusa durante l'invio, possibile limite senza 413", sz.Error), sz);
        }
    }
}
