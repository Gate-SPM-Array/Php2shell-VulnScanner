using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PhpVulnScanner.Core.Output;

/// <summary>
/// Pacchetto per analisi (v1.10): zip di una cartella di sessione con <c>results.json</c> e <c>results.jsonl</c> <b>senza i corpi delle risposte</b>
/// (al posto del corpo: lunghezza e SHA-256, così resta confrontabile), più session.json, scan.log, CSV, report, file degli host ed elenco per Excel.
/// Motivo: gli zip di sessione in debug pesano 60-700 MB per i corpi; senza corpi stanno in pochi MB e passano i limiti di upload (30 MB).
/// Le analisi (tempi per fase, thread, verdetti, indizi, test) usano tutto il resto. samples.json resta fuori (può contenere nomi dell'ente nei corpi).
/// </summary>
public static class AnalysisBundle
{
    public static string DefaultName(string sessionFolder, string appVersion) => Path.GetFileName(sessionFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)) + $"_analisi_v{appVersion}.zip";

    /// <summary>Crea lo zip e restituisce il percorso. I file mancanti vengono saltati.</summary>
    public static string Build(string sessionFolder, string zipPath)
    {
        if (File.Exists(zipPath)) File.Delete(zipPath);
        using var zip = ZipFile.Open(zipPath, ZipArchiveMode.Create);
        foreach (var file in Directory.EnumerateFiles(sessionFolder).OrderBy(f => f, StringComparer.Ordinal))
        {
            string name = Path.GetFileName(file);
            if (name.Equals(SessionFiles.SamplesJson, StringComparison.OrdinalIgnoreCase)) continue;
            if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) continue;
            bool strip = name.Equals(SessionFiles.ResultsJson, StringComparison.OrdinalIgnoreCase) || name.Equals(SessionFiles.ResultsJsonl, StringComparison.OrdinalIgnoreCase);
            var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
            using var outStream = entry.Open();
            if (!strip) { using var src = File.OpenRead(file); src.CopyTo(outStream); continue; }
            if (name.EndsWith(".jsonl", StringComparison.OrdinalIgnoreCase))
            {
                using var writer = new StreamWriter(outStream, new UTF8Encoding(false));
                foreach (var line in File.ReadLines(file))
                {
                    if (line.Length == 0) continue;
                    writer.WriteLine(StripBodies(line));
                }
            }
            else
            {
                string text = File.ReadAllText(file, Encoding.UTF8);
                using var writer = new StreamWriter(outStream, new UTF8Encoding(false));
                writer.Write(StripBodies(text));
            }
        }
        return zipPath;
    }

    /// <summary>Copia un documento JSON sostituendo ogni valore stringa della proprietà <c>Body</c> con "&lt;rimosso: N byte, sha256 …&gt;"; tutto il resto resta identico.</summary>
    public static string StripBodies(string json)
    {
        var bytes = Encoding.UTF8.GetBytes(json);
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = json.Contains('\n'), Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }))
        {
            bool bodyNext = false;
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject: writer.WriteStartObject(); break;
                    case JsonTokenType.EndObject: writer.WriteEndObject(); break;
                    case JsonTokenType.StartArray: writer.WriteStartArray(); break;
                    case JsonTokenType.EndArray: writer.WriteEndArray(); break;
                    case JsonTokenType.PropertyName:
                        string prop = reader.GetString()!;
                        writer.WritePropertyName(prop);
                        bodyNext = prop == "Body";
                        continue;
                    case JsonTokenType.String:
                        if (bodyNext)
                        {
                            string body = reader.GetString() ?? "";
                            if (body.Length > 0)
                            {
                                var b = Encoding.UTF8.GetBytes(body);
                                writer.WriteStringValue($"<rimosso: {b.Length} byte, sha256 {Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant()}>");
                            }
                            else writer.WriteStringValue("");
                        }
                        else writer.WriteStringValue(reader.GetString());
                        break;
                    case JsonTokenType.Number:
                        if (reader.TryGetInt64(out long l)) writer.WriteNumberValue(l); else writer.WriteNumberValue(reader.GetDouble());
                        break;
                    case JsonTokenType.True: writer.WriteBooleanValue(true); break;
                    case JsonTokenType.False: writer.WriteBooleanValue(false); break;
                    case JsonTokenType.Null: writer.WriteNullValue(); break;
                }
                bodyNext = false;
            }
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }
}
