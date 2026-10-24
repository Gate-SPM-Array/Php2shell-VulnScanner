using System.Globalization;
using System.Text;

namespace PhpVulnScanner.Core.Output;

public enum CsvDialect
{
    /// <summary>Separatore ";" e virgola decimale: si apre direttamente con Excel in italiano.</summary>
    ExcelItalian,
    /// <summary>Separatore "," e punto decimale (RFC 4180): adatto a Python, Power BI, SIEM.</summary>
    Standard,
}

/// <summary>Formattazione CSV coerente per tutti i file della sessione.</summary>
public sealed class CsvFormat
{
    public CsvDialect Dialect { get; }
    public char Sep { get; }
    public CultureInfo Culture { get; }

    public CsvFormat(CsvDialect d)
    {
        Dialect = d;
        Sep = d == CsvDialect.ExcelItalian ? ';' : ',';
        Culture = d == CsvDialect.ExcelItalian ? CultureInfo.GetCultureInfo("it-IT") : CultureInfo.InvariantCulture;
    }

    public string Num(double v, int decimals = 3)
    {
        if (double.IsNaN(v) || double.IsInfinity(v)) return "";
        return v.ToString("F" + decimals, Culture);
    }

    public string Escape(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        bool quote = s.IndexOfAny([Sep, '"', '\n', '\r']) >= 0;
        if (!quote) return s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    public string Join(IEnumerable<string> fields) => string.Join(Sep, fields);

    public double ParseNum(string s) =>
        string.IsNullOrWhiteSpace(s) ? double.NaN : double.Parse(s, NumberStyles.Float, Culture);

    /// <summary>Come <see cref="ParseNum"/>, ma restituisce NaN invece di sollevare eccezioni.</summary>
    public double ParseNumSafe(string s) =>
        double.TryParse(s, NumberStyles.Float, Culture, out var v) ? v : double.NaN;

    /// <summary>Divide una riga CSV rispettando le virgolette.</summary>
    public string[] Split(string line)
    {
        var res = new List<string>();
        var sb = new StringBuilder();
        bool inQ = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (inQ)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                    else inQ = false;
                }
                else sb.Append(c);
            }
            else if (c == '"') inQ = true;
            else if (c == Sep) { res.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        res.Add(sb.ToString());
        return [.. res];
    }

    public const string TimestampFormat = "yyyy-MM-dd HH:mm:ss.fff";
}
