namespace PhpVulnScanner.Core.Engine;

/// <summary>
/// Sezione "Avanzate" (v1.4): test aggiuntivi in sola lettura, ciascuno con la propria casella. Tutti spenti nella
/// configurazione predefinita tranne quelli a costo quasi nullo; "Massima detection" li accende tutti.
/// Le chiavi (<see cref="Keys"/>) sono stabili: compaiono in session.json, nel report e nella riga di comando (--advanced).
/// </summary>
public sealed class AdvancedOptions
{
    /// <summary>HEAD accanto alla GET sul percorso principale e confronto delle risposte (cache, filtri solo sulle GET, 405); OPTIONS per l'intestazione Allow.</summary>
    public bool HeadVsGet { get; set; } = true;
    /// <summary>composer.json (vincolo "php" = versione minima dichiarata), vendor/autoload.php, vendor/composer/installed.json (librerie e versioni).</summary>
    public bool Composer { get; set; } = true;
    /// <summary>Pagine di stato esposte: /server-info e /server-status (Apache: moduli caricati = SAPI certa), /nginx_status, /status e /fpm-status di PHP-FPM.</summary>
    public bool StatusPages { get; set; } = true;
    /// <summary>File di versione delle applicazioni (readme.html di WordPress, joomla.xml, CHANGELOG.txt di Drupal, version.php di Moodle, pagine di debug dei framework…) con confronto NCSC-NL.</summary>
    public bool AppVersionFiles { get; set; } = true;
    /// <summary>Sonda FastCGI sulla porta 9000: record FCGI_GET_VALUES (gestione, innocuo); una risposta = php-fpm esposto su TCP.</summary>
    public bool FastCgiProbe { get; set; } = true;
    /// <summary>Comportamenti tipici di PHP: PATH_INFO (/index.php/x), risposta di xmlrpc.php, sorgenti esposti (.phps, .php~, .php.bak, .php.save: solo l'esistenza), pagine rivelatrici aggiuntive.</summary>
    public bool PhpBehaviours { get; set; } = true;
    /// <summary>Livello 2 (barriera multipart) su ogni .php scoperto, non solo sul percorso principale (max <see cref="Level2MaxPaths"/>).</summary>
    public bool Level2AllPaths { get; set; } = false;
    public int Level2MaxPaths { get; set; } = 5;
    /// <summary>Secondo giro sul percorso principale con uno User-Agent da browser che contiene comunque il nome dello strumento: differenze = filtro sugli UA; la seconda risposta è spesso la pagina vera.</summary>
    public bool BrowserUserAgent { get; set; } = false;
    /// <summary>Inventario dei componenti dalle pagine già scaricate: plugin e temi WordPress, componenti Joomla, moduli Drupal, con versione quando c'è ?ver=. Nessuna richiesta in più.</summary>
    public bool Components { get; set; } = true;
    /// <summary>Esposizioni accessorie con sole HEAD: .env, .git/HEAD, .svn/entries, backup e dump comuni, TRACE abilitato. Solo l'esistenza, nessun contenuto scaricato.</summary>
    public bool Exposures { get; set; } = true;
    /// <summary>Più nomi: PTR di ogni host attivo e ServerName nella pagina di errore di Apache.</summary>
    public bool ReverseDns { get; set; } = true;
    /// <summary>Certificate Transparency (crt.sh) per i domini scoperti: nessun traffico verso i bersagli, ma una richiesta a un servizio esterno per dominio.</summary>
    public bool CertificateTransparency { get; set; } = false;
    /// <summary>v1.6: adozione dell'ID di sessione: una GET con un PHPSESSID casuale nuovo; se il server lo adotta invece di emetterne uno suo, session.use_strict_mode è spento. Una visita come un'altra, nessuna sessione di utenti. Spento per impostazione predefinita.</summary>
    public bool SessionIdProbe { get; set; } = false;

    /// <summary>Chiavi stabili per riga di comando e file: una per casella, nello stesso ordine della sezione Avanzate.</summary>
    public static readonly string[] Keys =
    [
        "headvsget", "composer", "status", "appversion", "fastcgi", "behaviours", "level2all", "browserua", "components", "exposures", "ptr", "ct", "sessionid",
    ];

    public bool Get(string key) => key switch
    {
        "headvsget" => HeadVsGet, "composer" => Composer, "status" => StatusPages, "appversion" => AppVersionFiles, "fastcgi" => FastCgiProbe,
        "behaviours" => PhpBehaviours, "level2all" => Level2AllPaths, "browserua" => BrowserUserAgent, "components" => Components,
        "exposures" => Exposures, "ptr" => ReverseDns, "ct" => CertificateTransparency, "sessionid" => SessionIdProbe,
        _ => false,
    };

    public void Set(string key, bool value)
    {
        switch (key)
        {
            case "headvsget": HeadVsGet = value; break;
            case "composer": Composer = value; break;
            case "status": StatusPages = value; break;
            case "appversion": AppVersionFiles = value; break;
            case "fastcgi": FastCgiProbe = value; break;
            case "behaviours": PhpBehaviours = value; break;
            case "level2all": Level2AllPaths = value; break;
            case "browserua": BrowserUserAgent = value; break;
            case "components": Components = value; break;
            case "exposures": Exposures = value; break;
            case "ptr": ReverseDns = value; break;
            case "ct": CertificateTransparency = value; break;
            case "sessionid": SessionIdProbe = value; break;
        }
    }

    public void SetAll(bool value) { foreach (var k in Keys) Set(k, value); }
    public bool Any => Keys.Any(Get);
    public IEnumerable<string> Enabled => Keys.Where(Get);

    /// <summary>"headvsget,composer,…" oppure "none"/"all".</summary>
    public string ToKeyList() => Keys.All(Get) ? "all" : !Any ? "none" : string.Join(",", Enabled);

    /// <summary>Interpreta "all", "none", oppure un elenco di chiavi separate da virgola (chiavi sconosciute → eccezione con l'elenco valido).</summary>
    public static AdvancedOptions Parse(string text)
    {
        var o = new AdvancedOptions();
        o.SetAll(false);
        text = (text ?? "").Trim();
        if (text.Equals("all", StringComparison.OrdinalIgnoreCase)) { o.SetAll(true); return o; }
        if (text.Length == 0 || text.Equals("none", StringComparison.OrdinalIgnoreCase)) return o;
        foreach (var raw in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string k = raw.ToLowerInvariant();
            if (!Keys.Contains(k)) throw new ArgumentException(L.F("opzione avanzata sconosciuta: {0} (valide: {1})", raw, string.Join(", ", Keys)));
            o.Set(k, true);
        }
        return o;
    }

    public AdvancedOptions Clone() => (AdvancedOptions)MemberwiseClone();
}
