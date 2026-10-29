# Changelog

Regola: ogni versione consegnata ha un numero diverso; anche una modifica minima del codice produce una nuova versione con la sua voce qui sotto.

## v1.11 — 2026-10-29

Via del maintainer dopo il giro notturno della v1.10 sulla /20 (16 thread, 8 cicli: 54-59 min per ciclo, zero errori) e la sua proposta di un alive check continuo in parallelo alla scansione. Nessuna richiesta HTTP in più al bersaglio.

### Novità
- **Sweeper dell'alive check** (proposta del maintainer): un task a parte riprova a ritmo lento, per tutta la durata del ciclo, gli host non confermati attivi (ICMP + TCP sulle porte della scansione, timeout 1,5×, corsie proprie: campo "corsie", predefinito 4, `--sweep-lanes`); chi risponde entra **subito** nella coda del ciclo in corso (dopo i nomi, prima degli host nuovi) e la riga "Non raggiungibile" viene sostituita. Primo giro su tutti i non confermati (anche dal ciclo 2); i giri successivi solo sugli host visti attivi nel loop o noti; alla fine della passata un ultimo giro sui non confermati mai riprovati nel ciclo. Sostituisce la seconda chance a fine ciclo delle v1.8-v1.10 (`--no-alive-retry` la spegne). Motivo: un host rimasto muto nella passata principale (sulla /20: un host attivo dato muto per 8 cicli perché una seconda istanza dallo stesso IP ne occupava le connessioni) rientra appena risponde, non al ciclo dopo.
- **Host noti** (campo nella sezione Bersagli, `--known-hosts <file>`): file con gli host attivi nelle sessioni precedenti, un IP per riga (es. `host_attivi_vX.Y.txt` della sessione prima). Lo sweeper li riprova a ogni ciclo; chi resta muto ha il test `KNOWN-HOST` nella scheda ("attivo in una sessione precedente, nessuna risposta in questa"), così un host che sparisce è un'informazione, non un buco.

### Corretto
- I nomi da CT dirottati verso un host **già analizzato** si perdevano (486 su 873 nella notte della v1.10): ora restano in memoria tra un ciclo e l'altro e vengono provati al ciclo successivo.
- Conteggio dei recuperati nel log ("7 recuperati su 6": contava anche gli host attivi finiti durante la seconda chance): ora conta solo gli host recuperati dallo sweeper e i tentativi fatti.
- Stato della riga di comando (`--merge`, `--save-config`, `--analysis-bundle`) per thread: chiamate parallele a `Parse` (test) non si pestano più.

### Test
- 402 test (+4, `V111Tests`): sweeper che recupera gli host durante il ciclo con conteggio esatto, sweeper spento, host noti (test `KNOWN-HOST`, riprovati in ogni ciclo), opzioni CLI. Test v1.8-v1.10 della seconda chance adeguati alle righe dello sweeper.

## v1.10 — 2026-10-28

Via del maintainer dopo il giro notturno della v1.9 sulla /20 (6 thread, 5 cicli) e le note sul report. Nessuna richiesta in più al bersaglio: una query DNS per nome da CT.

### Corretto
- **Rumore dei nomi da Certificate Transparency.** Nella /20 l'80% del tempo dei thread andava alla seconda passata sui nomi (ciclo 1: 3,0 h sulle righe per IP, 11,7 h su 1715 servizi per nome) e il 77-80% di quei nomi ripiegava su "stesso contenuto": nomi del dominio presi da crt.sh che non vivono su quell'IP (353 host arrivavano al tetto di 10). Ora i nomi da CT entrano nei nomi scoperti **solo se risolvono (A/AAAA, resolver configurato) sull'IP in esame**; se risolvono su un altro IP della lista bersagli vengono dirottati a quell'host (se non è già stato analizzato); gli altri restano tracciati nella scheda (test `ADV-HOST-CT-DNS`, campo `CtNamesElsewhere`), non riscansionati. Casella "Nomi da Certificate Transparency solo se risolvono sull'IP in esame", `--no-ct-dns`.
- **Seconda chance**: corsie fisse a 16 (con 6 thread la v1.9 ne aveva 4: 35 min per ciclo su 3750 host); dal ciclo 2 in poi si riprovano solo gli host visti attivi almeno una volta nel loop (il primo ciclo li prova tutti). Nel log il numero di host esclusi.
- **Connessione chiusa dal perimetro**: ~37 host per ciclo, sempre gli stessi, chiudevano la connessione con RST durante il TLS sulla 443 e finivano in "Non raggiungibile: nessuna risposta HTTP". Ora la motivazione dice "connessione chiusa dal perimetro durante il TLS (probabile IPS: l'host esiste)" e la scheda ha il test `L1-RESET`.
- **Colonna Nomi del report compatto**: la v1.8 le aveva dato un limite di larghezza con spezzatura ovunque e il browser la schiacciava a quattro caratteri. Ora un nome per riga, mai spezzato (tabelle "Da tenere in considerazione", "Host attivi", "PHP sospetto", "Loquacità", "Esposizioni").
- **Rigenerazione del report**: `elenco_vX.Y.csv` e `results_cN.csv` venivano sovrascritti; ora prendono lo stesso suffisso `_2`, `_3` dei report, e il log dice "nuova copia N: i report e i CSV precedenti restano".

### Novità
- **Configurazione su file**: pulsanti **Salva config…** / **Carica config…** (JSON con tutti i parametri; si può caricare anche il `session.json` di una sessione) e da console `--config <file>` (le opzioni esplicite vincono) e `--save-config <file>` (scrive e termina senza scansione).
- **Pacchetto per analisi**: in "Esporta log…" la voce "Pacchetto per analisi senza corpi (*.zip)" e da console `--analysis-bundle`: zip della cartella di sessione con `results.json` e `results.jsonl` senza i corpi delle risposte (al posto del corpo: lunghezza e SHA-256), più log, CSV, report, file degli host; `samples.json` escluso. Gli zip di sessione in debug pesavano 60-700 MB; così stanno in pochi MB e passano i limiti di upload.

### Test
- 398 test (+8, `V110Tests`): sorte dei nomi da CT (qui, dirottato, già analizzato, altrove), seconda chance dal ciclo 2 solo per host visti attivi, reset dal perimetro, colonna Nomi, suffissi sui CSV rigenerati, configurazione da file e da `session.json` con opzioni esplicite vincenti e `--save-config`, pacchetto per analisi (corpi rimossi, JSON valido, righe del jsonl conservate, samples escluso).

## v1.9 — 2026-10-24

Via del maintainer dopo il giro della v1.8 sulla /22 (2 cicli): la seconda chance recuperava 3-4 host su 914 ma costava 11,5 min per ciclo su 27 (4 corsie × timeout 3 s), e tutta a fine ciclo. Versione per il giro notturno sulla /20 e sulla /22.

### Modificato
- **Seconda chance più leggera e anticipata**: corsie = metà dei thread (minimo 4, mai più dei thread) invece di 4 fisse; timeout 1,5× invece di 2×; parte **appena la coda degli host si svuota**, servita dai lavoratori liberi mentre gli ultimi nomi finiscono; gli host ancora in corso in quel momento vengono riprovati in coda alla fine. Stima sulla /22 con 16 thread: 2-3 min invece di 11,5, stessi host recuperati. Il log dice quanti host entrano in seconda chance e quanti vengono recuperati.
- Un host entra nella seconda chance solo dopo che le sue righe "Non raggiungibile" sono uscite, così la riemissione le sostituisce sempre.

### Test
- 390 test (+3, `V19Tests`): timeout 1,5× nel log, seconda chance che parte con la coda degli host vuota mentre un host è ancora in corso (host in ritardo recuperato in coda), corsie calcolate dai thread.

## v1.8 — 2026-10-24

Costruita sulle note del maintainer durante le prove della v1.7 sulla /20 (giro "tirato" a 36 thread e giro a 16 thread) e su una regola sua sul consolidamento. Nessuna sonda in più sugli host che rispondono.

### Corretto
- **Alive check sotto burst**: con 36 thread ogni host apriva insieme ICMP + 6 TCP + 6 UDP (~470 flussi in volo) e tutti gli host andavano in timeout fin dai primi secondi (71 attivi su 4094 contro ~280). Ora l'alive check ha un **tetto separato** (campo "Host in parallelo", predefinito 8, `--alive-parallel`), indipendente dai thread HTTP.
- **Seconda chance a fine ciclo** (casella, `--no-alive-retry` per spegnerla): gli host non confermati vengono riprovati una volta, al massimo 4 alla volta, con ICMP + TCP sulle porte della scansione e timeout doppio; chi risponde viene scansionato per intero e la riga "Non raggiungibile" viene sostituita (stessa chiave, storia del ciclo aggiornata, entrambe le osservazioni nel `results.jsonl`). Un ciclo tirato non perde host per sempre.
- **Sonde annullate non attese**: dopo la conferma (TCP/443 in 18 ms) la fase alive durava comunque 1,2 s aspettando il ping annullato; sulla /20 ~6 min di thread per ciclo. Ora le sonde annullate sono registrate con il tempo trascorso e lasciate morire in sfondo.
- **Nomi in coda dietro gli host (regressione della v1.7)**: i lavori sui nomi aspettavano sul semaforo dietro migliaia di host (16 min misurati) e il thread dell'host altri 18 min per riprendere il posto: la riga in tabella restava con Nome vuoto per mezz'ora. La passata ora gira con **lavoratori e coda a priorità** (prima i nomi, poi gli host nuovi) e la chiusura dell'host è una continuazione accodata dall'ultimo nome: nessun lavoratore fermo, righe definitive pochi minuti dopo l'anteprima.
- **Certificate Transparency** interrogava il dominio registrabile a due etichette (`example.it`): troppo largo, crt.sh non rispondeva. Ora prima il sottodominio più frequente tra i nomi (`ente.example.it`), poi il registrabile solo se vuoto.
- **"PHP forse" nei filtri** era in AND con la tendina Verdetto (con "Non determinabili" selezionato spariva tutto): ora è una voce del gruppo Verdetto, in OR con gli altri riquadri.

### Novità
- **Consolidamento per campo** (regola del maintainer: il più informativo vince solo se contiene anche le informazioni dell'altro, altrimenti si fonde): la riga base resta la più informativa, ma versione, SAPI, applicazione, barriera, certificato, WAF, elenchi (nomi, superficie, tecnologie, esposizioni, indizi…) che ha solo l'altro ciclo vengono presi; verdetto e priorità ricalcolati sui campi fusi; ciclo e orario dell'ultima osservazione; test `MERGE` con i campi presi e il ciclo di provenienza. Vale anche per "Fondi sessioni". I file restano leggibili all'indietro.
- **Elenco per Excel** in fondo al report compatto e in `elenco_vX.Y.csv`: tutti i servizi in evidenza (vulnerabili, probabilmente vulnerabili, mitigati, non determinabili, PHP forse), un solo nome per riga con il conteggio degli altri, 14 colonne brevi senza a capo (IP, Nome, Altri nomi, Porta, Verdetto, Priorità, PHP, Versione, SAPI, App, Barriera, WAF, Referente, Ciclo), ordine per priorità; nel report le prime 300 righe, nel CSV tutte.
- Tabella "Da tenere in considerazione": colonne brevi senza a capo, Nomi limitata, Motivazione più larga; stato NCSC-NL abbreviato ("affetto: dipende dalla versione di PHP") con la frase intera nel suggerimento.

### Test
- 387 test (+13, `V18Tests`): seconda chance (riga sostituita, consolidato con una riga di storia per ciclo, spenta), CLI, sonde annullate non attese, nomi prima dell'host successivo (1 thread, 2 host), fusione per campo (campi presi, MERGE, verdetto ricalcolato, orario dell'ultima osservazione, stesso ciclo), CT sottodominio, NCSC breve, elenco per Excel (nome unico, altri nomi, forse, CSV, tetto nel report, file scritto accanto ai report).

## v1.7 — 2026-10-24

Prima versione costruita da Claude Code sul repository. Via del maintainer dato in serata dopo le prove della v1.6 su una /22 (1022 host, 32 thread, 5 cicli consolidati, Massima detection). Nessuna richiesta HTTP in più; nessun test in meno.

### Corretto
- **Coda del ciclo su un thread solo.** La seconda passata sui nomi scoperti girava in sequenza sul thread dell'host: 10 nomi × 2 porte × 60-120 s = 20-28 min per ciascuno dei cinque host più "ricchi" della /22, e a fine ciclo un solo thread al lavoro per ~17 min su 37 (i nomi ripiegati non compaiono in `results.json` ma costano lo stesso). Ora ogni coppia nome/porta prende un posto nel pool dei thread della passata (il thread dell'host cede il suo mentre aspetta): il numero di richieste in volo resta quello configurato, il ripiegamento (stesso contenuto, stesso esito) resta sequenziale e nell'ordine dei nomi, l'esito è identico.
- **Righe per IP in anteprima.** Le righe di un host uscivano tutte insieme alla fine dell'host, nomi compresi: nel ciclo 1 della /22 il riquadro "Vulnerabili per versione" diceva 4 fino alla fine del ciclo e 7 un attimo dopo (tre righe stavano sull'host con 10 nomi). Ora le righe per IP vanno in tabella appena complete e vengono riemesse (stessa chiave) a fine host con i nomi ripiegati; i file di sessione ricevono solo la riga definitiva.
- **Catch-all 5xx con la radice in redirect.** La regola v1.6 chiedeva lo stesso 5xx anche su `/`; sulla /22 un servizio rispondeva 302 su `/` e 503 (stesso corpo di 299 byte) su `index.php`, sul file inesistente e su tutti i 40 punti di ingresso provati a 1 s l'uno. Le pagine in redirect ora non contano nel confronto: superficie e sonde su percorso si fermano (`L1-SURFACE-PROBE`, `ADV-SKIP`) se le pagine restanti e il file inesistente danno lo stesso 5xx.

### Novità
- **"PHP forse" in evidenza**: riga in lilla nella tabella principale; riquadro **PHP forse** (servizi, sotto gli host) cliccabile come filtro (secondo clic: tutti); il riquadro "PHP non rilevato" non porta più la nota "di cui N con indizi". Nel report compatto il riquadro "PHP sospetto" è lilla, un richiamo nel riepilogo dice quanti servizi e host, e la sezione **PHP sospetto** sta subito dopo "Da tenere in considerazione" (prima degli host attivi); nel report completo le righe "forse" della tabella sono in lilla.

### Note
- `scan.log` e `results.jsonl` "indietro" in Esplora file: i due file sono aperti in append con scrittura immediata; è Esplora file di Windows che non aggiorna dimensione e data dei file tenuti aperti. Aprendoli con un editor il contenuto è aggiornato.

### Strumenti
- `tools/package.sh`: `dotnet` dal PATH e cartella di uscita `OUT=<dir>` (funziona in Claude Code); i pattern dei dati cliente stanno in `tools/private-patterns.txt`, escluso da git, invece che nello script; `Trascrizioni/` esclusa dallo zip dei sorgenti.

### Test
- 374 test (+7, `V17Tests`): nomi in parallelo con lo stesso ripiegamento (tempo misurato sul server finto con ritardo), anteprima e riemissione della riga per IP, nessuna anteprima senza nomi, interruzione durante la passata sui nomi, catch-all con radice in redirect (unità e motore), "forse" nei due report. `FakePhpServer`: ritardo per risposta, redirect per percorso, vhost per qualunque nome, radice in redirect con il resto 5xx.

## v1.6 — 2026-10-24

Versione "definitiva" richiesta dal maintainer (via alle 17:11), costruita su tre cose: le cinque attività utili ricavate da uno script Python di terzi (PHP Evidence Scanner 0.1.8), l'analisi dei due zip del pomeriggio (/20 con la v1.4.1 in due cicli, /22 con la v1.5) e la ricerca su CVE-2026-115560. Nessun esploit, nessuna richiesta che scriva stato: l'unica richiesta in più è la GET facoltativa dell'adozione dell'ID di sessione, spenta per impostazione predefinita.

### Novità
- **Stato del certificato TLS** (`Net/CertificateStatus.cs`, test `TLS-CERT`, colonna Certificato, sezione **Certificati** nel report compatto): scaduto il…, non ancora valido, scade tra N giorni (≤30), autofirmato, catena non attendibile (verifica offline con il magazzino radici locale, catena intermedia catturata dall'handshake), nome non corrispondente (solo per bersagli a nome), chiave RSA < 2048 bit, firma SHA-1/MD5. `TlsInfo` ha i campi NotBefore, SelfSigned, ChainTrusted, ChainError, KeyBits, SignatureAlgorithm, DaysToExpiry; SAN letti anche su Linux (prefissi `DNS:`).
- **Cache o intermediario davanti all'origine** (`CacheHint`, test `L1-CACHE`): Via, Age, X-Cache, CF-Cache-Status, X-Varnish, X-Served-By; su un HIT la nota "le intestazioni dell'origine possono mancare".
- **Versioni di PHP dichiarate nel corpo** (`BodyDeclaredVersions`): indizio di peso 2 e riga nella scheda, mai nel verdetto.
- **Inventario riconciliato** (`Inventory/InventoryFile.cs`, `InventoryMatcher.cs`, `Report/InventoryReportSection.cs`): CSV (alias di colonna, separatore automatico, virgolette, BOM, commenti, reti e intervalli come bersaglio) o JSON; a fine scansione referente/ambiente/note/versione dichiarata su ogni servizio corrispondente (`InventoryStatus`: ok, versione diversa, dichiarato PHP non osservato, versione non osservata, non osservato), file `inventario_vX.Y.json`, sezione **Inventario** nel report compatto (versioni diverse, dichiarati ma non osservati, osservati ma non inventariati, PHP dichiarato ma non osservato), colonna **Referente** nella tabella. Campo Inventario nell'interfaccia e `--inventory <file>`.
- **Adozione dell'ID di sessione** (`Php/SessionProbe.cs`, test `ADV-SESSIONID`, chiave `sessionid`, spento): una GET con un PHPSESSID casuale; adottato = `session.use_strict_mode` spento; eseguita solo se il percorso principale avvia una sessione.
- **Budget per servizio** (`ScanConfig.ServiceBudgetMs`, predefinito 120 s, `--budget`, campo nell'interfaccia): oltre, i punti di ingresso restanti e i gruppi di test aggiuntivi su percorso vengono saltati e registrati (`SkippedForBudget`, test `BUDGET`); livello 1, 2 e WAF mai.
- **Backend morto (catch-all 5xx)**: stesso 502/503/504 su pagina principale, index.php e file inesistente → `MissingFileKind.ServerError`, niente punti di ingresso, test aggiuntivi su percorso saltati (`ADV-SKIP`). Nella /22 di riferimento questi host costavano 170 s per servizio.

### Corretto
- **Il writer di sessione bloccava tutti i thread**: la riscrittura periodica di `results.json` avveniva dentro il lock preso da ogni risultato, serializzando tutto in una stringa (256 MB nella /20 con il debug). Misurato: 16 thread occupati in media per 4-5, ciclo 2 di 2 h 11 contro 1 h 38 del ciclo 1. Ora snapshot sotto lock e scrittura in streaming su un thread a parte, a singolo volo; `Finish` attende e scrive in modo sincrono. Contenuto del file identico.
- **Bilanciatore dedotto dall'header Date**: confrontava le date di risposte prese in momenti diversi (falso positivo "scarto di 88 s" su un host lento). Ora confronta lo scarto tra Date e ora di ricezione (`HttpSnapshot.ReceivedUtc`); segnala solo oltre 60 s di differenza tra gli scarti.
- Test intermittente `WordPressReadme_SetsApplicationVersion…`: causa trovata (`TechnologyDatabase.Default` statico scritto in parallelo da classi di test fuori dalla collezione `AppDbDefault`); le classi sono entrate nella collezione.
- Fixture di test: l'ordine delle chiavi `AdvancedOptions.Keys` termina con `sessionid`.

### Verifica sui due zip del pomeriggio (24/10)
- Zero righe `errore` nei log (nella notte v1.3.1 erano 108): il bug del robots.txt è chiuso; Matomo, Drupal 7 e i WordPress 7.1.3 sono tornati con l'applicazione.
- /20 v1.4.1 (2 cicli, 16 thread, tutti i test): 923 servizi HTTP, 10 vulnerabili per versione su 4 host, 6 probabilmente vulnerabili su 4, 134 non determinabili su 27, 85 esposizioni. /22 v1.5 (32 thread): 148 servizi HTTP, 7 vulnerabili per versione, 25 "forse" su 128 non rilevati, 52 nomi ripiegati per esito e 136 per contenuto, report compatto 77 KB.

### Test
- 367 test (+49): certificati (22: stato, catena, chiavi, SAN su Linux, idempotenza, cache, versioni nel corpo, orologi dei nodi), inventario e ID di sessione (17), prestazioni (9: writer non bloccante, streaming identico, catch-all 5xx, budget, CLI).

## v1.5 — 2026-10-24

Costruita sulle note del maintainer durante le prove della v1.4.x sulla /20 e sulla ricerca su CVE-2026-115560. Via dato alle 15:10. Nessuna richiesta HTTP in più rispetto alla v1.4: tutto il nuovo lavora sulle risposte già ricevute.

### Novità
- **Colonna PHP a tre valori: sì / forse / no.** "Forse" = nessuna prova ma indizi passivi pesati (forte 3, medio 2, debole 1; da 2 in su): l'intestazione `Expires: Thu, 19 Nov 1981 08:52:00 GMT` di `session_start()`, un cookie con valore nel formato dell'ID di sessione PHP (26 caratteri `0-9a-v`), cookie di framework e CMS PHP, `X-Pingback`/`Link rel=api.w.org`/`X-Redirect-By`/`X-Drupal-Cache`/`X-Generator`, link e form verso `.php`, cartelle tipiche, handler del file `.php` inesistente, `robots.txt`, terna di cache di PHP, pannelli di hosting, tecnologie dell'ecosistema PHP, nomi nel certificato. Test `L1-HINTS`; il verdetto non cambia ("PHP non rilevato"); il riquadro dice "di cui N con indizi"; sezione **PHP sospetto** nel report compatto; filtro `php:forse`. (`Php/PhpHints.cs`)
- **Impostazioni dalla pagina phpinfo** quando esposta: `session.upload_progress.enabled`, `session.serialize_handler`, `session.save_handler`, `expose_php`, `memory_limit`, `post_max_size`, `Server API` (che fissa la SAPI), versione. Test `L1-PHPINFO-INI`: dice se la mitigazione per CVE-2026-109619 **e CVE-2026-115560** (`upload_progress=0`) è applicata. (`Php/PhpInfoParser.cs`)
- **CVE-2026-115560** (advisory informativa PHP del 23/10): nota nel report ("Metodo e limiti") e nella guida: nessuna release corretta, "Corretto per versione" riguarda i due CVE del 21/10; le precondizioni (cambio a runtime di `session.serialize_handler` con upload progress attivo) sono invisibili dall'esterno.
- **Indice di loquacità 0-5** per servizio: versioni nei banner, sistema operativo, phpinfo, directory listing, pagine di stato, pagine di debug, Composer, `.git`/`.env`/backup, versione dell'applicazione, TRACE, nomi interni nel certificato. Test `L1-VERBOSITY`; sezione **Loquacità** nel report compatto ordinata per indice. (`Php/Verbosity.cs`)
- **Nomi con lo stesso esito**: un nome scoperto con contenuto diverso ma stesso verdetto, versione, SAPI, applicazione, barriera, WAF, priorità e presenza di PHP della riga per IP (o di un'altra riga per nome dello stesso IP+porta) non ha riga: va in `SameOutcomeNames` "(= stesso esito)". Risolve le farm dietro bilanciatore con certificato condiviso (10 nomi × 5 IP = 50 righe identiche nella /20). **Tutti i nomi restano nel report compatto** (colonna Nomi senza tagli), in `nomi_scoperti_vX.Y.txt` e in `results.jsonl`. Casella in Detection PHP, `--no-fold-outcome`. Le osservazioni ripiegate (anche quelle "stesso contenuto" della v1.4, che prima venivano scartate) finiscono nel `results.jsonl`.
- **Filtri**: le quattro tendine (verdetto, priorità, alive, barriera) sono a **scelta multipla** (OR dentro, AND tra loro e con il testo); un clic su un riquadro di verdetto aggiunge o toglie quel verdetto. **Sintassi del testo libero**: parole = AND, `a|b` = OR, `-x` esclude, `"testo con spazi"`, `campo:valore` (ip, nome, porta, ver, sapi, app, waf, motivo, superficie, verdetto, priorita, alive, barriera, php, tech, esposizione, os, ciclo, con alias inglesi), jolly `*` e `?` ancorati sul campo intero (senza jolly resta sottostringa), `ip:192.0.2.0/24` e `ip:192.0.2.10-50`. Un filtro scritto male non blocca nulla: casella rossa e suggerimento con l'errore. (`Output/ResultFilter.cs`)
- Report completo: scheda con indizi, impostazioni da phpinfo, loquacità, nomi con lo stesso esito; CSV con `same_outcome_names, php_presence, php_hints, php_hint_score, ini_hints, verbosity_score, verbosity_items`.

### Corretto
- I risultati dei test a livello di host (FastCGI 9000, esposizioni sulla 9000, SAPI fpm) non venivano copiati sulle righe per nome.
- CSV in dialetto standard (virgola): la colonna `started` (`HH:mm:ss,fff`) non era tra virgolette e ogni riga aveva una colonna in più dell'intestazione.
- `CLAUDE.md`: regola n. 9, nessuna nuova versione senza il via del maintainer.

### Test
- 317 test (+84): filtri (27: AND/OR/negazione/virgolette/campi/jolly/CIDR/intervalli/errori), indizi PHP e phpinfo e loquacità (27, con due test di motore sul server finto), ripiegamento per esito, CLI, CSV, report compatto e completo (12), robots.txt (v1.4.1).

## v1.4.2 — 2026-10-24

Due note di facciata del maintainer dopo la prova della v1.4.

### Modificato
- **Sezione "Detection PHP"** (a scomparsa): raccoglie tutto ciò che riguarda lo strato PHP, prima sparso tra "Bersagli", "Test" e "Avanzate": percorsi, livello 1 (pagine rivelatrici, easter egg, modalità leggera), livello 2 con il multipart di prova, superficie, nomi scoperti con seconda passata e ripiegamento dei nomi uguali, regola del numero puro, e in fondo i dodici test aggiuntivi. Il campo "Percorsi" lascia "Bersagli".
- **Pulsanti dei test aggiuntivi**: "Tutte" coincideva nei fatti con "Massima detection" ed è stato tolto; ora **Nessuno / Predefiniti / Massima detection**, con i suggerimenti che dicono esattamente cosa accende ciascuno (Predefiniti = tutti tranne User-Agent da browser, Certificate Transparency e livello 2 su ogni .php).
- La sezione "Test" diventa **"WAF, motore e debug"**: WAF e test comportamentale, pre-controllo TCP delle porte, modalità debug, schede dei non raggiungibili.
- `tools/bump_version.py`: porta il numero di versione in tutti i file in un colpo solo.

## v1.4.1 — 2026-10-24

Correzione urgente trovata verificando, su richiesta del maintainer, perché SAPI e applicazione non fossero migliorate nella sessione notturna della v1.3.1.

### Corretto
- **Servizi con `robots.txt` analizzati solo a metà (dalla v1.3)**: la scoperta della superficie aggiungeva i percorsi `Disallow` di `robots.txt` all'elenco dei candidati mentre lo stava scorrendo (`Collection was modified`), e l'eccezione interrompeva l'analisi del servizio prima delle deduzioni passive: niente SAPI, niente applicazione, niente database delle tecnologie, niente livello 2, niente WAF, verdetto "PHP non rilevato". Nella sessione notturna sono 18 servizi su 17 host (`errore Collection was modified` nel `scan.log`), e 11 di essi (WordPress ×4 host, Drupal, Matomo) erano "Non determinabile" con applicazione riconosciuta nella v1.2: una regressione proprio sui servizi PHP più interessanti. Ora l'elenco si scorre per indice e i percorsi aggiunti vengono provati; in più la scoperta della superficie è isolata: un suo errore finisce nel test `L1-SURFACE` e non cancella più SAPI, applicazione e il resto.

### Test
- 233 test: `robots.txt` con `Disallow` su un WordPress finto → nessun errore, applicazione e PHP riconosciuti, superficie registrata.

## v1.4 — 2026-10-24

Versione costruita sull'analisi della scansione notturna di sei cicli sulla /20 con la v1.3.1 (124.815 osservazioni) e sulle note del maintainer: la qualità della detection viene prima della velocità, i risultati devono indirizzare i team sulla verifica e sul patching.

### Corretto
- **Rami fuori supporto con numero "puro"** (7.4.33, 8.0.30, 8.1.14… senza suffisso di distribuzione): ora "Vulnerabile per versione", perché un numero senza suffisso viene da una build upstream e nessun distributore può aver fatto backport; con suffisso (`7.4.3-4ubuntu2.29`) resta "Probabilmente vulnerabile". Disattivabile (Avanzate, `--no-pure-version`).
- **SAPI**: il banner prevale sulla sonda del file inesistente: con `mod_fcgid`/`proxy_fcgi` nel banner un 404 con `X-Powered-By` significa FastCGI, non mod_php (nella notte un servizio era finito a priorità Critica per questo).
- **Nome del report**: `report_v1.0.html` era un numero di revisione interno e si confondeva con la versione del programma; ora `report_v1.4.html` (compatto) e `report_completo_v1.4.html`, con `_2`, `_3` alle rigenerazioni.
- Nomi scoperti con TLD inesistente (es. `cloudpanel.clp` dai certificati interni) non passano più la validazione.
- Stato NCSC-NL riformulato: "prodotto affetto in quanto dipende dalla versione di PHP" invece di un nudo "affetto".
- Barra di scorrimento orizzontale della tabella sempre disponibile; le colonne tengono la propria larghezza.
- **`samples.json` (debug) anonimizzato davvero**: la v1.3 sostituiva solo i nomi interi e lasciava passare nei corpi le etichette dei domini ("Regione …" in prosa), gli indirizzi e-mail, i nomi scoperti su altre righe, il banner `Server` e l'emittente dei certificati privati. Ora cadono anche le etichette di almeno 4 caratteri dei nomi scoperti in tutta la sessione (→ `orgN`, con i sottodomini di terzi → `sub.orgN.tld`), le e-mail (→ `utenteN@example.org`), `Server` e `Issuer`. Sulla sessione notturna: da 609 occorrenze del nome dell'ente a 0. Restano possibili nomi di organizzazioni o persone non legati a un nome scoperto: la nota nel file lo dice, controllare prima di condividere.

### Novità
- **Pausa / Riprendi**: il motore si ferma prima del prossimo host e della prossima richiesta (quelle in volo finiscono); il tempo in pausa non entra nella stima; riga nel log.
- **Pre-controllo TCP di tutte le porte in parallelo** sugli host attivi: handshake TLS e HTTP solo dove la porta risponde. Nella notte le porte chiuse o filtrate costavano il 22% del tempo (1.297 handshake da 3,3 s).
- **Nomi con lo stesso contenuto**: quando un nome scoperto restituisce esattamente la risposta del vhost predefinito (stato, banner, versione, applicazione, corpo), non si crea la riga: il nome va nella colonna Nome della riga per IP. Nella notte era il 75% delle righe per nome.
- **Colonne Bersaglio e Nome**: Bersaglio porta solo l'IP, Nome il FQDN (nome scoperto o bersaglio inserito per nome); ordinamento IP poi nome; stessa separazione nel report e nel CSV (`ip`, `name`, `same_content_names`).
- **Riquadri dei verdetti: servizi e host**: il numero grande conta i servizi (IP + porta + nome), sotto "su N host" conta gli IP distinti; "Host attivi" riporta anche gli host con HTTP. Stessa coppia nel report.
- **Sezione Avanzate** con una casella per ogni test aggiuntivo in sola lettura, costo in richieste tra parentesi, pulsanti Tutte / Nessuna / Massima detection; scelte salvate in `session.json` e nel report; CLI `--advanced all|none|chiavi`:
  HEAD contro GET e OPTIONS (cache, filtri solo sulle GET, metodi consentiti, TRACE); `composer.json` (versione minima di PHP dichiarata), `vendor/autoload.php`, `installed.json` (librerie e versioni); pagine di stato esposte (server-info con i moduli = SAPI certa, server-status, nginx_status, stato di PHP-FPM); file di versione delle applicazioni (readme.html, joomla.xml, CHANGELOG, pagine di debug dei framework) con confronto NCSC-NL; sonda FastCGI sulla 9000 (record di gestione `FCGI_GET_VALUES`: php-fpm esposto su TCP); comportamenti tipici di PHP (PATH_INFO, xmlrpc.php, sorgenti esposti `.phps`/`.bak`, pagine rivelatrici aggiuntive); livello 2 su ogni `.php` scoperto; secondo giro con User-Agent da browser che contiene comunque il nome dello strumento; inventario dei componenti (plugin, temi, moduli) dalle pagine scaricate; esposizioni accessorie con sole HEAD (`.env`, `.git`, `.svn`, backup e dump); più nomi da PTR e dalle pagine di errore di Apache; Certificate Transparency (crt.sh) per i domini scoperti (spento per impostazione predefinita, come il secondo User-Agent).
- **Report compatto** (`report_v1.4.html`, aperto dal pulsante): riepilogo, "Da tenere in considerazione" (vulnerabili, probabilmente vulnerabili, mitigati, non determinabili, esposizioni, applicazioni), "Host attivi" una riga per IP; nessun non raggiungibile, nessuna risposta grezza. Il completo (12 MB sulla /20) resta accanto come `report_completo_v1.4.html`, con la sezione **"Per ciclo"** nei loop consolidati: KPI di ogni ciclo e osservazioni ciclo per ciclo per ogni servizio; `results_c{i}.csv` e report per ciclo dal `results.jsonl`.
- **File degli host** nella cartella di sessione, un IP per riga, pronti per OpenVAS: `host_attivi_v1.4.txt`, `host_http_v1.4.txt`, `nomi_scoperti_v1.4.txt`; con i cicli sono l'unione di tutto il loop, aggiornati a ogni ciclo; anche da "Esporta…".
- **Fondi sessioni…** (e CLI `--merge cartella1 cartella2 … --out`): due o più sessioni sugli stessi range, anche di versioni diverse, fuse in una nuova sessione (vince il risultato più informativo, storia etichettata per sessione, data e versione del programma), con la sezione "Differenze" nel report: host attivi solo in una sessione, verdetti cambiati, informazioni presenti in una e assenti nell'altra. Le sessioni di ogni versione precedente restano leggibili e fondibili.
- **Aggiorna dati…**: scarica da GitHub firme (webappanalyzer) e inventario NCSC-NL aggiornati nella cartella `data\`, sostituendo i file solo a scaricamento riuscito.
- Stato VEX NCSC-NL anche per le tecnologie oltre l'applicazione principale; versione dell'applicazione confrontata con il "corretto in" dell'inventario.
- Modalità debug: anche le HEAD della superficie restano in `Requests`.

### Test
- Test v1.4: versione pura, SAPI banner contro sonda, TLD, pausa (token e motore), pre-controllo porte, nomi con lo stesso contenuto, opzioni avanzate (parsing, CLI, session.json), file degli host, test avanzati contro il server finto (HEAD/GET, composer, pagine di stato, file di versione, FastCGI con un listener finto, PATH_INFO, sorgenti esposti, componenti, esposizioni, PTR), report compatto (contenuto e dimensione su 20.000 righe sintetiche), sezione per ciclo, fusione di sessioni (sovrapposizione, storia, differenze, compatibilità con i file v1.2), convertitore dei dati offline, fixture anonimizzate dalla scansione reale.

## v1.3.1 — 2026-10-24

### Corretto
- **Crash all'arrivo della prima riga** nella v1.3 (`InvalidOperationException: impossibile modificare il contenuto di CollectionView durante il rinvio di un Refresh`, in `crash.log`): l'inserimento a lotti nella tabella avveniva dentro un `DeferRefresh` della vista ordinata, che WPF non consente. Tolto il rinvio; le righe arrivano a lotti ogni 300 ms come prima, inserite una per una nella vista ordinata (stesso schema della v1.2, collaudato su 16.000 righe). Nessuna modifica al motore: la v1.3.0 non va usata.

## v1.3 — 2026-10-24

Versione costruita sull'analisi della prima scansione reale di una /20 con la v1.2 (16.376 coppie host×porta, 2 h 04 min): i dati hanno mostrato dove si perdeva tempo, cosa sfuggiva e cosa mancava per leggere il perimetro.

### Corretto
- **Pianificazione per host.** Le porte dello stesso host erano adiacenti nella coda: con 4 thread, tutti e quattro aspettavano lo stesso alive check e la scansione avanzava di circa un host ogni 1,5 s (95 dei 124 minuti della /20). Ora l'unità di lavoro è l'host: risoluzione e alive check una volta sola, poi le porte in sequenza, parallelismo tra host diversi. Stesso traffico, tempo stimato da 124 a ~45 minuti con 4 thread. Il tempo dell'alive check è attribuito a una sola riga; le altre lo dichiarano "eseguito una volta per host".
- **SAPI con mod_fcgid**: `Apache … mod_fcgid/2.3.9 PHP/7.3.33` era classificato mod_php (priorità Critica); mod_fcgid è FastCGI (php-cgi), ora `cgi` e priorità Alta.
- **PHP-FPM dietro Apache senza banner**: la risposta `404 File not found.` su un `.php` è la firma di PHP-FPM; quattro host della /20 erano finiti in "PHP non rilevato" e ora sono "Non determinabile" (PHP presente, versione ignota).
- Evidenze duplicate (`X-Powered-By: PHP/7.4.33; X-Powered-By: PHP/7.4.33`) deduplicate; metodi dell'alive check annullati perché un altro ha confermato prima scrivono "annullato" invece di "A task was canceled."; distribuzioni normalizzate (`centos` → CentOS, `Win64` → Windows, `(Unix)` non è un sistema operativo).
- `results.json` non viene più riscritto per intero a ogni risultato (su 16.000 righe costava decine di MB di scritture al minuto): riscritto al massimo ogni 30 s e alla fine; in più `results.jsonl`, una riga per osservazione, scritto subito e sempre completo anche se il programma viene chiuso di colpo.

### Novità
- **Cicli di scansione**: N cicli con pausa configurabile, "ciclo i di N" nel log, nella barra di stato e nel riquadro Completati; Interrompi ferma tutto (anche durante la pausa) e conserva i risultati completati.
- **Esito dei cicli**: una sessione per ciclo (cartella `…_c1of4`, `…_c2of4`, ciascuna con il proprio report) oppure **consolidamento** in una sessione sola. Regola di fusione: vince il risultato più informativo (versione dichiarata > non determinabile; raggiungibile > non raggiungibile; barriera osservata > non provata), a parità il ciclo più recente; la **storia dei cicli** resta nel risultato (`ciclo 1: Non raggiungibile · ciclo 2: Probabilmente vulnerabile (7.4.33)`), la colonna Ciclo mostra `Δ` quando il verdetto è cambiato, il report ha la sezione "Storia dei cicli" e conta le variazioni.
- **Ordine casuale** degli host e delle porte, **pausa casuale** tra le richieste (min-max ms) e **tetto di richieste al secondo**: per non far scattare IDS/IPS anche quando l'indirizzo di origine è in white list. L'ordine resta per host (l'alive check si fa una volta sola).
- **Stima di fine ciclo e di fine loop** nella barra di stato: ritmo degli ultimi 5 minuti (media mobile aggiornata ogni 2 s, "in calcolo" sotto un minuto di dati), ora e durata residua del ciclo, ora di fine del loop (ciclo corrente proiettato + cicli restanti × durata dell'ultimo ciclo + pause); riga "Avanzamento" nel log ogni 5 minuti con la stima, per misurare a posteriori l'errore. Con ordine sequenziale la stima oscilla al cambio di sottorete, con l'ordine casuale è stabile.
- **Riquadro "Host attivi"**: host distinti confermati attivi (non coppie host×porta), clic = filtro; stesso dato nel report ("host attivi N su M, K con HTTP") e nella riga di chiusura del log. Con l'alive check spento conta gli host con almeno una risposta TCP/TLS/HTTP.
- **Scoperta dei nomi**: dai certificati (CN e SAN) e dalle intestazioni `Location` si raccolgono i nomi DNS validi (i redirect "incollati" come `https://www.esempio.itindex.php` sono scartati); elenco nella scheda e nel report; **seconda passata** facoltativa sugli stessi IP con `Host` e SNI = nome (riga `nome @ IP`, max N nomi per host): la scansione per IP vede solo il vhost predefinito, i siti veri stanno dietro i nomi.
- **Superficie PHP**: sonda di un `.php` inesistente (`File not found.` = PHP-FPM, `No input file specified.` = php-cgi, 404 con `X-Powered-By` = mod_php: firma di PHP indipendente da banner e applicazione), poi una quarantina di punti di ingresso comuni (wp-login.php, xmlrpc.php, administrator/, phpmyadmin/, adminer.php, typo3/, glpi/, roundcube/…) con sole HEAD (401/403 = esistono), più i `.php` linkati dalle pagine già scaricate (un livello). Colonna "Superficie", elenco nella scheda e nel report; il livello 2 usa il miglior `.php` scoperto quando i percorsi configurati non ne offrono uno.
- **Database delle applicazioni espandibile**: motore di firme in formato Wappalyzer (intestazioni, cookie, meta, html, script, URL, emittente del certificato, implicazioni e requisiti; esclusi i segnali che richiedono un browser) sui dati di **enthec/webappanalyzer** (7.647 tecnologie, 9.181 firme passive, GPL-3.0) e **inventario NCSC-NL** (751 pacchetti con stato VEX per CVE, EUPL-1.2), inclusi in `data\` con versione e data di estrazione (`DATA-VERSION.txt`, riportata nel report e nel log). Le 50 firme a mano restano e hanno la precedenza; il database completa: applicazione e **versione dell'applicazione**, elenco delle tecnologie riconosciute, ogni tecnologia che implica PHP è evidenza di PHP, **stato NCSC-NL per CVE** dell'applicazione riconosciuta (affetto / corretto in x.y / non affetto / in esame). Senza la cartella `data\` il programma funziona con le sole firme incorporate. Aggiornamento dei dati: `tools\build_appdb.py`.
- **Correlazione del filtro di perimetro**: quando lo stesso comportamento WAF (es. connessione chiusa sui parametri ostili) compare su gran parte degli host con web server diversi, il report lo dice una volta: è un unico dispositivo di perimetro (IPS), non N WAF.
- Riga "Bersagli / porte" del report con i bersagli **come inseriti** (`192.0.2.0/20`, intervalli, nomi), anche nel log e in `session.json`.
- **Modalità debug**: intestazioni della richiesta inviata salvate accanto a ogni risposta, e file `samples.json` con un campione **anonimizzato** (IP → 198.51.100.x, nomi → example.org) per ogni combinazione distinta di Server / X-Powered-By / cookie / applicazione, pensato per essere condiviso e analizzato senza esporre il perimetro.
- Opzione "Dettaglio dei non raggiungibili nel report" (spenta: il report di una /20 resta leggibile).
- Riga di comando: `--cycles`, `--cycle-pause`, `--consolidate` / `--separate-sessions`, `--random`, `--delay min-max`, `--rate`, `--no-surface`, `--no-names`, `--no-rescan-names`, `--max-names`, `--debug`, `--report-unreachable`.

### Test
- 123 test: database applicazioni (conversione delle firme, estrazione della versione, intestazioni/cookie/meta/script, implicazioni ed esclusioni, inventario NCSC-NL, prestazioni, riconoscimento dentro il motore), stima (finestra recente, loop, formato durate), fusione (vince il più informativo, parità al più recente, storia), ritmo (pausa e tetto), nomi (validazione, raccolta, seconda passata con Host), superficie (classificazione della sonda, punti di ingresso, livello 2 sul .php scoperto), pianificazione (alive una volta per host, 20 host × 4 porte = 20 alive check), cicli (consolidati con storia, sessioni distinte, interruzione durante la pausa), correzioni dalla /20 (mod_fcgid, dedupe, OS, "annullato"), file di sessione (jsonl, riscrittura a intervalli, campioni anonimizzati), riga di comando.

## v1.2 — 2026-10-23

Richieste del maintainer dopo la prima scansione reale, più le idee ricavate dalla ricognizione sugli strumenti pubblici (checker "openai", inventario NCSC-NL).

### Corretto
- **Banner Server letto per intero.** Il client HTTP spezzava `Server: Apache/2.4 (Debian) PHP/8.1.2` in tre valori e lo scanner vedeva solo `Apache/2.4`: la versione di PHP dichiarata nel banner (mod_php con ServerTokens Full) non veniva letta. Ora le intestazioni sono raccolte come ricevute. Chi ha scansionato con la v1.0/v1.1 può avere "Non determinabile" o "PHP non rilevato" dove il banner conteneva la versione.
- Campo "UDP, porte": accetta un elenco come il campo TCP; prima una lista spegneva l'UDP in silenzio. Ogni valore non valido nei campi numerici viene ora segnalato prima dell'avvio e nel log.
- La casella "Salta i bersagli non confermati attivi" è disabilitata quando l'alive check è spento, con suggerimenti che spiegano la relazione tra le due.

### Novità
- Riquadri di riepilogo come **filtri** (clic = solo quel verdetto, secondo clic = tutti); "PHP non rilevato" e "Non raggiungibili" separati.
- **Barra dei filtri** sopra la tabella: testo libero, verdetto, priorità, alive, barriera; conteggio delle righe mostrate.
- **Ordinamento per numerazione IP** (colonna Bersaglio), nei risultati, nel report e nei CSV/JSON; ordinamento per valore reale anche su porta, priorità, durata, avvio.
- Colonna **Avvio** (ora di inizio del test del bersaglio) in formato ISO con millisecondi e virgola decimale, `2026-10-22 16:07:12,243`; stesso formato nei CSV.
- **Log con ora locale e UTC** su ogni riga, a video e in `scan.log`: `2026-10-22 16:07:12,243 (14:07:12,243Z)`.
- Alive check: nella motivazione e nelle evidenze compaiono **tutti i metodi configurati**, nell'ordine configurato, con esito e durata; colonna `alive_methods` nel CSV.
- **SAPI** dedotta dal banner (mod_php, FPM, LSAPI, CGI, oppure non distinguibile), con l'avvertenza dell'avviso PHP su mod_php; **sistema operativo o distribuzione** dichiarati, a orientare la verifica dei backport.
- **Applicazione riconosciuta** passivamente (oltre 50 firme: WordPress, Joomla, Drupal, phpMyAdmin, Nextcloud, ownCloud, Laravel, Symfony, Moodle, GLPI, TYPO3, PrestaShop, Magento, MediaWiki, Roundcube, Zabbix, Matomo, Dolibarr, Plesk, cPanel…) con rimando alla pagina dell'inventario NCSC-NL.
- **Priorità** di remediation (Critica, Alta, Media, Bassa, Nessuna) derivata da verdetto, SAPI e barriera: ordinamento, non un verdetto nuovo; colonna nella tabella, nel report e nel CSV.
- **Riga di comando** (`--scan`, `--help`): stessa scansione senza finestra, output sulla console, codici di uscita 0/1/2/3/4 per script e attività pianificate, `--json` per una copia dei risultati.
- **Modalità leggera**: HEAD al posto di GET (GET solo se HEAD risponde 405/501); meno traffico, si perdono i segnali nel corpo.
- Report: colonne Avvio, SAPI, App, Priorità; riferimento NCSC-NL tra le fonti.

### Test
- 67 test: ordinamento IP, marche temporali, elenco porte UDP e compatibilità con le impostazioni della v1.1, SAPI/OS/applicazione, regole di priorità, riga di comando (codici di uscita, file di bersagli, argomenti non validi), modalità leggera, metodi dell'alive check nel risultato e nel CSV.

## v1.1 — 2026-10-23

Tempi di scansione, su segnalazione del maintainer (host che risponde al ping in 13 ms ma 4,2 s di durata).

### Corretto
- **Alive check in parallelo**: ICMP, TCP e UDP partono insieme e ci si ferma alla prima conferma; un host muto costa il timeout più lungo (1,5 s predefinito) invece della somma dei timeout (prima fino a 7 s).
- **Porta chiusa o muta: una sola connessione.** Se l'handshake TLS trova la porta rifiutata (RST) o aperta ma senza risposta, le richieste HTTP non vengono tentate (test "Richieste HTTP: non tentate"). Su Windows ogni connessione rifiutata costa ~2 s per i nuovi tentativi di SYN dello stack: prima si pagava due volte.
- **Tempi per fase** (alive, dns, tls, http-l1, http-l2, waf) nel log, nella scheda del bersaglio (doppio clic), nel report e in `results.json` (`PhaseMs`): ogni millisecondo è attribuito; alive check e handshake TLS mostrano la propria durata nell'evidenza.

### Test
- Nuovi test: porta chiusa senza seconda connessione, porta aperta ma muta saltata dopo il timeout dell'handshake, alive check parallelo.

## v1.0 — 2026-10-23

Prima versione.

- Bersagli: IP, reti CIDR, intervalli, nomi (FQDN); porte TCP multiple (predefinita 443); percorsi configurabili; Host header per gli IP; resolver DNS esplicito.
- Alive check preliminare configurabile: ICMP (API di sistema, senza privilegi), TCP (anche un RST vale come host attivo), UDP (solo risposta o ICMP port unreachable confermano); opzione "salta i non attivi".
- Livello 1 (passivo): versione PHP da X-Powered-By, Server, pagine phpinfo esposte, easter egg; cookie PHPSESSID con controllo del formato; errori PHP nel corpo. Confronto con 8.2.35, 8.3.36, 8.4.27, 8.5.12; rami 5.4 … 8.1 segnalati come "probabilmente vulnerabili" (backport non escludibile).
- Livello 2 (precondizioni e barriere): multipart minimo contro url-encoded, otto varianti di Content-Type, campo PHP_SESSION_UPLOAD_PROGRESS senza cookie, limite di dimensione (413). Nessuna richiesta porta PHP in esaurimento memoria; nessun codice di sfruttamento.
- Rilevazione WAF / CDN / reverse proxy / bilanciatori: firme su intestazioni, cookie, pagine di blocco, certificato TLS; test comportamentale con parametri ostili inerti; richieste ripetute per osservare nodi diversi.
- Verdetti con motivazione ed evidenze: Vulnerabile per versione, Probabilmente vulnerabile, Mitigato al perimetro, Non determinabile, Corretto per versione, PHP non rilevato, Non raggiungibile.
- Scansione parallela interrompibile; cartella di sessione con scan.log, results.json (riscritto ad ogni risultato), results.csv, tests.csv, session.json; report HTML autoconsistente mai sovrascritto; esportazione log/CSV/JSON; riapertura delle sessioni salvate.
- Interfaccia in italiano e inglese (stesso schema di DNS Load Tester), guida integrata (F1), programma portable per Windows x64.
- Test xunit: parser dei bersagli, confronto versioni, regole di verdetto, firme WAF, scansioni complete contro un server PHP finto, localizzazione, coerenza del repository.
