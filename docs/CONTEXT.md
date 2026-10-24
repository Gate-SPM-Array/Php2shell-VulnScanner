# CONTEXT — PhpVulnScanner (copia per Claude Code, 24/10/2026 17:50)

Copia sanificata del documento di contesto tenuto nel Project claude.ai "Scan PHP Shell Vulnerability - octo-2026". Nessun indirizzo o nome di cliente: i dati reali delle scansioni restano fuori dal repository (regola 7 di `CLAUDE.md`).

## Come lavorare con il maintainer (David)
- **Nessuna nuova versione senza il suo via** ("procedi" / "vai"): prima la proposta (cosa, perché, costo), poi codice, build e zip. Vale anche per i bug fix urgenti (regola 9 di `CLAUDE.md`).
- Ogni consegna = nuova versione + voce in `CHANGELOG.md` (`tools/bump_version.py vecchia nuova` porta il numero ovunque; `tools/package.sh <ver>` fa grep anti-dati-cliente, publish e i due zip).
- Stime: dire solo "ti arriva entro le X". Risposte brevi, schiette, con i numeri.
- Le "sensazioni" di David si verificano sui dati (results.json/jsonl, scan.log) prima di rispondere; contare sempre le righe `errore` nel `scan.log`; se un ciclo è lento misurare l'occupazione dei thread dal `results.jsonl`.
- Priorità dichiarate: qualità della detection sopra la velocità (anche +1 h per ciclo); i cicli servono a beccare gli host attivi su cui concentrare la remediation; **i nomi (FQDN) sono "oro"**, mai tagliarli nel report compatto; le informazioni raccolte su un host valgono come vulnerabilità organizzativa (da qui "PHP forse", loquacità, certificati, inventario).
- Terminologia: **host** = IP; **servizio** = riga (IP + porta + nome). I riquadri contano i servizi e, sotto, gli host.

## Stato
- **v1.9 (24/10 notte, Claude Code, PR #2)**, 390 test: seconda chance anticipata (parte con la coda degli host vuota) e più leggera (metà dei thread, timeout 1,5×); nella v1.8 sulla /22 costava 11,5 min per ciclo per 3-4 host. Giro notturno del maintainer sulla /20 e sulla /22 con questa versione.
- **v1.8 (24/10 notte, Claude Code, stessa PR #2 della v1.7, in attesa del maintainer)**, 387 test verdi: tetto separato dell'alive check (8) e seconda chance a fine ciclo (il giro a 36 thread confermava 71 host su 4094; a 16 thread 280); lavoratori con coda a priorità (nella v1.7 i nomi aspettavano 16 min dietro gli host e la chiusura altri 18); consolidamento campo per campo (regola del maintainer); "PHP forse" in OR nei filtri; CT sul sottodominio; colonne del report e **elenco per Excel** (`elenco_vX.Y.csv`). Da provare sull'AS di un altro cliente.
- **v1.7 (24/10 sera, prima versione fatta da Claude Code, PR in attesa del maintainer)**, 374 test verdi: nomi scoperti in parallelo sul pool dei thread (la coda del ciclo era un thread solo: 5 host da 20-28 min nella /22), righe per IP in anteprima, catch-all 5xx anche con `/` in redirect, "PHP forse" in evidenza (riga lilla, riquadro-filtro, sezione in alto nel report compatto). Zip `PhpVulnScanner_v1.7_win-x64.zip` consegnati in chat.
- **v1.6 (24/10 17:43)**, 367 test xunit verdi. Considerata la versione "definitiva" dal maintainer; la prossima evoluzione va fatta da Claude Code su questo repository (privato).
- Storia: v1.0/1.1/1.2 (23/10), v1.3/1.3.1 (notte 23-24/10), v1.4 (12:12), v1.4.1 (regressione robots.txt), v1.4.2 (facciata), v1.5 (15:36), v1.6 (17:43). Dettagli nel `CHANGELOG.md`.
- WPF non testabile in cloud: da provare su Windows le tendine multi-scelta dei filtri (v1.5), le colonne Referente/Certificato e i campi Budget/Inventario (v1.6).

## Cosa fa (sintesi)
Scanner difensivo per PHP2Shell (CVE-2026-109618/109619): alive check, pre-controllo TCP, livello 1 passivo (banner, cookie, errori, phpinfo, superficie `.php`), livello 2 inerte (barriere multipart, campo upload progress senza cookie, limite di dimensione), WAF/CDN/proxy/bilanciatori, nomi scoperti con seconda passata e ripiegamento (stesso contenuto, stesso esito), database applicazioni (webappanalyzer + inventario NCSC-NL), 13 test aggiuntivi in sola lettura, PHP sì/forse/no da indizi pesati, impostazioni lette da phpinfo (con il giudizio su CVE-2026-115560, che non ha release corretta), loquacità 0-5, stato del certificato TLS, cache davanti all'origine, inventario CSV/JSON riconciliato, budget per servizio, cicli consolidati con stima, fusione di sessioni, report completo e compatto, file per OpenVAS, CLI completa.

## Vincoli non negoziabili
- Niente codice di sfruttamento, niente sonde di esaurimento memoria (livello 3 escluso anche dietro opt-in), niente richieste che scrivano stato nella sessione del bersaglio (il "marker di sessione" di uno script di terzi è stato scartato per questo). L'adozione dell'ID di sessione è una GET con cookie, spenta per impostazione predefinita.
- Esposizioni = solo esistenza, mai scaricare contenuti riservati. Senza versione dichiarata il verdetto è "Non determinabile".
- Soglie: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; regola del numero puro (ramo EOL senza suffisso di distribuzione → "Vulnerabile per versione"); "Corretto per versione" riguarda i due CVE del 21/10.
- File di sessione sempre leggibili all'indietro; report con la versione nel nome (`report_vX.Y.html`, `report_completo_vX.Y.html`).
- Localizzazione IT/EN: ogni testo visibile passa da `L.T/L.F` o `l:Loc.Text/Tip`, con traduzione in `lang/en.json`; i test la impongono.

## Lezioni dalle scansioni reali (anonimizzate)
- /20 di un ente pubblico, ~280 host attivi su 4.094, ~230 con HTTP, 9 host con PHP in rami vecchi (5.4 … 8.1), 1 corretto; un unico IPS davanti all'80% degli host; farm dietro bilanciatore con certificato condiviso → decine di righe per nome identiche (da qui il ripiegamento per esito).
- Bug storici trovati sui dati: CollectionView `DeferRefresh` (v1.3.0 crash); `robots.txt` che aggiungeva candidati durante il `foreach` (v1.3 → 18 servizi analizzati a metà); writer di sessione che serializzava 256 MB sotto lock (16 thread occupati per 4-5); falso positivo "bilanciatore" dalle date di risposte prese in momenti diversi.
- Impostazioni consigliate per una /20: 8-16 thread, random, pausa 50-250 ms, tetto 20-30/s, 2-6 cicli consolidati, porte 443,80,8080,8085,8443, Predefiniti o Massima detection, debug acceso, budget 120 s, inventario CSV se disponibile.

## CVE-2026-115560 (advisory informativa PHP, 23/10/2026)
Serve `session.serialize_handler` = `php_binary`/`php_serialize` in configurazione, riportato a `php` con `ini_set()` prima di `session_start()`, con upload progress attivo. Nessuna release corretta; mitigazione `session.upload_progress.enabled=0`. Invisibile dall'esterno: lo scanner la tratta solo tramite la pagina phpinfo quando esposta.

## Proposta ancora aperta (non entrata nella v1.7, via da dare)
"Esporta per analisi…" (pulsante accanto a "Esporta log…" e `--analysis-bundle` da CLI): `<sessione>_analisi_vX.Y.zip` con `session.json`, `scan.log`, `results.json` e `results.jsonl` **senza corpi** (al posto del corpo lunghezza e SHA-256; restano stato, intestazioni, test, evidenze, durate), `tests.csv`, `results.csv`, i due report, i file degli host, a scelta `samples.json`. Motivo: Claude Code accetta upload fino a 30 MB; gli zip di sessione reali pesano 60-75 MB per i corpi in debug, mentre senza corpi stanno in 2-10 MB. Costo ~1 h.

## Punti aperti
- Prova della v1.6 su Windows e nuovo giro con le impostazioni sopra; analisi del `scan.log` (righe `BUDGET`, `ADV-SKIP`, durata dei cicli); fusione con le sessioni precedenti.
- Formato dell'orario: confermare le 3 cifre di millisecondi.
- Nota tecnica SEC-OPS-ANA v.0.3 (fuori da questo repository): NCSC-NL tra le fonti, indicatori host, CVE-2026-115560 come CVE separata non corretta, certificati scaduti e inventario come esempio di "informazione = vulnerabilità organizzativa".
