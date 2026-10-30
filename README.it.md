# PHP Vuln Scanner v1.12

[English](README.md) · **Italiano**

Scanner portable per Windows che rileva **dall'esterno**, in pochi secondi per bersaglio, l'esposizione alle due vulnerabilità del runtime PHP pubblicate il 21 ottobre 2026 (**PHP2Shell**, CVE-2026-109618 e CVE-2026-109619) e riconosce **WAF, CDN, reverse proxy e bilanciatori** a monte. Interfaccia grafica, log esteso, report HTML, esportazione CSV/JSON.

> **Uso responsabile.** Scansionare solo sistemi propri o con autorizzazione scritta del titolare. Il programma si dichiara nel `User-Agent`. Non contiene né esegue codice di sfruttamento, non modifica lo stato dei server e non invia richieste che portino PHP in esaurimento memoria.

> **Lingua:** il programma parla italiano e inglese (pulsante **🌐 Lingua**, applicato al riavvio). Al primo avvio segue la lingua di Windows.

## 1. Cosa fa

| Funzione | Dettaglio |
|---|---|
| Bersagli | IP, reti CIDR (`192.0.2.0/24`), intervalli (`192.0.2.10-20`), nomi (FQDN); una voce per riga o separate da virgola/spazio |
| Porte | TCP multiple, predefinita 443; porta 80 = HTTP, altre porte HTTPS se l'handshake TLS riesce |
| Alive check | ICMP (senza privilegi su Windows), TCP (anche un RST vale), UDP (solo risposta o ICMP port unreachable), timeout e "salta i non attivi" configurabili |
| Livello 1, passivo | Versione PHP da `X-Powered-By`, `Server`, pagine phpinfo esposte, easter egg; cookie `PHPSESSID`; errori PHP nel corpo. Confronto con 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Livello 2, barriere | Multipart minimo contro url-encoded, otto varianti di Content-Type, campo `PHP_SESSION_UPLOAD_PROGRESS` senza cookie, limite di dimensione (413) |
| WAF / proxy | Firme su intestazioni, cookie, pagine di blocco e certificato TLS; test comportamentale con parametri ostili inerti; richieste ripetute per i bilanciatori |
| Verdetti | Vulnerabile per versione · Probabilmente vulnerabile · Mitigato al perimetro · Non determinabile · Corretto per versione · PHP non rilevato · Non raggiungibile, ciascuno con motivazione ed evidenze; **priorità** di remediation derivata da verdetto, SAPI e barriera |
| Contesto passivo | **SAPI** (mod_php / FPM / LSAPI / CGI) e **sistema operativo** dal banner, **applicazione** riconosciuta (WordPress, Joomla, Drupal, phpMyAdmin, Nextcloud, Laravel, Moodle, GLPI, TYPO3…) con rimando all'inventario [NCSC-NL](https://github.com/NCSC-NL/php2shell) |
| Superficie PHP | Sonda di un `.php` inesistente (`File not found.` = PHP-FPM, `No input file specified.` = php-cgi), una quarantina di punti di ingresso comuni con sole HEAD, `.php` linkati dalle pagine; il livello 2 usa il miglior `.php` scoperto |
| Nomi scoperti | Nomi DNS da certificato (CN/SAN) e `Location`, con seconda passata facoltativa sugli stessi IP con `Host`/SNI = nome (`nome @ IP`): la scansione per IP vede solo il vhost predefinito |
| Avanzate | Test aggiuntivi in sola lettura, una casella ciascuno: HEAD contro GET e OPTIONS, Composer (versione minima di PHP dichiarata, librerie), pagine di stato (server-info = SAPI certa, stato FPM), file di versione delle applicazioni con confronto NCSC-NL, sonda FastCGI 9000, comportamenti di PHP (PATH_INFO, xmlrpc, sorgenti esposti), livello 2 su ogni .php, User-Agent da browser, inventario dei componenti, esposizioni (.env, .git, backup), più nomi (PTR, Certificate Transparency); pre-controllo TCP delle porte; nomi con lo stesso contenuto del vhost predefinito senza riga; numero puro su ramo fuori supporto = vulnerabile per versione |
| Pausa e fusione | Pausa / Riprendi senza perdere nulla; **Fondi sessioni** (anche di versioni diverse) con report delle differenze; **Aggiorna dati** da GitHub |
| Indizi e loquacità (v1.5) | Colonna **PHP** a tre valori (sì / **forse** / no): "forse" = indizi passivi pesati senza prova (Expires fisso di session_start, cookie con ID di sessione PHP, cookie di framework, intestazioni, percorsi, pannelli); **impostazioni dalla pagina phpinfo** (upload_progress, serialize_handler, Server API) con la nota su **CVE-2026-115560** (senza release corretta); **indice di loquacità** 0-5 per host; nomi con lo **stesso esito** senza riga doppia (tutti i nomi nel report compatto); **filtri** a scelta multipla e sintassi del testo (AND, `|`, `-`, virgolette, `campo:valore`, jolly `*` `?`, CIDR e intervalli) |
| File hosts e `nome@IP` (v1.12) | Nomi assegnati localmente a un IP (file in formato hosts, `--hosts-file`, oppure `nome@IP` nella lista bersagli) scansionati su quell'IP con SNI e `Host` = nome, **senza query DNS**, come un browser con la voce nel file hosts: una riga `nome @ IP` per nome, mai ripiegata; server tolti dal DNS pubblico o più servizi dietro un indirizzo vengono provati come li raggiungono i loro utenti |
| Sweeper sulle porte dell'alive check, avviso porta del perimetro (v1.11.1) | Lo sweeper non usa mai le porte della scansione come prova di vita (un perimetro che rispondeva su TCP/1720 per ogni indirizzo aveva reso "attivi" 3556 host su 4094); una porta TCP che conferma quasi tutti gli host della rete viene segnalata come perimetro |
| Sweeper continuo dell'alive check, host noti (v1.11) | Un task a parte riprova i non confermati per tutto il ciclo e fa entrare chi risponde nel ciclo in corso; file **Host noti** dalle sessioni precedenti (`--known-hosts`), host noti muti segnalati; nomi da CT dirottati ricordati tra i cicli |
| Nomi da CT verificati via DNS, configurazione su file, pacchetto per analisi (v1.10) | I nomi da Certificate Transparency entrano solo se risolvono sull'IP in esame (sulla /20 di riferimento l'80% del tempo dei thread andava a nomi ospitati altrove); seconda chance su 16 corsie e, dal ciclo 2, solo per gli host visti attivi; esito "connessione chiusa dal perimetro"; nomi uno per riga nel report compatto; CSV rigenerati con suffisso come i report; **Salva/Carica config** e `--config`/`--save-config`; **pacchetto per analisi** senza corpi (`--analysis-bundle`) |
| Seconda chance regolata (v1.9) | La seconda chance parte appena la coda degli host si svuota, su metà dei thread con timeout 1,5× (v1.8: 4 corsie, timeout doppio, a fine ciclo: 11,5 min per ciclo sulla /22) |
| Tetto alive, seconda chance, fusione per campo, elenco Excel (v1.8) | Tetto separato per l'alive check e **seconda chance** a fine ciclo per i non confermati; lavoratori con coda a priorità (nomi prima degli host nuovi); **consolidamento campo per campo** tra i cicli; **elenco per Excel** nel report compatto e in `elenco_vX.Y.csv`; CT sul sottodominio più specifico |
| Nomi in parallelo, PHP forse (v1.7) | Seconda passata sui nomi scoperti sul pool dei thread invece che in sequenza per host (la coda del ciclo era un thread solo); righe per IP in anteprima prima dei nomi; catch-all 5xx anche con `/` in redirect; **PHP forse** in evidenza (righe in lilla, riquadro come filtro, sezione in alto nel report compatto) |
| Certificati, inventario, budget (v1.6) | **Stato del certificato TLS** (scaduto, autofirmato, catena, nome, chiave); **cache davanti all'origine**; versioni dichiarate nel corpo; **inventario CSV/JSON riconciliato** (referente accanto a ogni servizio, versioni diverse, dichiarati non osservati, osservati non inventariati); **adozione dell'ID di sessione** (facoltativo); **budget per servizio** e stop sui backend morti (catch-all 5xx); scrittura dei file di sessione fuori dal blocco dei thread |
| Cicli | N cicli con pausa; una sessione per ciclo oppure consolidamento (vince il risultato più informativo, storia dei cicli, `Δ` sui verdetti cambiati); ordine casuale, pausa casuale tra le richieste e tetto di richieste/s; stima di fine ciclo e fine loop sul ritmo degli ultimi 5 minuti |
| Interfaccia | Colonne **Bersaglio** (IP) e **Nome** (FQDN) separate; riquadri di riepilogo come filtri che contano **servizi e host** (anche **Host attivi**), barra dei filtri (testo, verdetto, priorità, alive, barriera), ordinamento per numerazione IP, orario di avvio ISO con millisecondi, log con ora locale e UTC |
| Riga di comando | `PhpVulnScanner.exe --scan <file> …` senza interfaccia, con codici di uscita per script e attività pianificate (vedi §4) |
| Uscite | `scan.log`, `results.json`, `results.jsonl` (una riga per osservazione), `results.csv`, `tests.csv`, `session.json`, **report compatto** `report_vX.Y.html` (solo ciò che ha qualcosa da dire) e `report_completo_vX.Y.html` (tutto, con la sezione per ciclo), `host_attivi_vX.Y.txt` / `host_http_vX.Y.txt` / `nomi_scoperti_vX.Y.txt` (un IP per riga, per OpenVAS); `samples.json` anonimizzato in modalità debug; esportazione log/CSV/JSON; riapertura delle sessioni |

**Perché non c'è un test di sfruttabilità.** Nessuno scanner esterno dimostra la sfruttabilità di PHP2Shell: i test che portano PHP in esaurimento memoria rispondono allo stesso modo su un PHP corretto e su uno vulnerabile (issue #1 dello scanner Assetnote) e, su un worker non corretto, sono la prima metà della catena d'attacco. Per scelta lo scanner si ferma alla versione dichiarata e alle barriere: senza versione il verdetto resta "Non determinabile" e la prova va cercata sull'host (`php -v`, changelog del pacchetto).

## 2. Requisiti e avvio

- Windows 10/11 x64 oppure Windows Server 2016 o successivi. Nessuna installazione: l'exe è autosufficiente.
- Estrarre `PhpVulnScanner_v1.4_win-x64.zip` dove si preferisce e avviare `PhpVulnScanner.exe`. Guida completa con **F1**.

## 3. Programma portable

```
PhpVulnScanner\
  PhpVulnScanner.exe
  lang\en.json                      traduzione inglese (incorporata anche nell'exe; questo file ha la precedenza)
  data\                             firme delle tecnologie (webappanalyzer) e inventario NCSC-NL, con data di estrazione
  PhpVulnScanner.settings.json      ultima configurazione e lingua
  Guida_PhpVulnScanner_v1.4.html    guida (F1); Guide_… in inglese
  Sessioni\                         una cartella per ogni scansione
```

Se la cartella è in sola lettura, impostazioni e sessioni vanno in `%LOCALAPPDATA%\PhpVulnScanner` e `Documenti\PhpVulnScanner\Sessioni`.

## 4. Riga di comando

```
PhpVulnScanner.exe --scan bersagli.txt --ports 443,8443 --out D:\scansioni --label cliente --quiet
PhpVulnScanner.exe --scan 192.0.2.10,www.example.org --no-alive --light --json esito.json
PhpVulnScanner.exe --scan 192.0.2.0/22 --cycles 4 --cycle-pause 300 --random --delay 50-250 --rate 20 --threads 8 --advanced all
PhpVulnScanner.exe --merge D:\scansioni\20261023_224732_phpscan D:\scansioni\20261024_023528_phpscan --out D:\scansioni
PhpVulnScanner.exe --help
```

Stessa scansione, stessi file di sessione e report, nessuna finestra. Codici di uscita: **0** nessun vulnerabile, **1** almeno un "vulnerabile per versione" o "probabilmente vulnerabile", **2** argomenti non validi, **3** solo "non determinabili", **4** scansione interrotta o in errore. Da uno script: `& .\PhpVulnScanner.exe --scan ... ; if ($LASTEXITCODE -eq 1) { ... }`.

## 5. Compilazione dai sorgenti

```
dotnet build -c Release            # SDK .NET 10; su Linux EnableWindowsTargeting è già impostato per l'app WPF
dotnet test -c Release             # include scansioni complete contro un server PHP finto su loopback
dotnet publish src/PhpVulnScanner.App -c Release -r win-x64 -o publish -p:DebugType=none
```

Struttura: `src/PhpVulnScanner.Core` (bersagli, alive check, HTTP/TLS, test PHP, rilevazione WAF, motore, file, report; nessuna interfaccia), `src/PhpVulnScanner.App` (WPF), `tests/PhpVulnScanner.Tests` (xunit), `lang/` (traduzioni).

## 6. Traduzioni

Ogni testo passa dai file `lang\<codice>.json`: copiare `en.json`, impostare `code`, `language`, `culture`, tradurre i valori (le chiavi sono i testi italiani e non vanno modificate, i segnaposto `{0}` devono restare identici), riavviare e scegliere la lingua.

## 7. Licenza e crediti

Licenza [MIT](LICENSE); componenti di terze parti in [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt). Sviluppato da [Gate-SPM-Array](https://github.com/Gate-SPM-Array) con [Claude](https://claude.com) (Anthropic) sulla base dei requisiti e delle scelte progettuali del maintainer. Riferimenti tecnici: avvisi PHP GHSA-w8hw-w9fx-j79w e GHSA-6wmf-4rv5-p3rp, CERT-EU 2026-018, Datadog Security Labs, Wiz, Assetnote, Blue-B/php2shell-guard.
