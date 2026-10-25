# Confronto con assetnote/php2shell-scanner (25/10/2026, PhpVulnScanner v1.9)

Fonti lette: `README.md`, `scanner.py`, issue #1 e cronologia dei commit del repository `assetnote/php2shell-scanner` (MIT, ultimo commit 24/10/2026 "flag unfixed legacy PHP branches"); articolo Searchlight Cyber "High fidelity detection mechanism for php2shell". La segnalazione di CERT-AgID citata dal maintainer non è stata verificata (sito non raggiungibile dalla sessione).

## Che cosa fa lo scanner Assetnote
- Per ogni percorso (predefinito `/index.php`, phpMyAdmin ritentato su `/show_config_errors.php`): una richiesta multipart di controllo (~42 byte) e fino a **tre sonde multipart da 1, 8 e 20 MiB** (4000, 1020, 1020 parti, chiavi annidate a 62 livelli, boundary vuoto): ~29 MiB per percorso.
- Verdetto **VULNERABLE** se la sonda produce un errore fatale di memoria in chiaro, un 500 con corpo vuoto (il controllo aveva corpo), un 502/503/504 o un 200 vuoto (worker FPM terminato). Il segnale di crash **vince sulla versione**: un host patchato che va in OOM viene detto vulnerabile.
- Verdetto **FIXED** se nessun crash e versione da `X-Powered-By` ≥ 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; rami < 8.2 vulnerabili (commit del 24/10); altrimenti NO SIGNAL / INCONCLUSIVE.
- Versione letta solo da `X-Powered-By`. User-Agent che imita Chrome con suffisso `PHP2Shell/1.0.0`. Nessun alive check, nessuna scoperta di nomi, nessun riconoscimento di WAF/CDN, nessun report: JSON degli host vulnerabili.
- **Limiti dichiarati dagli autori** (README, sezione aggiunta dopo la issue #1 del 22/10): sulle versioni **patchate** 8.4.27 (memory_limit 2-32M) e 8.3.36 (128M con `max_multipart_body_parts` ≥ 2785) la sonda produce lo stesso 500 vuoto: **falso positivo**; senza versione dichiarata l'OOM sicuro post-patch è indistinguibile da quello vulnerabile. Il verdetto "ambiguo" proposto nella issue non risulta implementato.

## Che cosa fa PhpVulnScanner e dove sta la differenza
| Aspetto | Assetnote | PhpVulnScanner v1.9 |
|---|---|---|
| Versione dichiarata | solo `X-Powered-By`, stessa tabella di soglie | `X-Powered-By`, `Server` (valori grezzi, anche `Apache/2.4 (Debian) PHP/8.1`), easter egg, phpinfo esposto, versioni nel corpo (indizio); stessa tabella 8.2.35/8.3.36/8.4.27/8.5.12; **regola del numero puro** sui rami EOL (senza suffisso di distribuzione = vulnerabile, con suffisso = probabilmente vulnerabile, perché il backport del vendor non è escludibile) |
| Sonda di esaurimento memoria | sì, 29 MiB per percorso, è il segnale principale | **no, per scelta** (regola 2 di `CLAUDE.md`): è la prima metà della catena di attacco sui worker non patchati e, per ammissione degli autori, ambigua su quelli patchati |
| Richieste di livello 2 | multipart grandi | multipart **piccoli e inerti**: barriera multipart su più varianti di Content-Type, campo `PHP_SESSION_UPLOAD_PROGRESS` senza cookie (PHP non scrive nulla), limite di dimensione a 256 KiB |
| Senza versione dichiarata | OOM → VULNERABLE (falso positivo possibile) o INCONCLUSIVE | **Non determinabile**, mai un verdetto senza evidenza (regola 1); in più PHP sì/forse/no da prove e indizi pesati, SAPI dalla sonda del file inesistente e dal banner |
| Mitigazioni al perimetro | non viste (un WAF che blocca il multipart dà "rifiutato", sonda interrotta) | verdetto **Mitigato al perimetro** quando ogni variante multipart è bloccata e PHP è indicato; riconoscimento di WAF/CDN/reverse proxy/bilanciatori, correlazione dell'IPS unico |
| Superficie | un percorso (più `--path`) | percorsi configurati + scoperta della superficie PHP (40 punti di ingresso, link, robots.txt), nomi dal certificato, da Location, da PTR e da Certificate Transparency con seconda passata per nome |
| Reti intere | lista di URL | IP, CIDR, intervalli, nomi; alive check con tetto e seconda chance; pre-controllo delle porte; cicli consolidati con fusione per campo; fusione di sessioni |
| Identità del traffico | UA da browser con suffisso | UA che nomina lo strumento (regola 3); nessuna funzione per nascondere la sorgente |
| Uscite | JSON (host vulnerabili, evidenze redatte) | tabella, report compatto e completo con evidenze per richiesta, CSV, JSON, JSONL di ogni osservazione, elenco per Excel, file per OpenVAS, inventario riconciliato |
| CVE-2026-115560 | non trattata | impostazioni lette da phpinfo quando esposto (`session.upload_progress.enabled`, `serialize_handler`), nota nel report: nessuna release corretta |

## Riscontro
1. **Sulla parte "per versione" i due scanner sono equivalenti**: stessa tabella di soglie, stessa logica sui rami EOL (Assetnote dal 24/10 li marca tutti vulnerabili; noi distinguiamo numero puro e numero con suffisso, che è più prudente ma non meno severo).
2. **Il "segnale ad alta fedeltà" di Assetnote non è nel nostro scanner, e non ci entrerà**: è una richiesta che manda PHP in esaurimento di memoria. Sui worker non patchati è la prima metà dell'exploit; sui worker patchati, per ammissione degli autori (issue #1, README), produce falsi positivi che il loro codice non corregge (il crash vince sulla versione). Il nostro verdetto in quel caso è "Non determinabile" con tutte le evidenze passive raccolte, che è quello che serve a chi deve poi verificare sull'host.
3. **In tutto il resto il nostro fa di più**: mitigazioni al perimetro, WAF, superficie, nomi, reti intere, cicli, report, inventario. Assetnote risponde a "questo URL è vulnerabile?"; il nostro a "in questo perimetro chi deve muoversi, e con quale priorità".
4. Se ti serve una terza voce per la PA: i due strumenti sono complementari. Il nostro dà l'inventario e la priorità senza toccare i worker; Assetnote (o la sua logica) può essere usato **dal titolare del sistema, su un host alla volta, con autorizzazione**, per confermare un "Non determinabile" dove la versione non si vede, sapendo che sui patchati può dire "vulnerabile" a torto.

Nessuna modifica al codice deriva da questo confronto.
