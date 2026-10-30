# Checklist prima di rendere pubblico il repository (27/10/2026)

Controllo fatto sui file di tutti i branch (`main`, `claude/modest-hopper-1ewrba`, `docs/trascrizione-attiva`) e su tutte le 24 revisioni della storia.

## File attuali: puliti
- Nessun indirizzo IP reale, nessun nome di ente o cliente, nessuna e-mail nei sorgenti, nei test, nei documenti e nei CHANGELOG (gli esempi usano RFC 5737 ed example.org; "marche temporali" = timestamp; "Regione Acme" è un segnaposto di test).
- `Sessioni/`, `Trascrizioni/`, `PhpVulnScanner.settings.json`, `tools/private-patterns.txt`, `samples.json`, report e CSV sono esclusi da git e non sono mai stati committati.
- Licenze: MIT per il programma; dati derivati da webappanalyzer (GPL-3.0) e NCSC-NL (EUPL-1.2) con i testi in `data\` e `THIRD-PARTY-NOTICES.txt`: redistribuzione lecita, decisione del maintainer del 24/10 di lasciarli nel pacchetto.

## Un residuo nella storia dei commit
- `tools/package.sh`, da `b2338b2` (import iniziale, 24/10) fino al commit prima di `add901c` (v1.7): il grep anti-dati-cliente conteneva il prefisso `84\.38\.` (le prime due cifre della /20 del cliente). È in 10 revisioni, visibili a chiunque con `git log -p` una volta pubblico il repository. Dalla v1.7 i pattern stanno in `tools/private-patterns.txt`, fuori da git.
- Gravità: bassa (due ottetti di un /16 condiviso, senza nome), ma la regola 7 non ammette eccezioni e la correzione costa dieci minuti.

- Secondo residuo (29/10, commit `1e2efe6`, branch della PR #2): una riga del diario conteneva l'indirizzo completo di un host del cliente; corretta nel commit successivo ma presente in quella revisione. Stessa cura: `filter-repo --replace-text` con una seconda riga `<indirizzo>==>203.0.113.9` (l'indirizzo esatto è nella riga 101 della revisione `1e2efe6` del diario; non viene riportato qui).

## Cosa deve fare il maintainer (le regole vietano a Claude di forzare `main`)
1. **Prima** della pubblicazione: fondere la PR #2 (v1.7-v1.9) e, se la vuole, la PR #1 (trascrizione attiva), così le branch da riscrivere sono solo quelle che restano.
2. Riscrivere la storia sostituendo il pattern, con `git filter-repo` (una tantum, da un clone fresco):
   ```
   git clone --mirror https://github.com/Gate-SPM-Array/Php2shell-VulnScanner.git repo.git
   cd repo.git
   printf '84\\.38\\.==>203\\.0\\.113\\.\n' > ../replace.txt
   git filter-repo --replace-text ../replace.txt
   git push --force --all && git push --force --tags
   ```
   Poi ogni clone locale va rifatto (le hash cambiano dal commit `b2338b2` in avanti). Se restano PR aperte, i loro branch vengono riscritti dallo stesso comando (`--all`).
3. Facoltativo, stessa occasione: l'e-mail degli autori dei commit (`cloude.ai@27001.it`) diventa pubblica. Se preferisce l'indirizzo noreply di GitHub, `filter-repo` lo cambia con `--mailmap` prima del push.
4. Impostazioni del repository pubblico (fuori dalla portata di Claude): branch `main` protetto (PR obbligatoria), Issues aperte o chiuse a scelta, Security policy (`SECURITY.md`: segnalazioni a un indirizzo scelto dal maintainer), Discussioni spente.
5. **Release**: creare la release `v1.9` su GitHub caricando `PhpVulnScanner_v1.9_win-x64.zip` (è l'unico modo in cui i colleghi scaricano l'eseguibile: il repository contiene solo i sorgenti). Claude non pubblica release (regola 5).

## Da aggiungere nel repository prima della pubblicazione (Claude, su PR, al via del maintainer)
- `SECURITY.md` con l'indirizzo per le segnalazioni e la nota "uso solo su sistemi propri o con autorizzazione scritta".
- Nel `README` (EN e IT): sezione "Download" che rimanda alla release, e il riquadro di uso responsabile già presente nella guida.
- `CONTRIBUTING` minimo: PR su `main`, test verdi, regola delle versioni.
