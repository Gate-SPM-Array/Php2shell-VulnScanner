# Diario di sessione — Claude Code (branch `claude/modest-hopper-1ewrba`)

Appunti salvati periodicamente per non perdere informazioni alla compattazione della chat. Niente dati reali di scansione (regola 7 di `CLAUDE.md`): le immagini e i file caricati sono citati per nome, mai copiati.

## 2026-10-24 — ripresa da Cowork
- Repository verificato: branch allineato a `main`, v1.6, 367 test verdi su Linux (.NET 10 SDK installato dal repository apt Microsoft; il download diretto da builds.dotnet.microsoft.com è bloccato dalla policy di rete).
- File caricati dal maintainer: `CONTEXT_PhpVulnScanner.md` (contesto completo del Project claude.ai) e `PhpVulnScanner_v1.6_sources.zip` (SHA256 `20d8fe2a…e52fd`): identico file per file ai sorgenti nel repository.
- Limite di upload in questa sessione: 30 MB per file. Gli zip dei log del maintainer superano i 70 MB: accordato di caricare solo `scan.log` + `session.json` + `results.jsonl`, spezzando il jsonl per righe se necessario, oppure un estratto del log (`BUDGET`, `ADV-SKIP`, `errore`, `ciclo`).
- Immagine `1.png`: schermata della v1.6 in corso (ciclo 1 di 5, 6151 servizi, 108 host attivi su 1022, 82 con HTTP, 7 vulnerabili per versione su 4 host, 14 non determinabili su 12, 1 mitigato al perimetro, 134 PHP non rilevato su 75 host di cui 25 con indizi). Colonna PHP con "forse" visibile; righe "forse" senza evidenziazione.

## Richieste del maintainer per la v1.7 (24/10, sera)
1. Evidenziare i PHP "forse" nella tabella principale (riga colorata) e dare un pulsante/filtro dedicato.
2. Mettere i PHP "forse" in evidenza nel report, anche in quello compatto.
3. Fonti di dati terze (webappanalyzer GPLv3, NCSC-NL EUPL): per rendere pubblico il repository, l'interfaccia deve scaricare le fonti direttamente online invece di distribuirle nel pacchetto.
4. Nota operativa: salvare il contenuto della sessione in questo diario, periodicamente e prima di ogni compattazione; immagini e file solo per nome.

## Decisioni del maintainer (24/10, sera)
- Punto 3 (fonti terze scaricate online): **lasciare tutto com'è**, i dati derivati restano in `data\` con le licenze (distribuzione lecita, non un obbligo).
- Punti 1-2 (forse evidenziato in tabella, pulsante/filtro, evidenza nel report compatto): proposta accettata in linea di principio; **via non ancora dato**, arriva a fine test della v1.6 su Windows.
- Regola confermata: nessuna nuova versione senza l'ok esplicito del maintainer.
