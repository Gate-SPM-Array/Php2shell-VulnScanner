#!/bin/bash
# Esporta in Word la trascrizione della sessione corrente (regola 11 di CLAUDE.md).
# Uso: tools/export_transcript.sh [trascrizione.jsonl]
# Uscita: Trascrizioni/Trascrizione_<AAAA-MM-GG>_v<N>.docx (cartella esclusa da git: contiene dati del cliente).
# Ogni esportazione ha un numero nuovo: le precedenti non si sovrascrivono mai.
set -e
cd "$(dirname "$0")/.."
OUTDIR=Trascrizioni; mkdir -p "$OUTDIR"
DAY=$(TZ=Europe/Rome date +%Y-%m-%d)
N=1; while [ -e "$OUTDIR/Trascrizione_${DAY}_v${N}.docx" ]; do N=$((N+1)); done
WORK=$(mktemp -d)
python3 -I tools/transcript/extract.py ${1:+"$1"} "$WORK/chat.json" "$WORK/img"
node -e "require('docx')" 2>/dev/null || npm install --no-save --silent docx >/dev/null
node tools/transcript/build_docx.js "$WORK/chat.json" "$OUTDIR/Trascrizione_${DAY}_v${N}.docx"
rm -rf "$WORK"
echo "$OUTDIR/Trascrizione_${DAY}_v${N}.docx"
