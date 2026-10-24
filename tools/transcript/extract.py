#!/usr/bin/env python3
"""Estrae dalla trascrizione JSONL di una sessione Claude Code / claude.ai i messaggi del maintainer, le risposte
di Claude (testo visibile), le operazioni tecniche (una riga per strumento) e le immagini caricate.

Uso:  python3 -I tools/transcript/extract.py [trascrizione.jsonl] uscita.json [cartella_immagini]
Senza trascrizione esplicita usa il file .jsonl modificato più di recente sotto ~/.claude/projects (esclusi i subagenti).
Non include il ragionamento interno né gli output degli strumenti. Orari in ora di Roma.
"""
import base64, datetime, glob, json, os, re, sys
from zoneinfo import ZoneInfo

ROME = ZoneInfo("Europe/Rome")
SR = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)


def latest_transcript() -> str:
    files = [f for f in glob.glob(os.path.expanduser("~/.claude/projects/**/*.jsonl"), recursive=True) if "/subagents/" not in f]
    if not files:
        sys.exit("nessuna trascrizione trovata sotto ~/.claude/projects")
    return max(files, key=os.path.getmtime)


def local(ts: str) -> str:
    if not ts:
        return ""
    t = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(ROME)
    return t.strftime("%d/%m/%Y %H:%M")


def clean_user(txt: str) -> str:
    txt = SR.sub("", txt)
    txt = re.sub(r"<local-command-caveat>.*?</local-command-caveat>", "", txt, flags=re.S)
    txt = re.sub(r"<command-name>.*?</command-name>\s*<command-message>.*?</command-message>\s*<command-args>(.*?)</command-args>", r"[comando: \1]", txt, flags=re.S)
    txt = re.sub(r"<local-command-stdout>.*?</local-command-stdout>", "", txt, flags=re.S)
    txt = re.sub(r"Your response above was stopped by a safety classifier.*?even reworded\.", "[nota di sistema: risposta precedente interrotta dal classificatore di sicurezza]", txt, flags=re.S)
    txt = re.sub(r"The (\d+ )?attached image.*?(view them|view it)\.", "", txt, flags=re.S)
    txt = re.sub(r"One of the files attached to this message is at (\S+)\s.*?ask the user to upload it again\.", r"[allegato: \1]", txt, flags=re.S)
    txt = re.sub(r'@"/mnt/user-data/attachments/[^"]*/[0-9a-f]{8}-([^"]+)"', r"[allegato: \1]", txt)
    txt = re.sub(r"\[allegato: /mnt/user-data/uploads/([^\]]+)\]", r"[allegato: \1]", txt)
    txt = txt.replace("[Request interrupted by user]", "[richiesta interrotta dall'utente]")
    return txt.strip()


def main():
    args = sys.argv[1:]
    if len(args) >= 2 and args[0].endswith(".jsonl"):
        src, out = args[0], args[1]; imgdir = args[2] if len(args) > 2 else None
    elif len(args) >= 1:
        src, out = latest_transcript(), args[0]; imgdir = args[1] if len(args) > 1 else None
    else:
        sys.exit(__doc__)
    imgdir = imgdir or os.path.join(os.path.dirname(os.path.abspath(out)), "img")
    os.makedirs(imgdir, exist_ok=True)

    entries, n_img = [], 0
    for line in open(src, encoding="utf-8"):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        t, ts = o.get("type"), o.get("timestamp", "")
        if t == "user":
            c = (o.get("message") or {}).get("content")
            if o.get("isCompactSummary"):
                txt = c if isinstance(c, str) else " ".join(x.get("text", "") for x in c if isinstance(x, dict))
                txt = re.sub(r"<tools-used-before-summary>.*?</tools-used-before-summary>\s*", "", txt, flags=re.S)
                entries.append({"kind": "summary", "time": local(ts), "text": txt})
                continue
            if o.get("isMeta"):
                continue
            blocks = [{"type": "text", "text": c}] if isinstance(c, str) else (c or [])
            if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in blocks):
                continue
            texts, imgs = [], []
            for b in blocks:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "text":
                    texts.append(b["text"])
                elif b.get("type") == "image" and (b.get("source") or {}).get("type") == "base64":
                    n_img += 1
                    ext = "png" if "png" in b["source"].get("media_type", "") else "jpg"
                    p = os.path.join(imgdir, f"u{n_img:03d}.{ext}")
                    with open(p, "wb") as fh:
                        fh.write(base64.b64decode(b["source"]["data"]))
                    imgs.append({"path": os.path.abspath(p), "type": ext})
            raw = "\n".join(texts)
            if "<task-notification>" in raw or "SYSTEM NOTIFICATION" in raw:
                continue
            txt = clean_user(raw)
            if not txt and not imgs:
                continue
            entries.append({"kind": "user", "time": local(ts), "text": txt, "images": imgs})
        elif t == "assistant":
            for b in (o.get("message") or {}).get("content") or []:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "text" and b["text"].strip():
                    entries.append({"kind": "assistant", "time": local(ts), "text": b["text"].strip()})
                elif b.get("type") == "tool_use":
                    name, inp = b.get("name", ""), b.get("input") or {}
                    if name == "SendUserMessage":
                        entries.append({"kind": "assistant", "time": local(ts), "text": inp.get("message", "")})
                        continue
                    desc = inp.get("description") or inp.get("subject") or inp.get("file_path") or inp.get("query") or inp.get("url") or inp.get("method") or inp.get("path") or inp.get("pattern") or ""
                    if name == "SendUserFile":
                        desc = "file inviati: " + ", ".join(os.path.basename(x) for x in inp.get("files", []))
                    entries.append({"kind": "tool", "time": local(ts), "text": f"{name}: {str(desc)[:160]}"})

    merged = []
    for e in entries:
        if e["kind"] == "tool" and merged and merged[-1]["kind"] == "tools":
            merged[-1]["items"].append(e["text"])
        elif e["kind"] == "tool":
            merged.append({"kind": "tools", "time": e["time"], "items": [e["text"]]})
        else:
            merged.append(e)
    # immagini: dimensioni per il documento
    try:
        from PIL import Image
        for e in merged:
            for im in e.get("images", []):
                im["w"], im["h"] = Image.open(im["path"]).size
    except ImportError:
        for e in merged:
            for im in e.get("images", []):
                im["w"], im["h"] = 1200, 800
    meta = {"source": src, "exported": datetime.datetime.now(ROME).strftime("%d/%m/%Y %H:%M"),
            "first": next((e["time"] for e in merged if e.get("time")), ""), "last": next((e["time"] for e in reversed(merged) if e.get("time")), "")}
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "entries": merged}, fh, ensure_ascii=False)
    users = sum(1 for e in merged if e["kind"] == "user")
    print(f"{users} messaggi del maintainer, {sum(1 for e in merged if e['kind'] == 'assistant')} risposte, {n_img} immagini, dal {meta['first']} al {meta['last']} ({src})")


if __name__ == "__main__":
    main()
