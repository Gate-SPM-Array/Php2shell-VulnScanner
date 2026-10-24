// Costruisce il documento Word della trascrizione dal JSON prodotto da extract.py.
// Uso: node tools/transcript/build_docx.js chat.json uscita.docx [titolo]
const fs = require('fs');
const {
  Document, Packer, Paragraph, TextRun, ImageRun, HeadingLevel, AlignmentType, Footer, Header, PageNumber,
  LevelFormat, BorderStyle, ShadingType, TableOfContents, PageBreak,
} = require('docx');

const [, , IN, OUT, TITLE = 'Trascrizione della sessione — PhpVulnScanner'] = process.argv;
if (!IN || !OUT) { console.error('uso: node build_docx.js chat.json uscita.docx [titolo]'); process.exit(2); }
const { meta, entries } = JSON.parse(fs.readFileSync(IN, 'utf8'));
const FONT = 'Calibri', MONO = 'Consolas', MAXW = 600, MAXH = 780;

function inline(text, base = {}) {
  const runs = [];
  text = text.replace(/\[([^\]]+)\]\((https?:[^)]+)\)/g, '$1 ($2)');
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) runs.push(new TextRun({ text: text.slice(last, m.index), ...base }));
    const t = m[0];
    runs.push(t.startsWith('**') ? new TextRun({ text: t.slice(2, -2), bold: true, ...base }) : new TextRun({ text: t.slice(1, -1), font: MONO, size: 19, ...base }));
    last = m.index + t.length;
  }
  if (last < text.length) runs.push(new TextRun({ text: text.slice(last), ...base }));
  return runs.length ? runs : [new TextRun({ text: '', ...base })];
}

function mdBlock(text, shading) {
  const out = []; let inCode = false;
  for (const raw of text.replace(/\r/g, '').split('\n')) {
    const line = raw.replace(/\t/g, '    ');
    if (line.trim().startsWith('```')) { inCode = !inCode; continue; }
    if (inCode || /^\s*\|.*\|\s*$/.test(line)) { out.push(new Paragraph({ spacing: { after: 0 }, shading, children: [new TextRun({ text: line || ' ', font: MONO, size: 17 })] })); continue; }
    if (!line.trim()) { out.push(new Paragraph({ spacing: { after: 60 }, shading, children: [] })); continue; }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { out.push(new Paragraph({ spacing: { before: 120, after: 60 }, shading, children: inline(h[2], { bold: true }) })); continue; }
    const b = line.match(/^(\s*)[-*]\s+(.*)$/);
    if (b) { out.push(new Paragraph({ numbering: { reference: 'bullets', level: Math.min(2, Math.floor(b[1].length / 2)) }, shading, spacing: { after: 40 }, children: inline(b[2]) })); continue; }
    const n = line.match(/^(\s*)(\d+)\.\s+(.*)$/);
    if (n) { out.push(new Paragraph({ indent: { left: 360, hanging: 300 }, shading, spacing: { after: 40 }, children: [new TextRun({ text: n[2] + '. ' }), ...inline(n[3])] })); continue; }
    out.push(new Paragraph({ spacing: { after: 80 }, shading, children: inline(line) }));
  }
  return out;
}

function image(img, caption) {
  const s = Math.min(1, MAXW / img.w, MAXH / img.h);
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 80, after: 40 },
      children: [new ImageRun({ type: img.type === 'jpg' ? 'jpg' : 'png', data: fs.readFileSync(img.path), transformation: { width: Math.round(img.w * s), height: Math.round(img.h * s) } })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [new TextRun({ text: caption, italics: true, size: 17, color: '666666' })] }),
  ];
}

const speaker = (name, time, color) => new Paragraph({ spacing: { before: 240, after: 60 }, keepNext: true,
  border: { bottom: { style: BorderStyle.SINGLE, size: 4, color, space: 2 } },
  children: [new TextRun({ text: name, bold: true, color, size: 22 }), new TextRun({ text: '   ' + time, color: '888888', size: 18 })] });

const children = [
  new Paragraph({ heading: HeadingLevel.TITLE, children: [new TextRun(TITLE)] }),
  new Paragraph({ spacing: { after: 60 }, children: [new TextRun({ text: `Periodo: ${meta.first} – ${meta.last} (ora di Roma)`, size: 22 })] }),
  new Paragraph({ spacing: { after: 240 }, children: [new TextRun({ text: `Esportato il ${meta.exported}`, size: 22 })] }),
  new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun('Nota sulla completezza')] }),
];
for (const t of [
  'Costruito dal file di trascrizione della sessione: messaggi del maintainer e risposte di Claude **alla lettera**, immagini nel punto in cui sono state caricate. Le operazioni tecniche sono una riga per gruppo, senza output; il ragionamento interno di Claude non è incluso.',
  'Se il contesto è stato compattato, la parte precedente è nel file solo come **riassunto automatico** (riportato come tale): la copia letterale di quella parte è nell\'esportazione precedente alla compattazione.',
  '**Riservatezza**: può contenere indirizzi, nomi di host e di enti dei perimetri scansionati. Non va pubblicato né aggiunto al repository.',
]) children.push(new Paragraph({ numbering: { reference: 'bullets', level: 0 }, spacing: { after: 60 }, children: inline(t) }));
children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun('Indice')] }));
children.push(new TableOfContents('Indice', { hyperlink: true, headingStyleRange: '1-2' }));
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun('Trascrizione')] }));

let lastHour = '', imgN = 0;
for (const e of entries) {
  if (e.kind === 'summary') {
    children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(`Riassunto automatico alla compattazione del contesto (${e.time})`)] }));
    children.push(...mdBlock(e.text.replace(/^This session is being continued[^\n]*\n+/, '').replace(/\n\nIf you need specific details from before compaction[\s\S]*$/, ''),
      { type: ShadingType.CLEAR, fill: 'F4F4F4', color: 'auto' }));
    continue;
  }
  const hour = e.time.slice(0, 13);
  if (hour !== lastHour) { lastHour = hour; children.push(new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(`${e.time.slice(0, 10)} — ore ${e.time.slice(11, 13)}`)] })); }
  if (e.kind === 'user') {
    children.push(speaker('Maintainer', e.time, '1F4E79'));
    children.push(...mdBlock(e.text || '(solo immagini)', { type: ShadingType.CLEAR, fill: 'EEF3F8', color: 'auto' }));
    for (const im of e.images || []) { imgN++; children.push(...image(im, `Immagine ${imgN} — caricata il ${e.time}`)); }
  } else if (e.kind === 'assistant') {
    children.push(speaker('Claude', e.time, 'B45309'));
    children.push(...mdBlock(e.text));
  } else if (e.kind === 'tools') {
    const items = e.items.slice(0, 6).map(s => (s.length > 110 ? s.slice(0, 107) + '…' : s));
    children.push(new Paragraph({ spacing: { before: 40, after: 40 }, indent: { left: 360 },
      children: [new TextRun({ text: `Operazioni (${e.items.length}): ` + items.join(' · ') + (e.items.length > 6 ? ` … e altre ${e.items.length - 6}` : ''), italics: true, size: 16, color: '777777' })] }));
  }
}

const doc = new Document({
  title: TITLE,
  styles: {
    default: { document: { run: { font: FONT, size: 20 } } },
    paragraphStyles: [
      { id: 'Title', name: 'Title', basedOn: 'Normal', run: { size: 40, bold: true, color: '1F4E79' }, paragraph: { spacing: { after: 200 } } },
      { id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 30, bold: true, color: '1F4E79' }, paragraph: { spacing: { before: 300, after: 120 }, outlineLevel: 0 } },
      { id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true, run: { size: 24, bold: true, color: '2E75B6' }, paragraph: { spacing: { before: 240, after: 80 }, outlineLevel: 1 } },
    ],
  },
  numbering: { config: [{ reference: 'bullets', levels: [0, 1, 2].map(l => ({ level: l, format: LevelFormat.BULLET, text: ['•', '◦', '▪'][l], alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 360 + l * 360, hanging: 260 } } } })) }] },
  features: { updateFields: true },
  sections: [{
    properties: { page: { margin: { top: 1134, bottom: 1134, left: 1134, right: 1134 } } },
    headers: { default: new Header({ children: [new Paragraph({ alignment: AlignmentType.RIGHT, children: [new TextRun({ text: `${TITLE} · RISERVATO`, size: 16, color: '888888' })] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [new TextRun({ children: ['Pagina ', PageNumber.CURRENT, ' di ', PageNumber.TOTAL_PAGES], size: 16, color: '888888' })] })] }) },
    children,
  }],
});
Packer.toBuffer(doc).then(b => { fs.writeFileSync(OUT, b); console.log(`ok ${OUT} (${Math.round(b.length / 1024)} KB, ${imgN} immagini)`); });
