/* ===== P6 (PWA) + P7 (PDF report). Loaded after script.js. ===== */

/* ---------- P6: register the service worker (needs http/https, not file://) ---------- */
if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
  addEventListener("load", () => navigator.serviceWorker.register("sw.js").catch(() => {}));
}

/* ---------- P7: PDF report (hand-built, no library, works offline) ---------- */
function pdfSafe(s) {                       // PDF text strings: ASCII only, escape ( ) \
  return String(s).replace(/[‘’]/g, "'").replace(/[“”]/g, '"')
    .replace(/[–—]/g, "-").replace(/…/g, "...").replace(/[^\x20-\x7E]/g, "?")
    .replace(/([()\\])/g, "\\$1");
}

function wrapText(text, max) {
  const out = []; let line = "";
  String(text).split(/\s+/).forEach(w => {
    if ((line + " " + w).trim().length > max) { out.push(line); line = w; }
    else line = (line + " " + w).trim();
  });
  if (line) out.push(line);
  return out;
}

function buildPdf(rows) {                   // rows: [{t, size, bold, gap}]
  const pages = []; let ops = [], y = 800;
  const flush = () => { pages.push(ops.join("\n")); ops = []; y = 800; };
  rows.forEach(r => {
    y -= r.gap ?? r.size * 1.5;
    if (y < 50) { flush(); y = 800 - (r.gap ?? r.size * 1.5); }
    ops.push(`BT /${r.bold ? "F2" : "F1"} ${r.size} Tf 50 ${y.toFixed(1)} Td (${pdfSafe(r.t)}) Tj ET`);
  });
  flush();

  const objs = [];                          // object n is objs[n-1]
  const add = body => objs.push(body) ;
  add("<< /Type /Catalog /Pages 2 0 R >>");
  add(`<< /Type /Pages /Kids [${pages.map((_, i) => (5 + i * 2) + " 0 R").join(" ")}] /Count ${pages.length} >>`);
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>");
  pages.forEach((content, i) => {
    add(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${6 + i * 2} 0 R >>`);
    add(`<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
  });

  let pdf = "%PDF-1.4\n"; const offs = [];
  objs.forEach((b, i) => { offs.push(pdf.length); pdf += `${i + 1} 0 obj\n${b}\nendobj\n`; });
  const xref = pdf.length;
  pdf += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n` +
    offs.map(o => String(o).padStart(10, "0") + " 00000 n \n").join("") +
    `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return new Blob([pdf], { type: "application/pdf" });
}

document.getElementById("pdfBtn").addEventListener("click", () => {
  const $ = id => document.getElementById(id);
  const note = $("pdfNote");
  if (!input.value) { note.textContent = "Type a password first."; return; }
  note.textContent = "";

  const rows = [];
  const add = (t, size = 11, bold = false, gap) => rows.push({ t, size, bold, gap });
  const section = t => { add(t, 13, true, 26); };

  add("Password Strength Report", 20, true, 10);
  add("Created " + new Date().toLocaleString() + "  |  The password itself is not included.", 9, false, 18);

  section("Result");
  add("Strength: " + $("label").textContent + "   (" + $("score").textContent + " / 6)");
  add("Preset: " + $("preset").selectedOptions[0].textContent.replace("Preset: ", ""));
  add("Time to crack: " + $("crack").textContent);
  add("Entropy: " + $("entropy").textContent);
  add("Length: " + input.value.length + " characters");

  section("Requirements");
  document.querySelectorAll("#checklist li").forEach(li => {
    const text = [...li.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join("").trim();
    add((li.classList.contains("ok") ? "[x] " : "[ ] ") + text + (li.classList.contains("req") ? " (required)" : ""));
  });

  section("Attack times");
  document.querySelectorAll("#attacks .attack").forEach(a => add(a.children[0].textContent + ": " + a.children[1].textContent));

  section("Tips");
  document.querySelectorAll("#feedback li:not(.leaving)").forEach(li =>
    wrapText(li.textContent, 88).forEach((l, i) => add((i ? "    " : "- ") + l)));

  add("Experiment only: this tool does not guarantee the security of your passwords.", 9, false, 30);

  const a = document.createElement("a");
  a.href = URL.createObjectURL(buildPdf(rows));
  a.download = "password_report.pdf";
  a.click();
  URL.revokeObjectURL(a.href);
  note.textContent = "Report downloaded (no password inside).";
});
