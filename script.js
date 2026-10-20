/* ===================================================
   Password Strength Checker - logic + animations
   Scoring matches password_checker.py (out of 6).
   =================================================== */

/* ---------- Scoring logic ---------- */
const COMMON = new Set(window.COMMON_PASSWORDS || ["password", "123456", "12345678", "qwerty", "abc123"]);
const leaked = new Map();   // passwords found in breaches (kept in memory only)

/* ---------- Leetspeak (p@ssw0rd -> password) ---------- */
const LEET = { "@": "a", "4": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t", "!": "i" };

function leetVariants(pw) {
  const lower = pw.toLowerCase();
  const out = new Set();
  for (const source of [lower, lower.replace(/[!?.]+$/, "")]) {
    for (const one of ["l", "i", "1"]) {
      out.add([...source].map(c => (c === "1" ? one : LEET[c] || c)).join(""));
    }
  }
  return [...out];
}

function isCommon(pw) {
    return leaked.has(pw) || COMMON.has(pw.toLowerCase()) || leetVariants(pw).some(v => COMMON.has(v));
}

const SEQUENCES = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"];

function hasSequence(pw, n = 4) {
  const p = pw.toLowerCase();
  for (const seq of SEQUENCES) {
    for (const s of [seq, [...seq].reverse().join("")]) {
      for (let i = 0; i <= s.length - n; i++) {
        if (p.includes(s.slice(i, i + n))) return true;
      }
    }
  }
  return false;
}

const hasRepeat = (pw, n = 3) => new RegExp("(.)\\1{" + (n - 1) + ",}").test(pw);

function labelFor(score) {
  if (score <= 1) return "Low";
  if (score <= 3) return "Medium";
  if (score === 4) return "Moderate";
  return "Strong";
}

function checkPassword(pw) {
  if (!pw) return { score: 0, label: "Low", feedback: ["Enter a password."] };
  if (leaked.has(pw)) {
    return { score: 0, label: "Low", feedback: ["Found in " + leaked.get(pw).toLocaleString() + " known data breaches. Never use this password."] };
  }

  if (COMMON.has(pw.toLowerCase())) {
    return { score: 0, label: "Low", feedback: ["This is a very common password. Pick something unique."] };
  }
  if (isCommon(pw)) {
    return { score: 0, label: "Low", feedback: ["This is a common password with look-alike swaps (like p@ssw0rd). Pick something unique."] };
  }
  const feedback = [];
  let score = 0;

  if (pw.length >= 8) score++; else feedback.push("Use at least 8 characters.");
  if (pw.length >= 12) score++; else feedback.push("Use 12 or more characters.");
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++; else feedback.push("Mix uppercase and lowercase letters.");
  if (/\d/.test(pw)) score++; else feedback.push("Add a number.");
  if (/[^A-Za-z0-9]/.test(pw)) score++; else feedback.push("Add a symbol (e.g. ! @ # $).");

  if (hasSequence(pw)) feedback.push("Avoid sequences like abcd, 1234 or qwer.");
  else if (hasRepeat(pw)) feedback.push("Avoid repeating the same character 3+ times.");
  else score++;

  return { score, label: labelFor(score), feedback };
}

/* ---------- B2: smarter crack-time (pattern-aware) ---------- */
const WORDS = new Set((window.WORDLIST || []).map(w => w.toLowerCase()));
const SEQ_ALL = SEQUENCES.flatMap(s => [s, [...s].reverse().join("")]);
const DICT_BITS = 15;                    // an attacker's dictionary has about 30,000 words (2^15)

function estimateBits(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
  const charBits = Math.log2(pool || 1);

  const n = pw.length, low = pw.toLowerCase();
  const forms = [low, ...leetVariants(pw).filter(v => v.length === n)];
  const inDict = w => COMMON.has(w) || WORDS.has(w);

  const best = new Array(n + 1).fill(Infinity);
  best[0] = 0;
  for (let i = 1; i <= n; i++) {
    best[i] = best[i - 1] + charBits;                           // plain random character
    for (let j = Math.max(0, i - 30); j < i; j++) {
      const L = i - j, seg = pw.slice(j, i), segLow = low.slice(j, i);
      let cost = Infinity;
      if (L >= 4 && SEQ_ALL.some(s => s.includes(segLow))) cost = 7 + Math.log2(L);           // abcd, 1234, qwer
      if (L >= 3 && seg.split("").every(c => c === seg[0])) cost = Math.min(cost, charBits + Math.log2(L));  // aaaa
      if (L === 4 && /^(19|20)\d\d$/.test(seg)) cost = Math.min(cost, 7);                    // years
      if (L >= 4) {
        forms.forEach((f, k) => {
          const part = f.slice(j, i);
          if (inDict(part)) cost = Math.min(cost, DICT_BITS + (k ? 2 : 0) + (seg !== segLow ? 2 : 0));
        });
        if (avoidWords.some(w => forms.some(f => f.slice(j, i) === w))) cost = Math.min(cost, 10);
      }
      if (cost < Infinity) best[i] = Math.min(best[i], best[j] + cost);
    }
  }
  return best[n];
}

function crackTime(pw) {
  if (!pw) return "—";
  if (isCommon(pw)) return "less than a millisecond (common password)";

  // Size of the character set the password draws from.
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;

  // Average case: half of all combinations, at 10 billion guesses per second.
  const seconds = Math.pow(2, estimateBits(pw)) / 2 / 1e10;

  const YEAR = 31557600;
  if (seconds < 1e-3) return "less than a millisecond";
  if (seconds < 1) return Math.round(seconds * 1000) + " milliseconds";
  if (seconds / YEAR > 1e9) return "billions of years";

  const units = [["years", YEAR], ["days", 86400], ["hours", 3600], ["minutes", 60], ["seconds", 1]];
  for (const [name, size] of units) {
    if (seconds >= size) {
      const n = Math.round(seconds / size);
      return n.toLocaleString() + " " + (n === 1 ? name.slice(0, -1) : name);
    }
  }
}

/* ---------- Entropy ---------- */
function entropyInfo(pw) {
  if (!pw) return "—";
  if (isCommon(pw)) return "0 bits (very weak)";

  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;

  const bits = Math.round(estimateBits(pw));
  const label = bits < 28 ? "very weak" : bits < 36 ? "weak" : bits < 60 ? "fair" : bits < 80 ? "strong" : "very strong";
  return bits + " bits (" + label + ")";
}

/* ---------- Personal words to avoid ---------- */
const avoidInput = document.getElementById("avoid");
let avoidWords = [];

function withPersonal(r, pw) {
  if (!avoidWords.length) return r;
  const forms = [pw.toLowerCase(), ...leetVariants(pw)];
  if (!avoidWords.some(w => forms.some(f => f.includes(w)))) return r;
  const score = Math.max(0, r.score - 2);
  return { score, label: labelFor(score), feedback: [...r.feedback, "Contains a word from your avoid list. Skip names, pets and birth years."] };
}

/* ---------- Strength presets ---------- */
const PRESETS = {
  standard: { name: "Standard", minLen: 0,  need: [] },
  wifi:     { name: "Wi-Fi",    minLen: 12, need: [] },
  email:    { name: "Email",    minLen: 12, need: ["sym"] },
  bank:     { name: "Bank",     minLen: 14, need: ["case", "num", "sym", "pattern"] },
};
let preset = PRESETS.standard;
const NEED_TEXT = { case: "upper and lower case letters", num: "a number", sym: "a symbol", pattern: "no sequences or repeats" };

function ruleResults(pw) {
  return {
    len8: pw.length >= 8,
    len12: pw.length >= Math.max(12, preset.minLen),
    case: /[a-z]/.test(pw) && /[A-Z]/.test(pw),
    num: /\d/.test(pw),
    sym: /[^A-Za-z0-9]/.test(pw),
    pattern: pw.length > 0 && !hasSequence(pw) && !hasRepeat(pw),
  };
}

function requiredRules() {
  const req = new Set(preset.need);
  if (preset.minLen >= 8) req.add("len8");
  if (preset.minLen >= 12) req.add("len12");
  return req;
}

function withPreset(r, pw) {
  if (preset.minLen === 0 && !preset.need.length) return r;
  const unmet = [];
  if (pw.length < preset.minLen) unmet.push(preset.name + " needs at least " + preset.minLen + " characters.");
  const ok = ruleResults(pw);
  preset.need.forEach(k => { if (!ok[k]) unmet.push(preset.name + " requires " + NEED_TEXT[k] + "."); });
  if (!unmet.length) return r;
  const score = Math.min(r.score, 3);          // a missing requirement caps the result at Medium
  return { score, label: labelFor(score), feedback: [...unmet, ...r.feedback] };
}

const adjustResult = (r, pw) => withPreset(withPersonal(r, pw), pw);

/* ---------- Page elements ---------- */
const card = document.getElementById("card");
const input = document.getElementById("pw");
const toggle = document.getElementById("toggle");
const segs = document.querySelectorAll("#meter span");
const badge = document.getElementById("label");
const scoreEl = document.getElementById("score");
const tipsList = document.getElementById("feedback");
const meterEl = document.getElementById("meter");
const srStatus = document.getElementById("srStatus");

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// Give each meter segment an index so the fill can ripple left to right.
segs.forEach((s, i) => s.style.setProperty("--i", i));

/* ---------- Animated score number ---------- */
let shownScore = 0;
let scoreRaf = 0;

function animateScore(to) {
  cancelAnimationFrame(scoreRaf);
  if (reduceMotion) { shownScore = to; scoreEl.textContent = to; return; }

  const from = shownScore;
  if (from === to) { scoreEl.textContent = to; return; }

  const start = performance.now();
  const duration = 450;

  (function step(now) {
    const t = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - t, 3);
    shownScore = from + (to - from) * eased;
    scoreEl.textContent = Math.round(shownScore);
    if (t < 1) scoreRaf = requestAnimationFrame(step);
    else shownScore = to;
  })(start);
}

/* ---------- Tips list (only animates what changed) ---------- */
function updateTips(messages, isGreat) {
  const wanted = new Set(messages);

  // Remove tips that no longer apply.
  [...tipsList.children].forEach(li => {
    if (!wanted.has(li.dataset.text) && !li.classList.contains("leaving")) {
      li.classList.add("leaving");
      setTimeout(() => li.remove(), 300);
    }
  });

  // Add new ones, with a small stagger.
  const existing = new Set([...tipsList.children].map(li => li.dataset.text));
  let delay = 0;
  messages.forEach(text => {
    if (existing.has(text)) return;
    const li = document.createElement("li");
    li.textContent = text;
    li.dataset.text = text;
    li.style.animationDelay = delay + "ms";
    if (isGreat) li.classList.add("great");
    tipsList.appendChild(li);
    delay += 70;
  });
}

/* ---------- Live checklist ---------- */
const checklistItems = document.querySelectorAll("#checklist li");

function updateChecklist(pw) {
  const rules = ruleResults(pw);
  const req = requiredRules();
  checklistItems.forEach(li => {
    const k = li.dataset.rule;
    if (k === "len12") li.textContent = Math.max(12, preset.minLen) + "+ characters";
    li.classList.toggle("ok", rules[k]);
    li.classList.toggle("req", req.has(k));
    let st = li.querySelector(".sr-only");                      // state for screen readers
    if (!st) { st = document.createElement("span"); st.className = "sr-only"; li.appendChild(st); }
    st.textContent = rules[k] ? " - done" : " - not done";
  });
}


/* ---------- Main render ---------- */
let lastLevel = "none";

function render() {
  const value = input.value;

  // Empty box: reset everything.
  if (!value) {
    card.dataset.level = "none";
    segs.forEach(s => s.classList.remove("on"));
    badge.textContent = "Waiting";
    meterEl.setAttribute("aria-valuenow", 0);
    meterEl.setAttribute("aria-valuetext", "No password yet");
    srStatus.textContent = "";
    animateScore(0);
    setRing(0);
    updateChecklist("");
    document.getElementById("crack").textContent = "—";
    document.getElementById("entropy").textContent = "—";
    updateTips([], false);
    updateAttacks("");
    updateViewer();
    lastLevel = "none";
    return;
  }

  const r = adjustResult(checkPassword(value), value);
  const level = r.label.toLowerCase();
  updateChecklist(value);
  document.getElementById("crack").textContent = crackTime(value);
  document.getElementById("entropy").textContent = entropyInfo(value);
  updateAttacks(value);

  card.dataset.level = level;
  segs.forEach((s, i) => s.classList.toggle("on", i < r.score));
  animateScore(r.score);
  setRing(r.score);
  meterEl.setAttribute("aria-valuenow", r.score);
  meterEl.setAttribute("aria-valuetext", r.score + " out of 6, " + r.label);
  srStatus.textContent = "Strength: " + r.label + ", " + r.score + " out of 6.";

  // Pop the badge only when the level really changes.
  if (level !== lastLevel) {
    badge.textContent = r.label;
    if (!reduceMotion) {
      badge.classList.remove("swap");
      void badge.offsetWidth;            // restart the animation
      badge.classList.add("swap");
    }
    if (level === "strong" && !reduceMotion) {
      card.classList.remove("pulse");
      void card.offsetWidth;
      card.classList.add("pulse");
    }
    lastLevel = level;
  }

  if (r.feedback.length === 0) updateTips(["Great job! This password looks strong."], true);
  else updateTips(r.feedback, false);
  updateViewer();
}

input.addEventListener("input", render);
avoidInput.addEventListener("input", () => {
  avoidWords = avoidInput.value.toLowerCase().split(",").map(w => w.trim()).filter(w => w.length >= 3);
  render();
  const bulk = document.getElementById("bulkFile");        // re-check the uploaded list with the new words
  if (bulk.files.length) bulk.dispatchEvent(new Event("change"));
});

document.getElementById("preset").addEventListener("change", e => {
  preset = PRESETS[e.target.value] || PRESETS.standard;
  render();
  const bulk = document.getElementById("bulkFile");
  if (bulk.files.length) bulk.dispatchEvent(new Event("change"));
});

/* ---------- Show / hide password ---------- */
toggle.addEventListener("click", () => {
  const hidden = input.type === "password";
  input.type = hidden ? "text" : "password";
  toggle.textContent = hidden ? "Hide" : "Show";
  toggle.setAttribute("aria-label", hidden ? "Hide password" : "Show password");
  updateViewer();
  input.focus();
});

/* ---------- Corner popup: "experiment only" notice ---------- */
const toast = document.getElementById("toast");
const toastClose = document.getElementById("toastClose");
const TOAST_SECONDS = 12;
let toastTimer;

toast.style.setProperty("--toast-time", TOAST_SECONDS + "s");

function showToast() {
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(hideToast, TOAST_SECONDS * 1000);
}

function hideToast() {
  clearTimeout(toastTimer);
  toast.classList.remove("show");
}

toastClose.addEventListener("click", hideToast);
setTimeout(showToast, 700);   // appears shortly after the page loads

/* ---------- Rainbow cursor trail ---------- */
(function rainbowTrail() {
  if (reduceMotion) return;                       // respect "reduce motion"

  const canvas = document.getElementById("trail");
  const ctx = canvas.getContext("2d");

  const LIFE = 650;          // how long (ms) each part of the trail stays visible
  const MAX_WIDTH = 12;      // thickest part of the trail, in pixels
  const HUE_STEP = 5;        // how fast the colours cycle along the trail

  let points = [];           // {x, y, t, hue}
  let hue = 0;
  let running = false;

  function resize() {
    const dpr = window.devicePixelRatio || 1;
    canvas.width = innerWidth * dpr;
    canvas.height = innerHeight * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resize();
  addEventListener("resize", resize);

  // Works for mouse, pen and touch.
  addEventListener("pointermove", e => {
    hue = (hue + HUE_STEP) % 360;
    points.push({ x: e.clientX, y: e.clientY, t: performance.now(), hue });
    if (!running) { running = true; requestAnimationFrame(draw); }
  }, { passive: true });

  function draw(now) {
    ctx.clearRect(0, 0, innerWidth, innerHeight);

    // Drop points that have faded out.
    points = points.filter(p => now - p.t < LIFE);

    ctx.lineCap = "round";
    ctx.lineJoin = "round";

    for (let i = 1; i < points.length; i++) {
      const a = points[i - 1], b = points[i];
      const life = 1 - (now - b.t) / LIFE;        // 1 = fresh, 0 = gone
      if (life <= 0) continue;

      ctx.strokeStyle = `hsla(${b.hue}, 100%, 60%, ${life})`;
      ctx.lineWidth = MAX_WIDTH * life;
      ctx.shadowColor = `hsla(${b.hue}, 100%, 60%, ${life * 0.8})`;
      ctx.shadowBlur = 10;

      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }

    // Stop the loop when there is nothing left to draw (saves battery).
    if (points.length > 0) requestAnimationFrame(draw);
    else { running = false; ctx.clearRect(0, 0, innerWidth, innerHeight); }
  }
})();

/* ---------- Footer year ---------- */
document.getElementById("year").textContent = new Date().getFullYear();

function randInt(n) {                       // secure random number from 0 to n-1
  const a = new Uint32Array(1);
  const limit = Math.floor(2 ** 32 / n) * n;
  do { crypto.getRandomValues(a); } while (a[0] >= limit);
  return a[0] % n;
}

function generatePassword(len = 16) {
  const sets = ["abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!@#$%^&*()-_=+?"];
  const all = sets.join("");
  let pw;
  do {
    const chars = sets.map(s => s[randInt(s.length)]);          // one of each kind
    while (chars.length < len) chars.push(all[randInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) {                 // shuffle
      const j = randInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    pw = chars.join("");
  } while (checkPassword(pw).score < 6);                         // keep trying until it scores 6/6
  return pw;
}

document.getElementById("generate").addEventListener("click", () => {
  input.value = generatePassword();
  input.type = "text";                       // show it so the user can see it
  toggle.textContent = "Hide";
  render();
});

/* ---------- Passphrase generator ---------- */
const PASSPHRASE_WORDS = 4;                 // change to 5 or 6 for a stronger passphrase

function generatePassphrase() {
  const list = window.WORDLIST || [];
  if (list.length < 100) return null;       // word list file missing
  const seps = ["-", ".", "_", "+"];
  let pw;
  do {
    const sep = seps[randInt(seps.length)];
    const words = Array.from({ length: PASSPHRASE_WORDS }, () => {
      const w = list[randInt(list.length)];
      return w[0].toUpperCase() + w.slice(1);
    });
    pw = words.join(sep) + sep + (randInt(90) + 10);       // e.g. River-Lamp-Cactus-Pilot-47
  } while (checkPassword(pw).score < 6);
  return pw;
}

document.getElementById("passphrase").addEventListener("click", () => {
  const pw = generatePassphrase();
  if (!pw) { leakResult.textContent = "Word list not found. Check that wordlist.js is next to index.html."; return; }
  input.value = pw;
  input.type = "text";
  toggle.textContent = "Hide";
  render();
});

document.getElementById("copy").addEventListener("click", async e => {
  if (!input.value) return;
  await navigator.clipboard.writeText(input.value);
  e.target.textContent = "Copied!";
  setTimeout(() => (e.target.textContent = "Copy"), 1500);
});

async function sha1Hex(text) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function breachCount(pw) {
  const hash = await sha1Hex(pw);
  const prefix = hash.slice(0, 5), suffix = hash.slice(5);
  const res = await fetch("https://api.pwnedpasswords.com/range/" + prefix);
  if (!res.ok) throw new Error("Lookup failed");
  for (const line of (await res.text()).split("\n")) {
    const [h, count] = line.trim().split(":");
    if (h === suffix) return Number(count);
  }
  return 0;
}

const leakBtn = document.getElementById("leakBtn");
const leakResult = document.getElementById("leakResult");

leakBtn.addEventListener("click", async () => {
  if (!input.value) return;
  leakResult.className = "leak-result";
  leakResult.textContent = "Checking…";
  try {
    const n = await breachCount(input.value);
    if (n > 0) { leaked.set(input.value, n); render(); }
    if (n > 0) { leakResult.className = "leak-result bad"; leakResult.textContent = `Found in ${n.toLocaleString()} data breaches. Don't use it.`; }
    else { leakResult.className = "leak-result good"; leakResult.textContent = "Not found in known breaches."; }
  } catch {
    leakResult.textContent = "Couldn't reach the service. Check your internet connection.";
  }
});

let bulkRows = [];

document.getElementById("bulkFile").addEventListener("change", async e => {
  const file = e.target.files[0];
  if (!file) return;

  const lines = (await file.text()).split(/\r?\n/).map(l => l.trim()).filter(Boolean);

  const scored = await scoreList(lines);
  bulkRows = scored.rows.map(r => {                 // apply the "words to avoid" box too
    const a = adjustResult({ score: r.score, label: r.label, feedback: [] }, r.pw);
    return { ...r, score: a.score, label: a.label };
  });
  document.getElementById("bulkSource").textContent = "Checked by: " + scored.source;

  drawBulkChart(bulkRows);

  const table = document.getElementById("bulkTable");
  const body = table.querySelector("tbody");
  body.replaceChildren();
  bulkRows.forEach(r => {
    const tr = document.createElement("tr");
    [r.pw, r.score + "/6", r.label].forEach(text => {
      const td = document.createElement("td");
      td.textContent = text;                 // textContent, never innerHTML, for safety
      tr.appendChild(td);
    });
    body.appendChild(tr);
  });
  table.hidden = false;
  document.getElementById("csvBtn").hidden = false;
  document.getElementById("chartPngBtn").hidden = false;
});

document.getElementById("csvBtn").addEventListener("click", () => {
  const safe = s => `"${(/^[=+\-@]/.test(s) ? "'" : "") + s.replace(/"/g, '""')}"`;   // also blocks spreadsheet formula tricks
  const csv = ["Password,Score,Strength", ...bulkRows.map(r => [safe(r.pw), r.score, r.label].join(","))].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = "password_report.csv";
  a.click();
  URL.revokeObjectURL(a.href);
});

/* ---------- Download the bulk chart as PNG ---------- */
document.getElementById("chartPngBtn").addEventListener("click", () => {
  const css = getComputedStyle(document.documentElement);
  const v = name => css.getPropertyValue(name).trim();
  const levels = [["Low", "--low"], ["Medium", "--medium"], ["Moderate", "--moderate"], ["Strong", "--strong"]];
  const counts = levels.map(([n]) => bulkRows.filter(r => r.label === n).length);
  const total = bulkRows.length || 1;

  const W = 640, H = 420, left = 56, right = 24, top = 86, bottom = 64;
  const canvas = document.createElement("canvas");
  canvas.width = W * 2; canvas.height = H * 2;                 // 2x for a sharp image
  const g = canvas.getContext("2d");
  g.scale(2, 2);
  const font = "Inter, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif";

  g.fillStyle = v("--bg"); g.fillRect(0, 0, W, H);

  g.fillStyle = v("--text"); g.font = "700 22px " + font; g.textAlign = "left";
  g.fillText("Password strength", left, 38);
  g.fillStyle = v("--muted"); g.font = "14px " + font;
  g.fillText(bulkRows.length + " passwords checked", left, 60);

  const max = Math.max(...counts, 1);
  const step = Math.ceil(max / 4);
  const topValue = step * Math.ceil(max / step);
  const plotH = H - top - bottom, plotW = W - left - right;
  const yOf = n => top + plotH - (n / topValue) * plotH;

  g.font = "12px " + font; g.textAlign = "right"; g.lineWidth = 1;
  for (let n = 0; n <= topValue; n += step) {
    g.strokeStyle = v("--line"); g.beginPath(); g.moveTo(left, yOf(n)); g.lineTo(W - right, yOf(n)); g.stroke();
    g.fillStyle = v("--muted"); g.fillText(String(n), left - 8, yOf(n) + 4);
  }

  const slot = plotW / levels.length, barW = Math.min(70, slot * 0.55);
  levels.forEach(([name, cssVar], i) => {
    const x = left + slot * i + (slot - barW) / 2;
    const y = yOf(counts[i]);
    g.fillStyle = v(cssVar);
    g.beginPath(); g.roundRect(x, y, barW, top + plotH - y, [8, 8, 0, 0]); g.fill();

    g.textAlign = "center";
    g.fillStyle = v("--text"); g.font = "700 15px " + font;
    g.fillText(String(counts[i]), x + barW / 2, y - 8);
    g.fillStyle = v("--muted"); g.font = "13px " + font;
    g.fillText(name, x + barW / 2, top + plotH + 22);
    g.fillText(Math.round(counts[i] / total * 100) + "%", x + barW / 2, top + plotH + 40);
  });

  canvas.toBlob(blob => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "strength_chart.png";
    a.click();
    URL.revokeObjectURL(a.href);
  });
});

/* ---------- Keyboard shortcuts ---------- */
addEventListener("keydown", e => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
  if (e.key === "Escape") { hideToast(); return; }
  if (e.key === "/" && !typing) { e.preventDefault(); input.focus(); return; }
  if (e.altKey && !e.ctrlKey && !e.metaKey) {
    const target = { KeyG: "generate", KeyP: "passphrase", KeyT: "themeBtn" }[e.code];
    if (target) { e.preventDefault(); document.getElementById(target).click(); }
  }
});

/* ---------- Theme selection ---------- */

const themeBtn = document.getElementById("themeBtn");
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  themeBtn.textContent = theme === "dark" ? "☀️" : "🌙";
  try { localStorage.setItem("theme", theme); } catch { }
}
let savedTheme = null;
try { savedTheme = localStorage.getItem("theme"); } catch { }
applyTheme(savedTheme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
themeBtn.addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
});

function drawBulkChart(rows) {
  const box = document.getElementById("bulkChart");
  if (!rows.length) { box.hidden = true; return; }

  const levels = [["Low", "--low"], ["Medium", "--medium"], ["Moderate", "--moderate"], ["Strong", "--strong"]];
  const counts = levels.map(([name]) => rows.filter(r => r.label === name).length);
  const max = Math.max(...counts, 1);

  box.replaceChildren();
  levels.forEach(([name, cssVar], i) => {
    const pct = Math.round(counts[i] / rows.length * 100);

    const col = document.createElement("div"); col.className = "bc-col";
    const area = document.createElement("div"); area.className = "bc-area";
    const num = document.createElement("span"); num.className = "bc-count"; num.textContent = counts[i];
    const bar = document.createElement("div"); bar.className = "bc-bar";
    bar.style.setProperty("--c", `var(${cssVar})`);
    const label = document.createElement("div"); label.className = "bc-label"; label.textContent = `${name} · ${pct}%`;

    area.append(num, bar);
    col.append(area, label);
    box.appendChild(col);

    requestAnimationFrame(() => requestAnimationFrame(() => {
      bar.style.height = counts[i] ? Math.max(counts[i] / max * 110, 6) + "px" : "0px";
    }));
  });
  box.hidden = false;
}


/* ---------- Flask Backend ---------- */
async function scoreList(lines) {
  try {
    const res = await fetch("/api/bulk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ passwords: lines }),
    });
    if (!res.ok) throw new Error("server error");
    const data = await res.json();
    return { source: "Python server (Flask)", rows: data.results.map(r => ({ pw: r.password, score: r.score, label: r.label })) };
  } catch {
    return { source: "your browser (server not running)", rows: lines.map(pw => ({ pw, ...checkPassword(pw) })) };
  }
}

/* ---------- Attack simulator ---------- */
const attacksEl = document.getElementById("attacks");

function fmtTime(seconds) {
  const YEAR = 31557600;
  if (seconds < 1e-3) return "instantly";
  if (seconds < 1) return Math.round(seconds * 1000) + " ms";
  if (seconds / YEAR > 1e9) return "billions of years";
  for (const [name, size] of [["year", YEAR], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]]) {
    if (seconds >= size) {
      const n = Math.round(seconds / size);
      return n.toLocaleString() + " " + name + (n === 1 ? "" : "s");
    }
  }
}

function updateAttacks(pw) {
  attacksEl.replaceChildren();
  if (!pw) return;

  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += 33;

  const common = isCommon(pw);
  const space = Math.pow(2, estimateBits(pw)) / 2;           // average guesses needed
  const speed = s => (s < 86400 ? "fast" : s < 31557600 ? "mid" : "safe");

  const rows = [
    ["Dictionary list", common ? "instantly" : "not in word list", common ? "fast" : "safe"],
    ["Online guessing (100/s)", ...(s => [fmtTime(s), speed(s)])(common ? 0 : space / 100)],
    ["Offline GPU (10 billion/s)", ...(s => [fmtTime(s), speed(s)])(common ? 0 : space / 1e10)],
  ];
  rows.forEach(([name, text, cls]) => {
    const row = document.createElement("div");
    row.className = "attack " + cls;
    const a = document.createElement("span"); a.textContent = name;
    const b = document.createElement("b"); b.textContent = text;
    row.append(a, b);
    attacksEl.appendChild(row);
  });
}

/* ---------- Score ring ---------- */
const ringFg = document.getElementById("ringFg");
function setRing(score) {
  ringFg.style.strokeDashoffset = 113.1 * (1 - score / 6);
}

/* ---------- Clipboard auto-clear ---------- */
const CLIP_SECONDS = 30;
const copyNote = document.getElementById("copyNote");
let clipTimer;

document.getElementById("copy").addEventListener("click", () => {
  if (!input.value) return;
  clearInterval(clipTimer);
  let left = CLIP_SECONDS;
  copyNote.textContent = "Clipboard clears in " + left + " s";
  clipTimer = setInterval(async () => {
    left--;
    if (left > 0) { copyNote.textContent = "Clipboard clears in " + left + " s"; return; }
    clearInterval(clipTimer);
    try { await navigator.clipboard.writeText(""); copyNote.textContent = "Clipboard cleared."; }
    catch { copyNote.textContent = "Couldn't clear the clipboard (tab was in the background)."; }
  }, 1000);
});

/* ---------- Weak-part highlighter ---------- */
const viewer = document.getElementById("viewer");
const viewerText = document.getElementById("viewerText");
const viewerNote = document.getElementById("viewerNote");

function weakMask(pw) {
  const mask = new Array(pw.length).fill(false);
  const mark = (i, n) => { for (let k = i; k < i + n && k < mask.length; k++) mask[k] = true; };
  const markAll = (text, part) => {
    let at = text.indexOf(part);
    while (at !== -1) { mark(at, part.length); at = text.indexOf(part, at + 1); }
  };

  if (isCommon(pw)) { mark(0, pw.length); return mask; }

  const low = pw.toLowerCase();
  for (const seq of SEQUENCES) {
    for (const s of [seq, [...seq].reverse().join("")]) {
      for (let i = 0; i <= s.length - 4; i++) markAll(low, s.slice(i, i + 4));
    }
  }
  const rep = /(.)\1{2,}/g;
  let m;
  while ((m = rep.exec(pw))) mark(m.index, m[0].length);

  const forms = [low, ...leetVariants(pw)];
  avoidWords.forEach(w => forms.forEach(f => markAll(f, w)));
  return mask;
}

function updateViewer() {
  const pw = input.value;
  const mask = pw ? weakMask(pw) : [];
  if (!mask.some(Boolean)) { viewer.hidden = true; return; }

  const show = input.type === "text";
  viewerText.replaceChildren();
  pw.split("").forEach((ch, i) => {
    const s = document.createElement("span");
    s.textContent = show ? ch : "•";
    if (mask[i]) s.className = "bad";
    viewerText.appendChild(s);
  });
  viewerNote.textContent = "Red parts are easy to guess: sequences, repeats, common or personal words.";
  viewer.hidden = false;
}
