"use strict";

/* ============================================================
   Ship Guard — browser UI.
   The rule engine lives in scanner.js (shared with the CLI) and
   is exposed here as the global `ShipGuard`. This file is only
   DOM rendering + wiring + demo samples.
   ============================================================ */

const {
  SEV, SEV_LABEL,
  normalizeLines, runValidate, runSecure, decideVerdict, buildShipReport,
} = window.ShipGuard;

/* ---------------- Rendering ---------------- */

// Build a DOM node with textContent — no innerHTML, so nothing user-derived
// is ever parsed as HTML (the exact fix Ship Guard's Secure phase recommends).
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function renderFindings(container, findings, emptyMsg) {
  container.replaceChildren();
  if (findings.length === 0) {
    const li = el("li", "finding");
    const body = el("div", "finding-body");
    const title = el("div", "finding-title", "✓ " + emptyMsg);
    title.style.color = "var(--ok)";
    body.appendChild(title);
    li.appendChild(body);
    container.appendChild(li);
    return;
  }
  const order = { crit: 0, high: 1, med: 2, low: 3, ok: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  for (const f of findings) {
    const li = el("li", "finding");
    const badge = el("span", `sev-badge sev-${f.severity}`, SEV_LABEL[f.severity]);
    const body = el("div", "finding-body");
    body.appendChild(el("div", "finding-title", f.title));
    const metaBits = [];
    if (f.line) metaBits.push(`line ${f.line}`);
    if (f.item) metaBits.push(f.item);
    if (metaBits.length) body.appendChild(el("div", "finding-meta", metaBits.join(" · ")));
    if (f.snippet) body.appendChild(el("div", "finding-snippet", f.snippet));
    if (f.advice) body.appendChild(el("div", "finding-advice", f.advice));
    li.appendChild(badge);
    li.appendChild(body);
    container.appendChild(li);
  }
}

/* ---------------- Wiring ---------------- */

const codeInput = document.getElementById("code-input");
const lineCount = document.getElementById("line-count");
const emptyState = document.getElementById("empty-state");
const report = document.getElementById("report");

function updateLineCount() {
  const n = codeInput.value === "" ? 0 : codeInput.value.split("\n").length;
  lineCount.textContent = `${n} line${n === 1 ? "" : "s"}`;
}

function runPipeline() {
  const src = codeInput.value;
  if (src.trim() === "") {
    alert("Paste some code or load a sample first.");
    return;
  }
  const lines = normalizeLines(src);
  const validate = runValidate(src, lines);
  const secure = runSecure(src, lines);
  const verdict = decideVerdict(validate, secure);

  const verdictEl = document.getElementById("verdict");
  verdictEl.className = `verdict ${verdict.level}`;
  verdictEl.replaceChildren();
  const textWrap = el("div");
  textWrap.appendChild(el("div", null, verdict.label));
  textWrap.appendChild(el("div", "verdict-sub", verdict.sub));
  verdictEl.appendChild(el("span", "verdict-icon", verdict.icon));
  verdictEl.appendChild(textWrap);

  const secureReal = secure.filter((f) => f.severity !== SEV.OK);
  document.getElementById("validate-score").textContent =
    `${validate.filter((f) => f.severity !== SEV.OK).length} issue(s)`;
  document.getElementById("secure-score").textContent = `${secureReal.length} finding(s)`;

  renderFindings(document.getElementById("validate-findings"), validate, "No test or code-smell issues detected.");
  renderFindings(document.getElementById("secure-findings"), secure, "No security issues flagged by heuristic checks.");

  document.getElementById("ship-report-text").textContent = buildShipReport(verdict, validate, secure);

  emptyState.classList.add("hidden");
  report.classList.remove("hidden");

  document.querySelectorAll(".phase-chip").forEach((c) => c.classList.add("active"));
}

/* ---------------- Samples & use-case gallery ---------------- */

const SAMPLES = window.SHIP_GUARD_SAMPLES || {};
const USE_CASES = window.SHIP_GUARD_USE_CASES || [];

// Populate the "50 use cases" dropdown, grouped by category via <optgroup>.
const usecaseSelect = document.getElementById("usecase-select");
const useCaseById = {};
(function buildGallery() {
  const groups = {};
  for (const uc of USE_CASES) {
    useCaseById[uc.id] = uc;
    (groups[uc.category] = groups[uc.category] || []).push(uc);
  }
  for (const [category, list] of Object.entries(groups)) {
    const group = document.createElement("optgroup");
    group.label = `${category} (${list.length})`;
    for (const uc of list) {
      const opt = document.createElement("option");
      opt.value = uc.id;
      opt.textContent = `${uc.vuln ? "⚠" : "✓"} ${uc.title}`;
      group.appendChild(opt);
    }
    usecaseSelect.appendChild(group);
  }
})();

/* ---------------- Events ---------------- */

document.getElementById("scan-btn").addEventListener("click", runPipeline);
document.getElementById("clear-btn").addEventListener("click", () => {
  codeInput.value = "";
  updateLineCount();
  report.classList.add("hidden");
  emptyState.classList.remove("hidden");
  document.querySelectorAll(".phase-chip").forEach((c) => c.classList.remove("active"));
  document.getElementById("sample-select").value = "";
  usecaseSelect.value = "";
});
document.getElementById("sample-select").addEventListener("change", (e) => {
  const key = e.target.value;
  if (SAMPLES[key]) {
    codeInput.value = SAMPLES[key];
    usecaseSelect.value = "";
    updateLineCount();
    runPipeline();
  }
});
usecaseSelect.addEventListener("change", (e) => {
  const uc = useCaseById[e.target.value];
  if (uc) {
    codeInput.value = uc.code;
    document.getElementById("sample-select").value = "";
    updateLineCount();
    runPipeline();
  }
});
document.getElementById("copy-report").addEventListener("click", async (e) => {
  const text = document.getElementById("ship-report-text").textContent;
  try {
    await navigator.clipboard.writeText(text);
    e.target.textContent = "Copied ✓";
    setTimeout(() => (e.target.textContent = "Copy report"), 1500);
  } catch (_) {
    e.target.textContent = "Copy failed";
  }
});
codeInput.addEventListener("input", updateLineCount);

codeInput.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); runPipeline(); }
});

updateLineCount();
