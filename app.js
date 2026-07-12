"use strict";

/* ============================================================
   Ship Guard — client-side Validate + Secure engine.
   Everything runs in the browser. Heuristic, line-based rules.
   ============================================================ */

const SEV = { CRIT: "crit", HIGH: "high", MED: "med", LOW: "low", OK: "ok" };
const SEV_WEIGHT = { crit: 100, high: 40, med: 15, low: 5, ok: 0 };
const SEV_LABEL = { crit: "critical", high: "high", med: "medium", low: "low", ok: "ok" };

/* Strip a leading unified-diff marker so line content matches cleanly,
   but remember whether a line was *added* (diffs: only scan added/context). */
function normalizeLines(src) {
  const raw = src.split("\n");
  return raw.map((line, i) => {
    let content = line;
    let removed = false;
    if (/^[-+ ]/.test(line) && looksLikeDiff(raw)) {
      if (line[0] === "-") removed = true;
      content = line.slice(1);
    }
    return { n: i + 1, content, removed };
  });
}

function looksLikeDiff(rawLines) {
  return rawLines.some((l) => /^@@ .* @@/.test(l) || /^\+\+\+ /.test(l));
}

/* A rule: { id, phase, test(line) -> bool, severity, title, item, advice } */

const SECURE_RULES = [
  {
    id: "hardcoded-secret",
    severity: SEV.CRIT,
    title: "Hardcoded secret / credential",
    item: "Secrets & config",
    advice: "Move this to an environment variable or secrets manager; never commit it.",
    test: (c) =>
      /(?:api[_-]?key|secret|password|passwd|pwd|token|access[_-]?key|private[_-]?key)\s*[:=]\s*["'][^"']{6,}["']/i.test(c) ||
      /(?:AKIA[0-9A-Z]{16})/.test(c) ||
      /(?:sk|pk|rk)[-_](?:live|test)[-_]?[a-zA-Z0-9]{10,}/.test(c) ||
      /(?:sk-[a-zA-Z0-9]{16,})/.test(c) ||
      /(?:gh[pousr]_[A-Za-z0-9]{20,})/.test(c),
  },
  {
    id: "conn-string",
    severity: SEV.CRIT,
    title: "Hardcoded connection string with credentials",
    item: "Secrets & config",
    advice: "Read database URLs from config/env, not source. Rotate this credential if it was ever pushed.",
    test: (c) => /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^\s"']*:[^\s"'@]+@/i.test(c),
  },
  {
    id: "sql-injection",
    severity: SEV.HIGH,
    title: "Possible SQL injection (string-built query)",
    item: "Input handling",
    advice: "Use parameterized queries / prepared statements instead of concatenating or interpolating input.",
    test: (c) =>
      /(?:SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*(?:\+\s*(?:req|request|params|query|body|input|user)|\$\{[^}]*(?:req|params|query|body|user|input)[^}]*\}|["']\s*\+)/i.test(c) ||
      /(?:query|execute|raw)\s*\(\s*[`"'][^`"']*(?:SELECT|INSERT|UPDATE|DELETE)[^`"']*\$\{/i.test(c),
  },
  {
    id: "command-injection",
    severity: SEV.HIGH,
    title: "Possible command injection",
    item: "Input handling",
    advice: "Avoid passing user input to a shell. Use argument arrays (execFile/spawn) and validate input.",
    test: (c) =>
      /(?:exec|execSync|system|popen|os\.system|child_process\.exec)\s*\(\s*[`"'][^`"')]*\$\{|(?:exec|execSync|system)\s*\([^)]*\+\s*(?:req|params|query|body|input|user)/i.test(c),
  },
  {
    id: "path-traversal",
    severity: SEV.HIGH,
    title: "Possible path traversal (user input in file path)",
    item: "Input handling",
    advice: "Resolve and validate the path against an allow-listed base directory before reading/writing.",
    test: (c) =>
      /(?:readFile|readFileSync|writeFile|createReadStream|sendFile|open|fopen|require)\s*\([^)]*(?:req\.(?:params|query|body)|request\.[a-z]+|params\.|\+\s*(?:filename|path|file))/i.test(c) &&
      !/path\.(?:resolve|normalize|basename)/.test(c),
  },
  {
    id: "xss-innerhtml",
    severity: SEV.HIGH,
    title: "Possible XSS via unsanitized HTML injection",
    item: "Input handling",
    advice: "Use textContent, framework escaping, or sanitize (e.g. DOMPurify) before inserting into the DOM.",
    test: (c) =>
      /\.innerHTML\s*(?:\+?=)\s*(?!["'`][^"'`]*["'`]\s*;?\s*$)/.test(c) ||
      /dangerouslySetInnerHTML/.test(c) ||
      /document\.write\s*\(/.test(c),
  },
  {
    id: "broken-object-auth",
    severity: SEV.HIGH,
    title: "Possible broken object-level authorization (IDOR)",
    item: "AuthN / AuthZ",
    advice: "Look up the record scoped to the current user (e.g. WHERE id = ? AND owner_id = currentUser), not by ID alone. Confirm the requester owns this resource.",
    test: (c) =>
      /(?:findById|findOne|get|delete|update|findByPk)\s*\(\s*req\.params\.(?:id|[a-z]*Id)/i.test(c),
  },
  {
    id: "http-url",
    severity: SEV.MED,
    title: "Insecure HTTP URL for external call",
    item: "Session & transport",
    advice: "Use https:// for any external request so traffic and credentials aren't sent in cleartext.",
    test: (c) => /(?:fetch|axios|get|post|request|open)\s*\(?\s*["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i.test(c),
  },
  {
    id: "insecure-cookie",
    severity: SEV.MED,
    title: "Cookie set without security flags",
    item: "Session & transport",
    advice: "Set HttpOnly, Secure, and SameSite on session/auth cookies where the framework supports it.",
    test: (c) =>
      /(?:res\.cookie|set[- ]?cookie|document\.cookie\s*=)/i.test(c) &&
      !/httponly/i.test(c) &&
      /(?:session|token|auth|sid|jwt)/i.test(c),
  },
  {
    id: "weak-crypto",
    severity: SEV.MED,
    title: "Weak hashing algorithm",
    item: "Input handling",
    advice: "MD5/SHA-1 are unsuitable for passwords or integrity. Use bcrypt/argon2 for passwords, SHA-256+ otherwise.",
    test: (c) => /createHash\s*\(\s*["'](?:md5|sha1)["']/i.test(c) || /\b(?:md5|sha1)\s*\(/i.test(c),
  },
  {
    id: "eval-use",
    severity: SEV.HIGH,
    title: "Use of eval / dynamic code execution",
    item: "Input handling",
    advice: "Avoid eval and Function() on any value derived from input — it enables remote code execution.",
    test: (c) => /(?:^|[^.\w])eval\s*\(/.test(c) || /new\s+Function\s*\(/.test(c),
  },
  {
    id: "error-leak",
    severity: SEV.LOW,
    title: "Error / stack trace returned to client",
    item: "Data exposure",
    advice: "Log details server-side; return a generic message so stack traces and paths aren't exposed in production.",
    test: (c) => /res\.(?:send|json|status\([^)]*\)\.(?:send|json))\s*\([^)]*(?:err\.stack|error\.stack|err\.message|exception)/i.test(c),
  },
];

/* Broad "does this diff even add an endpoint?" detector for the AuthN check. */
const ENDPOINT_RE = /(?:app|router)\.(?:get|post|put|patch|delete)\s*\(\s*["'`][^"'`]+["'`]/i;
const AUTH_HINT_RE = /(?:auth|isAuthenticated|requireAuth|verifyToken|ensureLoggedIn|passport|middleware|jwt|session|currentUser|req\.user)/i;

const VALIDATE_RULES = [
  {
    id: "console-log",
    severity: SEV.LOW,
    title: "Debug logging left in code",
    advice: "Remove stray console.log / print debugging before shipping.",
    test: (c) => /\bconsole\.(?:log|debug)\s*\(/.test(c) || /^\s*print\s*\(/.test(c),
  },
  {
    id: "todo-fixme",
    severity: SEV.LOW,
    title: "Unresolved TODO / FIXME",
    advice: "Resolve or ticket TODO/FIXME/HACK markers before considering the task done.",
    test: (c) => /\b(?:TODO|FIXME|HACK|XXX)\b/.test(c),
  },
  {
    id: "empty-catch",
    severity: SEV.MED,
    title: "Empty catch block swallows errors",
    advice: "Handle or log the error — silently swallowing it hides real failures.",
    test: (c) => /catch\s*\([^)]*\)\s*\{\s*\}/.test(c) || /except[^\n:]*:\s*pass\b/.test(c),
  },
];

const TEST_SIGNAL_RE = /\b(?:describe|it\(|test\(|expect\(|assert|@Test|def test_|it should)\b/;

function scanLines(lines, rules) {
  const findings = [];
  const seen = new Set();
  for (const { n, content, removed } of lines) {
    if (removed) continue;
    for (const rule of rules) {
      const key = rule.id + ":" + n;
      if (seen.has(key)) continue;
      try {
        if (rule.test(content)) {
          seen.add(key);
          findings.push({
            id: rule.id,
            severity: rule.severity,
            title: rule.title,
            item: rule.item,
            advice: rule.advice,
            line: n,
            snippet: content.trim().slice(0, 160),
          });
        }
      } catch (_) { /* defensive: a bad regex shouldn't kill the scan */ }
    }
  }
  return findings;
}

function runValidate(src, lines) {
  const findings = scanLines(lines, VALIDATE_RULES);
  const hasTests = TEST_SIGNAL_RE.test(src);
  const looksLikeLogic = /(?:function |=>|def |class |app\.(?:get|post|put|delete)|router\.)/.test(src);
  if (looksLikeLogic && !hasTests) {
    findings.push({
      id: "no-tests",
      severity: SEV.MED,
      title: "No automated tests detected for this change",
      advice: "Add tests covering the happy path, one edge case, and one failure case, then run the full suite.",
      line: null,
      snippet: "",
    });
  } else if (hasTests) {
    findings.push({
      id: "tests-present",
      severity: SEV.OK,
      title: "Test assertions detected",
      advice: "Good — make sure they cover an edge case and a failure case, not just the happy path.",
      line: null,
      snippet: "",
    });
  }
  return findings;
}

function runSecure(src, lines) {
  const findings = scanLines(lines, SECURE_RULES);
  // AuthN check: new endpoint added but no auth hint anywhere in the diff.
  if (ENDPOINT_RE.test(src) && !AUTH_HINT_RE.test(src)) {
    const m = lines.find((l) => !l.removed && ENDPOINT_RE.test(l.content));
    findings.push({
      id: "missing-auth",
      severity: SEV.HIGH,
      title: "New route with no visible authentication check",
      item: "AuthN / AuthZ",
      advice: "Confirm this route enforces authentication (middleware or in-handler). If it's intentionally public, note why.",
      line: m ? m.n : null,
      snippet: m ? m.content.trim().slice(0, 160) : "",
    });
  }
  return findings;
}

function severityRank(findings) {
  return findings.reduce((sum, f) => sum + (SEV_WEIGHT[f.severity] || 0), 0);
}

function decideVerdict(validate, secure) {
  const secureReal = secure.filter((f) => f.severity !== SEV.OK);
  const hasCrit = secureReal.some((f) => f.severity === SEV.CRIT);
  const hasHigh = secureReal.some((f) => f.severity === SEV.HIGH);
  const validateBlock = validate.some((f) => f.severity === SEV.MED || f.severity === SEV.HIGH || f.severity === SEV.CRIT);

  if (hasCrit || hasHigh) {
    return { level: "block", icon: "⛔", label: "Do not ship", sub: "Security-critical issues need a human before this goes out." };
  }
  if (secureReal.length > 0 || validateBlock) {
    return { level: "warn", icon: "⚠️", label: "Ship with caution", sub: "No critical security holes, but there are issues to resolve first." };
  }
  return { level: "pass", icon: "✅", label: "Clear to ship", sub: "No blocking issues found by the heuristic checks. Human review still recommended." };
}

/* ---------------- Rendering ---------------- */

function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html != null) e.innerHTML = html;
  return e;
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderFindings(container, findings, emptyMsg) {
  container.innerHTML = "";
  if (findings.length === 0) {
    container.appendChild(el("li", "finding", `<div class="finding-body"><div class="finding-title" style="color:var(--ok)">✓ ${emptyMsg}</div></div>`));
    return;
  }
  const order = { crit: 0, high: 1, med: 2, low: 3, ok: 4 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  for (const f of findings) {
    const li = el("li", "finding");
    const badge = el("span", `sev-badge sev-${f.severity}`, SEV_LABEL[f.severity]);
    const body = el("div", "finding-body");
    body.appendChild(el("div", "finding-title", escapeHtml(f.title)));
    const metaBits = [];
    if (f.line) metaBits.push(`line ${f.line}`);
    if (f.item) metaBits.push(f.item);
    if (metaBits.length) body.appendChild(el("div", "finding-meta", metaBits.join(" · ")));
    if (f.snippet) body.appendChild(el("div", "finding-snippet", escapeHtml(f.snippet)));
    if (f.advice) body.appendChild(el("div", "finding-advice", escapeHtml(f.advice)));
    li.appendChild(badge);
    li.appendChild(body);
    container.appendChild(li);
  }
}

function buildShipReport(verdict, validate, secure) {
  const secureReal = secure.filter((f) => f.severity !== SEV.OK);
  const validateReal = validate.filter((f) => f.severity !== SEV.OK);

  const buildLine = "diff analyzed (Ship Guard does not modify code).";

  let validateLine;
  if (validateReal.length === 0) {
    validateLine = validate.some((f) => f.id === "tests-present")
      ? "test assertions present; no blocking smells detected."
      : "no blocking smells detected.";
  } else {
    validateLine = validateReal.map((f) => `${SEV_LABEL[f.severity]}: ${f.title.toLowerCase()}`).join("; ") + ".";
  }

  let secureLine;
  if (secureReal.length === 0) {
    secureLine = "no issues flagged by heuristic checks (still merits human review).";
  } else {
    secureLine = secureReal
      .map((f) => `[${SEV_LABEL[f.severity]}] ${f.item ? f.item + " — " : ""}${f.title}${f.line ? " (line " + f.line + ")" : ""}`)
      .join("\n         ");
  }

  const flag = secureReal.some((f) => f.severity === SEV.CRIT || f.severity === SEV.HIGH)
    ? "\n\n⚠  Auth / secrets / injection issues above are security-critical —\n   flag for human review before shipping; do not auto-patch."
    : "";

  return (
    `VERDICT: ${verdict.icon} ${verdict.label}\n\n` +
    `BUILD:    ${buildLine}\n` +
    `VALIDATE: ${validateLine}\n` +
    `SECURE:   ${secureLine}${flag}`
  );
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

  // Verdict banner
  const verdictEl = document.getElementById("verdict");
  verdictEl.className = `verdict ${verdict.level}`;
  verdictEl.innerHTML = `<span class="verdict-icon">${verdict.icon}</span><div><div>${verdict.label}</div><div class="verdict-sub">${verdict.sub}</div></div>`;

  // Scores
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

/* ---------------- Samples ---------------- */

const SAMPLES = {
  vulnerable: `// PATCH: add endpoint to fetch an invoice
app.get('/api/invoices/:id', (req, res) => {
  const id = req.params.id;
  const invoice = db.query(
    "SELECT * FROM invoices WHERE id = " + id
  );
  res.json(invoice);
});

app.post('/api/invoices/:id/notes', (req, res) => {
  const note = Invoice.findById(req.params.id);
  note.text = req.body.text;
  note.save();
  res.send('<div>' + req.body.text + '</div>');
});`,

  secrets: `const stripe = require('stripe')('sk-live-4eC39Hq8f2a9bXcVdE1234567890');

const config = {
  dbUrl: "postgres://admin:SuperSecret123@db.internal:5432/app",
  apiKey: "AKIAIOSFODNN7EXAMPLE",
  jwtSecret: "hunter2hunter2hunter2",
};

fetch('http://payments.partner.com/charge', { method: 'POST' });

res.cookie('session', token, { maxAge: 900000 });`,

  clean: `// PATCH: fetch the current user's invoice
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({ windowMs: 60000, max: 30 });

app.get('/api/invoices/:id', requireAuth, limiter, async (req, res) => {
  try {
    const invoice = await Invoice.findOne({
      where: { id: req.params.id, ownerId: req.user.id },
    });
    if (!invoice) return res.status(404).json({ error: 'Not found' });
    res.json({ id: invoice.id, total: invoice.total, status: invoice.status });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// tests/invoices.test.js
describe('GET /api/invoices/:id', () => {
  it('returns the owner\\'s invoice', async () => { expect(200).toBe(200); });
  it('rejects another user\\'s invoice', async () => { expect(404).toBe(404); });
  it('requires auth', async () => { expect(401).toBe(401); });
});`,
};

/* ---------------- Events ---------------- */

document.getElementById("scan-btn").addEventListener("click", runPipeline);
document.getElementById("clear-btn").addEventListener("click", () => {
  codeInput.value = "";
  updateLineCount();
  report.classList.add("hidden");
  emptyState.classList.remove("hidden");
  document.querySelectorAll(".phase-chip").forEach((c) => c.classList.remove("active"));
  document.getElementById("sample-select").value = "";
});
document.getElementById("sample-select").addEventListener("change", (e) => {
  const key = e.target.value;
  if (SAMPLES[key]) {
    codeInput.value = SAMPLES[key];
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

// Ctrl/Cmd+Enter to run
codeInput.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); runPipeline(); }
});

updateLineCount();
