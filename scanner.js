/* ============================================================
   Ship Guard — shared Validate + Secure rule engine.

   Runs in BOTH the browser (window.ShipGuard) and Node
   (require("./scanner.js")). Heuristic, line-based rules.
   No DOM, no dependencies — pure functions over text.
   ============================================================ */
(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (root) root.ShipGuard = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const SEV = { CRIT: "crit", HIGH: "high", MED: "med", LOW: "low", OK: "ok" };
  const SEV_WEIGHT = { crit: 100, high: 40, med: 15, low: 5, ok: 0 };
  const SEV_LABEL = { crit: "critical", high: "high", med: "medium", low: "low", ok: "ok" };

  function looksLikeDiff(rawLines) {
    return rawLines.some((l) => /^@@ .* @@/.test(l) || /^\+\+\+ /.test(l));
  }

  /* Turn raw source (or a unified diff) into scannable line records.
     For diffs, removed lines are marked so callers can skip them. */
  function normalizeLines(src) {
    const raw = src.split("\n");
    const isDiff = looksLikeDiff(raw);
    return raw.map((line, i) => {
      let content = line;
      let removed = false;
      if (isDiff && /^[-+ ]/.test(line)) {
        if (line[0] === "-") removed = true;
        content = line.slice(1);
      }
      return { n: i + 1, content, removed };
    });
  }

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
      test: (c) => /(?:findById|findOne|get|delete|update|findByPk)\s*\(\s*req\.params\.(?:id|[a-z]*Id)/i.test(c),
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

  // Matches common test signals. Note the call-style alternatives use \s*\(
  // rather than a trailing \b — a \b right after "(" never matches (both sides
  // are non-word chars), which would silently disable it(/test(/expect( detection.
  const TEST_SIGNAL_RE = /\b(?:describe|context|it|test|expect)\s*\(|\bassert\b|@Test\b|def test_|it should/;

  /* Run a rule set over normalized lines. `label` prefixes finding location
     (used by the CLI to carry a filename). */
  function scanLines(lines, rules, fileLabel) {
    const findings = [];
    const seen = new Set();
    for (const rec of lines) {
      if (rec.removed) continue;
      const lineNo = rec.diffLine || rec.n;
      for (const rule of rules) {
        const key = rule.id + ":" + (fileLabel || "") + ":" + lineNo;
        if (seen.has(key)) continue;
        try {
          if (rule.test(rec.content)) {
            seen.add(key);
            findings.push({
              id: rule.id,
              severity: rule.severity,
              title: rule.title,
              item: rule.item,
              advice: rule.advice,
              line: lineNo,
              file: fileLabel || null,
              snippet: rec.content.trim().slice(0, 160),
            });
          }
        } catch (_) { /* a bad regex shouldn't kill the scan */ }
      }
    }
    return findings;
  }

  function runValidate(src, lines, fileLabel) {
    const findings = scanLines(lines, VALIDATE_RULES, fileLabel);
    const hasTests = TEST_SIGNAL_RE.test(src);
    const looksLikeLogic = /(?:function |=>|def |class |app\.(?:get|post|put|delete)|router\.)/.test(src);
    if (looksLikeLogic && !hasTests) {
      findings.push({
        id: "no-tests",
        severity: SEV.MED,
        title: "No automated tests detected for this change",
        advice: "Add tests covering the happy path, one edge case, and one failure case, then run the full suite.",
        line: null, file: null, snippet: "",
      });
    } else if (hasTests) {
      findings.push({
        id: "tests-present",
        severity: SEV.OK,
        title: "Test assertions detected",
        advice: "Good — make sure they cover an edge case and a failure case, not just the happy path.",
        line: null, file: null, snippet: "",
      });
    }
    return findings;
  }

  function runSecure(src, lines, fileLabel) {
    const findings = scanLines(lines, SECURE_RULES, fileLabel);
    if (ENDPOINT_RE.test(src) && !AUTH_HINT_RE.test(src)) {
      const m = lines.find((l) => !l.removed && ENDPOINT_RE.test(l.content));
      findings.push({
        id: "missing-auth",
        severity: SEV.HIGH,
        title: "New route with no visible authentication check",
        item: "AuthN / AuthZ",
        advice: "Confirm this route enforces authentication (middleware or in-handler). If it's intentionally public, note why.",
        line: m ? (m.diffLine || m.n) : null,
        file: fileLabel || null,
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

    const loc = (f) => (f.file ? f.file + ":" + f.line : f.line ? "line " + f.line : "");
    let secureLine;
    if (secureReal.length === 0) {
      secureLine = "no issues flagged by heuristic checks (still merits human review).";
    } else {
      secureLine = secureReal
        .map((f) => `[${SEV_LABEL[f.severity]}] ${f.item ? f.item + " — " : ""}${f.title}${loc(f) ? " (" + loc(f) + ")" : ""}`)
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

  return {
    SEV, SEV_WEIGHT, SEV_LABEL,
    SECURE_RULES, VALIDATE_RULES,
    looksLikeDiff, normalizeLines, scanLines,
    runValidate, runSecure, severityRank, decideVerdict, buildShipReport,
  };
});
