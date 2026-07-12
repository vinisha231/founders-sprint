#!/usr/bin/env node
"use strict";

/* ============================================================
   ship-guard — run Build → Validate → Secure over a git diff.

   Usage:
     ship-guard                 scan staged changes (pre-commit)
     ship-guard --all           scan everything vs the default branch
     ship-guard --range A..B    scan a commit range (CI / pre-push)
     ship-guard <file> [...]    scan specific files (whole file)
     ship-guard --staged        explicit staged scan

   Exit code: 0 = clear/caution, 1 = "Do not ship" (blocking).
   Use --no-fail to always exit 0 (report-only).
   ============================================================ */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const SG = require("./scanner.js");

const RESET = "\x1b[0m", BOLD = "\x1b[1m", DIM = "\x1b[2m";
const RED = "\x1b[31m", YEL = "\x1b[33m", GRN = "\x1b[32m", CYA = "\x1b[36m", MAG = "\x1b[35m";
const SEV_COLOR = { crit: RED, high: RED, med: YEL, low: CYA, ok: GRN };
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (color, s) => (useColor ? color + s + RESET : s);

// This is a reporting CLI: writing to stdout/stderr is its job, not debug cruft.
const out = (s = "") => process.stdout.write(s + "\n");
const err = (s = "") => process.stderr.write(s + "\n");

function git(args) {
  return execSync("git " + args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

function isGitRepo() {
  try { git("rev-parse --is-inside-work-tree"); return true; } catch { return false; }
}

/* Parse a unified diff into per-file added lines with new-file line numbers. */
function parseDiff(diff) {
  const files = {};
  let current = null;
  let newLine = 0;
  for (const line of diff.split("\n")) {
    const fileMatch = line.match(/^\+\+\+ b\/(.+)$/);
    if (fileMatch) {
      current = fileMatch[1] === "/dev/null" ? null : fileMatch[1];
      if (current) files[current] = files[current] || [];
      continue;
    }
    const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) { newLine = parseInt(hunk[1], 10); continue; }
    if (!current) continue;
    if (line.startsWith("+") && !line.startsWith("+++")) {
      files[current].push({ n: newLine, content: line.slice(1), removed: false, diffLine: newLine });
      newLine++;
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      /* removed line: does not advance the new-file counter */
    } else if (!line.startsWith("\\")) {
      newLine++; /* context line */
    }
  }
  return files;
}

/* Only scan source-ish files; skip lockfiles, binaries, vendored dirs. */
const SKIP_RE = /(?:^|\/)(?:node_modules|dist|build|vendor|\.min\.)|\.(?:lock|png|jpe?g|gif|svg|ico|pdf|zip|map)$/i;

/* User-supplied ignores from .shipguardignore (gitignore-ish globs, one/line). */
function loadIgnorePatterns() {
  let root = ".";
  try { root = git("rev-parse --show-toplevel").trim() || "."; } catch { /* not a repo */ }
  const file = path.join(root, ".shipguardignore");
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map(globToRegExp);
}

/* Minimal glob → RegExp: supports * (any run, incl. /) and ? . Anchored to full path. */
function globToRegExp(glob) {
  const re = glob
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp("(?:^|/)" + re + "$");
}

const IGNORE_PATTERNS = loadIgnorePatterns();
function scannable(file) {
  if (SKIP_RE.test(file)) return false;
  return !IGNORE_PATTERNS.some((re) => re.test(file));
}

function getInputs(argv) {
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  const files = argv.filter((a) => !a.startsWith("--"));

  if (files.length) {
    // Explicit files: scan whole-file content.
    const result = {};
    for (const f of files) {
      if (!fs.existsSync(f)) { err(c(YEL, `skip (not found): ${f}`)); continue; }
      const src = fs.readFileSync(f, "utf8");
      result[f] = SG.normalizeLines(src);
    }
    return result;
  }

  let diff;
  if (flags.has("--all")) {
    let base = "HEAD";
    try { base = git("merge-base HEAD origin/HEAD").trim() || "HEAD"; } catch { /* keep HEAD */ }
    diff = git(`diff ${base} --unified=0`);
  } else if ([...flags].some((f) => f.startsWith("--range"))) {
    const range = argv.find((a) => a.startsWith("--range")).split("=")[1] || argv[argv.indexOf("--range") + 1];
    diff = git(`diff ${range} --unified=0`);
  } else {
    // Default: staged changes (pre-commit).
    diff = git("diff --cached --unified=0");
  }

  const parsed = parseDiff(diff);
  const result = {};
  for (const [file, lines] of Object.entries(parsed)) {
    if (scannable(file) && lines.length) result[file] = lines;
  }
  return result;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--help") || argv.includes("-h")) {
    out(fs.readFileSync(__filename, "utf8").split("*/")[0].split("Usage:")[1].split("Exit code")[0].trim());
    process.exit(0);
  }
  if (!isGitRepo() && !argv.some((a) => !a.startsWith("--"))) {
    err(c(RED, "Not a git repository. Pass file paths, or run inside a repo."));
    process.exit(2);
  }

  const inputs = getInputs(argv);
  const fileNames = Object.keys(inputs);

  if (fileNames.length === 0) {
    out(c(DIM, "Ship Guard: no scannable changes found. Nothing to check."));
    process.exit(0);
  }

  let allValidate = [];
  let allSecure = [];
  let combinedSrc = "";

  for (const file of fileNames) {
    const lines = inputs[file];
    const src = lines.map((l) => l.content).join("\n");
    combinedSrc += src + "\n";
    allValidate = allValidate.concat(SG.runValidate(src, lines, file));
    allSecure = allSecure.concat(SG.runSecure(src, lines, file));
  }

  // De-dupe the "no tests" heuristic across files: judge on the whole changeset.
  allValidate = allValidate.filter((f) => f.id !== "no-tests" && f.id !== "tests-present");
  const hasTests = /\b(?:describe|it\(|test\(|expect\(|assert|@Test|def test_)\b/.test(combinedSrc);
  const hasLogic = /(?:function |=>|def |class |app\.(?:get|post|put|delete)|router\.)/.test(combinedSrc);
  if (hasLogic && !hasTests) {
    allValidate.push({ id: "no-tests", severity: "med", title: "No automated tests detected in this changeset",
      advice: "Add tests (happy path + edge + failure) and run the suite before shipping.", line: null, file: null });
  }

  const verdict = SG.decideVerdict(allValidate, allSecure);
  render(fileNames, allValidate, allSecure, verdict);

  const blocking = verdict.level === "block";
  const failOnBlock = !argv.includes("--no-fail");
  process.exit(blocking && failOnBlock ? 1 : 0);
}

function render(files, validate, secure, verdict) {
  const order = { crit: 0, high: 1, med: 2, low: 3, ok: 4 };
  const line = "─".repeat(58);

  out("");
  out(c(BOLD, "🛡  Ship Guard") + c(DIM, `  ·  ${files.length} file(s) scanned`));
  out(c(DIM, line));

  const printSection = (name, color, findings) => {
    const real = findings.filter((f) => f.severity !== "ok").sort((a, b) => order[a.severity] - order[b.severity]);
    out(c(color + BOLD, name) + c(DIM, `  ${real.length} finding(s)`));
    if (real.length === 0) { out("  " + c(GRN, "✓ nothing flagged")); return; }
    for (const f of real) {
      const loc = f.file ? `${f.file}:${f.line || "?"}` : (f.line ? `line ${f.line}` : "");
      const badge = c(SEV_COLOR[f.severity] + BOLD, `[${SG.SEV_LABEL[f.severity]}]`);
      out(`  ${badge} ${f.title}` + (loc ? c(DIM, `  (${loc})`) : ""));
      if (f.snippet) out("      " + c(DIM, f.snippet));
      if (f.advice) out("      " + c(CYA, "→ " + f.advice));
    }
  };

  printSection("VALIDATE", GRN, validate);
  out("");
  printSection("SECURE", MAG, secure);
  out(c(DIM, line));

  const vColor = verdict.level === "block" ? RED : verdict.level === "warn" ? YEL : GRN;
  out(c(vColor + BOLD, `${verdict.icon} ${verdict.label.toUpperCase()}`) + c(DIM, `  — ${verdict.sub}`));

  if (verdict.level === "block") {
    out(c(YEL, "\n⚠  Security-critical findings above. Fix them or override with --no-fail\n   (and flag auth/secrets/injection for human review before shipping)."));
  }
  out("");
}

main();
