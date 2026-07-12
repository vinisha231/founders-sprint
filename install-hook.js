#!/usr/bin/env node
"use strict";

/* Installs Ship Guard as a git pre-commit hook in the current repo.
   Run:  node install-hook.js   (or)   npm run install-hook            */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

let gitDir;
try {
  gitDir = execSync("git rev-parse --git-dir", { encoding: "utf8" }).trim();
} catch {
  err("✗ Not inside a git repository. cd into your project first.");
  process.exit(1);
}

const hooksDir = path.join(gitDir, "hooks");
fs.mkdirSync(hooksDir, { recursive: true });
const hookPath = path.join(hooksDir, "pre-commit");
const cliPath = path.resolve(__dirname, "cli.js");

const hook = `#!/bin/sh
# Ship Guard — Build → Validate → Secure pre-commit hook
node "${cliPath}" --staged
`;

if (fs.existsSync(hookPath)) {
  const existing = fs.readFileSync(hookPath, "utf8");
  if (existing.includes("Ship Guard")) {
    out("✓ Ship Guard pre-commit hook already installed.");
    process.exit(0);
  }
  const backup = hookPath + ".backup";
  fs.copyFileSync(hookPath, backup);
  out(`! Existing pre-commit hook backed up to ${path.relative(process.cwd(), backup)}`);
}

fs.writeFileSync(hookPath, hook, { mode: 0o755 });
out("✓ Installed Ship Guard pre-commit hook at " + path.relative(process.cwd(), hookPath));
out("  It runs on every commit and blocks 'Do not ship' verdicts.");
out("  Bypass once with:  git commit --no-verify");
