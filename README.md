# Founders Sprint — Ship Guard 🛡️

**Live demo:** https://vinisha231.github.io/founders-sprint/

A tiny, zero-dependency web app that runs a code change through three phases
before you ship it — **Build → Validate → Secure**. Paste a snippet or a diff,
hit **Run pipeline**, and get back a ship report with a go / no-go verdict.

It's the [Build → Validate → Secure methodology](CLAUDE.md) turned into
something you can actually click.

## What it does

| Phase | What Ship Guard checks |
| --- | --- |
| **Build** | Takes your pasted code / unified diff as input (it never modifies your code). |
| **Validate** | Detects missing tests, leftover `console.log`/`print` debugging, unresolved `TODO`/`FIXME`, and empty `catch` blocks that swallow errors. |
| **Secure** | Heuristic security scan mapped to the checklist: hardcoded secrets & connection strings, SQL/command injection, path traversal, XSS, **broken object-level authorization (IDOR)**, missing auth on new routes, insecure `http://` calls, cookies without security flags, weak hashing, `eval`, **SSRF, open redirect, prototype pollution, insecure deserialization, weak randomness for tokens, and permissive CORS**. |

The output is the exact structured **ship report** from the methodology:

```
VERDICT: ⛔ Do not ship

BUILD:    diff analyzed (Ship Guard does not modify code).
VALIDATE: medium: no automated tests detected for this change.
SECURE:   [high] Input handling — Possible SQL injection (line 5)
          [high] AuthN / AuthZ — Possible broken object-level authorization (line 11)
          [high] AuthN / AuthZ — New route with no visible authentication check (line 2)
```

Critical findings (auth, secrets, injection) trip a **Do not ship** verdict and
are explicitly flagged for human review — the tool never pretends a hole is fine.

## Demo it in 10 seconds

1. Open the [live demo](https://vinisha231.github.io/founders-sprint/).
2. Pick a sample from the dropdown:
   - **😱 Vulnerable Express route** → SQL injection + IDOR + missing auth → *Do not ship*
   - **🔑 Hardcoded secrets** → API keys, DB creds, insecure cookie → *Do not ship*
   - **✅ Reasonably clean handler** → owner-scoped query, auth, rate limit, tests → *Clear to ship*
3. Or paste your own code and hit **Run pipeline** (⌘/Ctrl + Enter).

## Add it to a project (no more pasting)

The same rule engine ([`scanner.js`](scanner.js)) also runs as a CLI over your
real `git diff`, so it can live inside your workflow instead of a browser tab.

### Scan your staged changes
```bash
node cli.js            # scan staged changes
node cli.js --all      # scan everything vs the default branch
node cli.js src/*.js   # scan specific files
```
Exit code is **1** on a "Do not ship" verdict, **0** otherwise — so it plugs
straight into hooks and CI. Add `--no-fail` for report-only.

### Install as a pre-commit hook
```bash
node install-hook.js   # writes .git/hooks/pre-commit
```
Now every commit is scanned automatically; a blocking verdict stops the commit.
Bypass once with `git commit --no-verify`.

### Run on pull requests (GitHub Action)
[`.github/workflows/ship-guard.yml`](.github/workflows/ship-guard.yml) scans only
the lines a PR changed against its base branch and fails the check on a blocking
verdict — drop it into any repo's `.github/workflows/`.

All three surfaces (web app, CLI, Action) share **one** engine, so the verdict is
identical everywhere.

## Tests & use cases

The engine ships with **63 unit tests** and a corpus of **62 real-world use
cases**, each with the verdict/rules it should produce:

```bash
npm test        # runs both suites
node test.js            # 63 unit tests (rule true/false positives, verdicts, diffs, report)
node test-usecases.js   # validates all 62 scenarios in use-cases.js
```

The 62 use cases in [`use-cases.js`](use-cases.js) cover SQL/command injection,
secrets, IDOR, missing auth, XSS, path traversal, transport, cookies, crypto,
`eval`, error leakage, and clean/safe counterparts. They double as the web app's
**"62 use cases" gallery** — pick any from the dropdown to load it into the
scanner and see the verdict.

## Run the web app locally

No build step, no dependencies — it's plain HTML/CSS/JS.

```bash
git clone https://github.com/vinisha231/founders-sprint.git
cd founders-sprint
python3 -m http.server 4181
# open http://localhost:4181
```

## How it works

Everything runs client-side in [`app.js`](app.js) — your code is never uploaded.
The scanner normalizes unified diffs (skipping removed lines), runs a set of
line-based heuristic rules, ranks findings by severity, and decides a verdict.

It's a **heuristic aid, not a guarantee** — it catches common, high-signal
mistakes to make Validate and Secure hard to skip. It does not replace real
tests, a proper SAST tool, or human review.

## Files

- [`scanner.js`](scanner.js) — the shared rule engine (browser + Node)
- [`index.html`](index.html) · [`styles.css`](styles.css) · [`app.js`](app.js) · [`samples.js`](samples.js) — the web app
- [`cli.js`](cli.js) · [`install-hook.js`](install-hook.js) — the CLI and hook installer
- [`test.js`](test.js) · [`test-usecases.js`](test-usecases.js) · [`use-cases.js`](use-cases.js) — 63 unit tests, the use-case runner, and the 62-scenario corpus
- [`.github/workflows/ship-guard.yml`](.github/workflows/ship-guard.yml) — the PR check
- [`CLAUDE.md`](CLAUDE.md) — the Build → Validate → Secure methodology the tool enforces
- [`.cursorrules`](.cursorrules) · [`system-prompt.md`](system-prompt.md) — the same methodology as a drop-in agent prompt

## Also in this repo

[`content-risk-detector/`](content-risk-detector/) — a separate prototype: a
multilingual child-safety detection/alerting layer that classifies messages a
parent's app already has legitimate access to and produces a parent alert.
Different tool, different problem; see its own
[README](content-risk-detector/README.md) for details.
