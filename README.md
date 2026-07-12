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
| **Secure** | Heuristic security scan mapped to the checklist: hardcoded secrets & connection strings, SQL/command injection, path traversal, XSS, **broken object-level authorization (IDOR)**, missing auth on new routes, insecure `http://` calls, cookies without security flags, weak hashing, and `eval`. |

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

## Run it locally

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

- [`index.html`](index.html) · [`styles.css`](styles.css) · [`app.js`](app.js) — the app
- [`CLAUDE.md`](CLAUDE.md) — the Build → Validate → Secure methodology the app enforces
- [`.cursorrules`](.cursorrules) · [`system-prompt.md`](system-prompt.md) — the same methodology as a drop-in agent prompt
