# Multilingual Content-Risk Detector + Parent Alert

A runnable prototype of a child-safety detection/alerting layer: it ingests a
message the parent's app **already has legitimate access to**, classifies it for
risk **in whatever language it's written**, and produces a parent alert with a
concrete next action.

> **Scope — read this first.** This system **detects and alerts. It does not
> intercept or block** messages before a child sees them on Instagram / YouTube /
> TikTok — no third-party app has that platform access. The honest ceiling is:
> detect fast, alert the parent immediately with context, and let the **parent**
> take the action (lock the app, contact the platform, talk to the child). This
> prototype does no blocking, no scraping, and no platform login. See
> [`CLAUDE.md`](CLAUDE.md) for the full brief it's built from.

## What it does

Three phases, one pipeline:

1. **Ingest** ([`src/ingest.js`](src/ingest.js)) — normalizes an already-accessed
   message. Only sanctioned sources are allowed (Family Link, Screen Time,
   YouTube Data API, comment-moderation APIs, consented Android accessibility).
   A non-sanctioned source (scraping, private API) is **refused**, not worked
   around.
2. **Classify** ([`src/classifier.js`](src/classifier.js)) — detects language
   first ([`src/language.js`](src/language.js)), then runs multilingual lexicons
   ([`src/lexicons.js`](src/lexicons.js)) for five categories:
   sexual solicitation · **grooming** · harassment/bullying · self-harm ·
   violent threats. Grooming is multi-signal (secrecy + platform-move + meeting +
   age-probing + flattery compound into higher confidence). Self-harm is only
   flagged on the child's **outgoing** messages.
3. **Alert** ([`src/alerts.js`](src/alerts.js)) — high-confidence flags alert
   **immediately**; borderline ones batch into a summary to avoid alert fatigue.
   Every alert carries a specific next action. Nothing is ever auto-blocked.

Each finding captures **category, confidence, detected language, a redacted
excerpt** (never the full message — see [`src/redact.js`](src/redact.js)), and
**sender relationship** (mutual vs. not, which raises confidence for grooming).

## Try it

```bash
# One message (flags: --direction, --relationship, --platform, --json)
node cli.js "let's talk on telegram, don't tell your parents" --relationship not-mutual

# A child's outgoing message
node cli.js "ich kann nicht mehr" --direction outgoing

# A whole stream (one JSON message per line) → immediate alerts + daily summary
npm run demo        # runs cli.js --file examples/sample-stream.jsonl
```

Example output:

```
DETECTED: grooming | fr | 0.78
CONTEXT: "▇▇▇ ce weekend, tu es seu…" · sender: not a mutual connection
SUGGESTED ACTION: This may need immediate attention. Review the conversation now
and consider locking the app...
```

## Design choices worth calling out

- **Multilingual by construction, not translate-first.** Patterns live in each
  language (en/es/fr/pt/de + Arabic/Russian/Hindi via script detection).
  Translating to English before classifying loses the slang and coded language
  grooming detection depends on.
- **When language detection is unsure** (short, keyword-only messages), the
  classifier scans *all* lexicons and infers the language from the pattern that
  matched — recall matters more than precision for a safety tool.
- **Categories, not one score.** Each risk type is scored independently; the
  parent sees *what kind* of risk, not a vague red flag.
- **Heuristic, honest.** This is a lexicon+rules layer, not a trained model. A
  production build would swap in a multilingual model behind the same interface —
  the pipeline shape (ingest → classify → route) stays identical.

## Tests

```bash
npm test    # 47 checks: language detection, every category, direction gating,
            # multilingual self-harm, redaction, alert routing/format, and the
            # ingestion guardrail (no network/shell imports).
```

## Not in scope (by design)

- No pre-delivery blocking on closed platforms — impossible, not built.
- No scraping, private/unofficial endpoints, or credential automation.
- No routing of a child's content to anyone but the designated parent/guardian.
- No general surveillance — this is safety-risk detection, not blanket monitoring.
