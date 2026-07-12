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
   first ([`src/language.js`](src/language.js); optionally via AWS Comprehend,
   see below), then runs multilingual lexicons
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

# Same, but detecting language via AWS Comprehend instead of the local
# heuristic (falls back to local automatically if unavailable) — see
# "Optional: AWS Comprehend language detection" below before using this.
npm run demo:aws
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

## Optional: AWS Comprehend language detection

The local heuristic in `src/language.js` is the default and requires no setup.
As a pluggable alternative, [`src/aws-language.js`](src/aws-language.js) can
route language **detection only** (not translation, not classification)
through Amazon Comprehend's `DetectDominantLanguage`:

```bash
npm install @aws-sdk/client-comprehend   # optional dependency, not installed by default
export AWS_REGION=us-east-1              # + standard AWS credential resolution
node cli.js "some message" --use-aws
# or: CONTENT_RISK_LANGUAGE_BACKEND=aws-comprehend node cli.js "some message"
```

Why Comprehend and not Translate: `DetectDominantLanguage` is purpose-built for
language ID — cheaper and more accurate on short text than paying for a
translation call just to read back its source-language side effect. And
critically, this is **detection-only** — the classifier still runs the native
per-language lexicons against the original text; nothing gets translated to
English before classifying, which would lose the slang and coded language
grooming detection depends on (see "Design choices" above).

**This is opt-in and fails safe.** If the SDK isn't installed, credentials
aren't configured, or the API call fails for any reason, detection
automatically and silently-to-the-pipeline falls back to the local heuristic
— the `note:`/`fallback` field in the CLI/JSON output tells you when that
happened. The base install, `npm test`, and `npm run demo` never touch AWS or
the network; `@aws-sdk/client-comprehend` is an `optionalDependency` and is
lazy-required only when `--use-aws` / `CONTENT_RISK_LANGUAGE_BACKEND` is set.

**Privacy note.** Enabling this backend sends message text to AWS — a
third-party processor — for language identification. That's a real
deployment decision (parent disclosure, a data-processing agreement with
AWS, data-retention settings on the Comprehend side) that this integration
makes *possible*, not one it makes *for you*. The default, credential-free
path never leaves the machine.

## Tests

```bash
npm test    # 58 checks: language detection, every category, direction gating,
            # multilingual self-harm, redaction, alert routing/format, the
            # ingestion guardrail (no network/shell imports), and the AWS
            # backend's fallback behavior (exercised without real AWS
            # credentials, since the SDK is an optional dependency).
```

## Not in scope (by design)

- No pre-delivery blocking on closed platforms — impossible, not built.
- No scraping, private/unofficial endpoints, or credential automation.
- No routing of a child's content to anyone but the designated parent/guardian
  — except, if you explicitly opt into the AWS Comprehend backend above, the
  message text sent to AWS for language ID only (see the privacy note above).
- No general surveillance — this is safety-risk detection, not blanket monitoring.
