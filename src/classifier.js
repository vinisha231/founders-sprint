"use strict";

/* ============================================================
   Classifier — PHASE 2 core.

   Given a normalized message, detect language, run the relevant
   multilingual lexicons, and return per-category findings with a
   confidence, detected language, redacted excerpt, matched signals,
   and sender relationship. NO single good/bad score — each category
   is scored independently.
   ============================================================ */

const { detectLanguage, detectLanguageAsync, NAMES } = require("./language.js");
const { ENTRIES, CATEGORY_LABELS, ANY } = require("./lexicons.js");
const { redactExcerpt } = require("./redact.js");

const MIN_CONFIDENCE = 0.45;   // below this we don't surface anything
const DETECT_UNSURE = 0.5;     // below this, scan ALL lexicons (short/keyword-only text)

// Combine independent weak signals: 1 - Π(1 - w).
function noisyOr(weights) {
  return 1 - weights.reduce((p, w) => p * (1 - w), 1);
}

/* Which lexicon entries apply for a detected language.
   Always include the detected language, language-agnostic ("any"),
   and English (global slang/loanwords show up in every language). */
function entriesForLanguage(lang) {
  return ENTRIES.filter((e) => {
    if (e.langs.includes(ANY)) return true;
    if (e.langs.includes(lang)) return true;
    if (e.langs.includes("en")) return true;
    return false;
  });
}

/* Shared core: given a message and an ALREADY-DETECTED language result
   (from either the sync local detector or the async pluggable one),
   run the lexicons and build findings. Kept separate from language
   detection so classify() (sync, local-only) and classifyAsync()
   (async, pluggable backend) share every byte of matching logic —
   the only thing that differs between them is how `lang` was
   produced. */
function classifyWithLanguage(message, lang) {
  const text = String(message && message.text || "");
  const direction = message && message.direction === "outgoing" ? "outgoing" : "incoming";
  const relationship = (message && message.senderRelationship) || "unknown";

  // Short, keyword-only messages often have no stopwords to detect from. When
  // detection is unsure, cast a wide net (all lexicons) — recall matters more
  // than precision for a safety detector — and infer the language from whatever
  // language-specific pattern actually matched.
  const unsure = lang.confidence < DETECT_UNSURE;
  const applicable = unsure ? ENTRIES : entriesForLanguage(lang.language);

  // Accumulate matches per category.
  const byCategory = {}; // cat -> { weights, signals, firstStart, firstEnd, langHint }

  for (const entry of applicable) {
    // Self-harm is only meaningful in the child's OWN outgoing messages.
    if (entry.category === "self-harm" && direction !== "outgoing") continue;

    const m = entry.re.exec(text);
    if (!m) continue;

    const bucket = byCategory[entry.category] || (byCategory[entry.category] = {
      weights: [], signals: new Set(), firstStart: m.index, firstEnd: m.index + m[0].length, langHint: null,
    });
    bucket.weights.push(entry.weight);
    if (entry.signal) bucket.signals.add(entry.signal);
    // Remember a specific (non-"any"/"en") language a pattern revealed.
    if (!bucket.langHint && !entry.langs.includes(ANY) && entry.langs[0] !== "en") {
      bucket.langHint = entry.langs[0];
    }
    if (m.index < bucket.firstStart) {
      bucket.firstStart = m.index;
      bucket.firstEnd = m.index + m[0].length;
    }
  }

  const findings = [];
  for (const [category, bucket] of Object.entries(byCategory)) {
    let confidence = noisyOr(bucket.weights);

    // Sender relationship raises confidence for stranger-driven risks.
    if ((category === "grooming" || category === "sexual-solicitation")) {
      if (relationship === "not-mutual") confidence = noisyOr([confidence, 0.2]);
      else if (relationship === "mutual") confidence *= 0.9;
    }

    confidence = Math.min(0.99, Math.round(confidence * 100) / 100);
    if (confidence < MIN_CONFIDENCE) continue;

    // If detection was unsure, trust the matched pattern's language.
    const reportLang = (unsure && bucket.langHint) ? bucket.langHint : lang.language;

    findings.push({
      category,
      label: CATEGORY_LABELS[category] || category,
      confidence,
      language: reportLang,
      languageName: NAMES[reportLang] || reportLang,
      excerpt: redactExcerpt(text, bucket.firstStart, bucket.firstEnd),
      signals: [...bucket.signals],
      senderRelationship: relationship,
      direction,
    });
  }

  // Highest-confidence category first.
  findings.sort((a, b) => b.confidence - a.confidence);
  return {
    language: lang.language,
    languageName: lang.name,
    findings,
    // Present only when the async pluggable backend produced this
    // result; undefined (and dropped by JSON.stringify) for the
    // plain sync local path so existing output/tests are unaffected.
    languageSource: lang.source,
    languageFallback: lang.fallback,
  };
}

/*
  message = {
    text: string,
    direction: "incoming" | "outgoing",   // relative to the child
    senderRelationship: "mutual" | "not-mutual" | "unknown",
    platform, timestamp, id  (optional metadata)
  }
  Returns { language, findings: [ {category, label, confidence, language,
            excerpt, signals, senderRelationship, direction} ] }

  Synchronous, local-heuristic language detection only — this is the
  default used throughout the pipeline and every existing test.
*/
function classify(message) {
  const text = String(message && message.text || "");
  const lang = detectLanguage(text);
  return classifyWithLanguage(message, lang);
}

/* Same as classify(), but detects language via the pluggable async
   backend (see detectLanguageAsync in src/language.js) — pass
   { backend: "aws-comprehend" } or set
   CONTENT_RISK_LANGUAGE_BACKEND=aws-comprehend to use Amazon
   Comprehend, with automatic fallback to the local heuristic on any
   failure. Classification itself is unaffected either way: findings
   still come from the same native-per-language lexicons. */
async function classifyAsync(message, opts = {}) {
  const text = String(message && message.text || "");
  const lang = await detectLanguageAsync(text, opts);
  return classifyWithLanguage(message, lang);
}

module.exports = { classify, classifyAsync, MIN_CONFIDENCE, noisyOr };
