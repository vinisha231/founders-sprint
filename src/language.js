"use strict";

/* ============================================================
   Language detection — PHASE 2, step 1.

   Runs BEFORE classification so we never assume English. Two
   stages: (1) script detection for non-Latin writing systems,
   (2) stopword-frequency scoring for Latin-script languages.

   Dependency-free and deterministic. This is a lightweight
   detector for routing to the right lexicons — a production
   build would swap in a trained model (e.g. fastText lid.176),
   but the classifier interface stays identical.

   detectLanguage() (below) is the synchronous, always-available,
   fully local default — it's what classify()/processMessage() use
   and what every existing test exercises. detectLanguageAsync()
   is an OPT-IN pluggable wrapper: set
   CONTENT_RISK_LANGUAGE_BACKEND=aws-comprehend to route detection
   through Amazon Comprehend (src/aws-language.js) instead, with an
   automatic, silent-to-the-caller fallback to this same local
   heuristic if the AWS SDK isn't installed, credentials aren't
   configured, or the call fails for any reason. Detection-only —
   classification still runs natively per language; nothing here
   translates message text before classifying it.
   ============================================================ */

// Non-Latin scripts map straight to a language via Unicode ranges.
const SCRIPTS = [
  { lang: "ar", name: "Arabic", re: /[؀-ۿ]/ },
  { lang: "ru", name: "Russian", re: /[Ѐ-ӿ]/ },
  { lang: "hi", name: "Hindi", re: /[ऀ-ॿ]/ },
  { lang: "zh", name: "Chinese", re: /[一-鿿]/ },
  { lang: "ko", name: "Korean", re: /[가-힯]/ },
  { lang: "ja", name: "Japanese", re: /[぀-ヿ]/ },
  { lang: "he", name: "Hebrew", re: /[֐-׿]/ },
  { lang: "th", name: "Thai", re: /[฀-๿]/ },
  { lang: "el", name: "Greek", re: /[Ͱ-Ͽ]/ },
];

// Common function words per Latin-script language.
const STOPWORDS = {
  en: ["the", "and", "you", "to", "is", "of", "in", "that", "it", "for", "are", "your", "on", "do"],
  es: ["que", "de", "la", "el", "no", "en", "y", "los", "se", "un", "por", "con", "tu", "para", "eres"],
  fr: ["le", "la", "les", "et", "de", "un", "une", "je", "tu", "ne", "pas", "est", "que", "on", "chez", "toi", "moi", "avec", "vous", "ça", "où", "ton", "ta", "suis"],
  pt: ["que", "de", "não", "o", "a", "e", "um", "uma", "você", "com", "para", "os", "eu", "tá"],
  de: ["der", "die", "das", "und", "ist", "nicht", "du", "ich", "ein", "eine", "zu", "mit", "wie", "bist"],
  it: ["che", "di", "il", "la", "e", "non", "un", "per", "con", "sono", "ti", "sei", "ho"],
};

const NAMES = {
  en: "English", es: "Spanish", fr: "French", pt: "Portuguese",
  de: "German", it: "Italian", und: "Undetermined",
};

/* Returns { language, name, confidence }.  `language` is an ISO-ish code;
   "und" when nothing scores above noise. */
function detectLanguage(text) {
  const s = String(text || "");
  if (s.trim() === "") return { language: "und", name: NAMES.und, confidence: 0 };

  // 1) Script detection wins outright for non-Latin writing systems.
  for (const script of SCRIPTS) {
    if (script.re.test(s)) {
      return { language: script.lang, name: script.name, confidence: 0.95 };
    }
  }

  // 2) Stopword frequency for Latin scripts.
  const tokens = s.toLowerCase().match(/[\p{L}']+/gu) || [];
  if (tokens.length === 0) return { language: "und", name: NAMES.und, confidence: 0 };

  const counts = {};
  for (const lang of Object.keys(STOPWORDS)) counts[lang] = 0;
  const wordSets = {};
  for (const [lang, words] of Object.entries(STOPWORDS)) wordSets[lang] = new Set(words);

  for (const tok of tokens) {
    if (tok.length < 2) continue; // 1-char words (a, o, y, e) are ambiguous across languages
    for (const lang of Object.keys(wordSets)) {
      if (wordSets[lang].has(tok)) counts[lang]++;
    }
  }

  let best = "und", bestScore = 0, total = 0;
  for (const [lang, c] of Object.entries(counts)) {
    total += c;
    if (c > bestScore) { bestScore = c; best = lang; }
  }

  if (bestScore === 0) {
    // No stopword hits: default to English (Latin script) but low confidence.
    return { language: "en", name: NAMES.en, confidence: 0.3 };
  }

  const confidence = Math.min(0.95, 0.4 + (bestScore / tokens.length) * 2 + (bestScore / Math.max(total, 1)) * 0.2);
  return { language: best, name: NAMES[best] || best, confidence: Math.round(confidence * 100) / 100 };
}

const DEFAULT_BACKEND = "local";
const BACKEND_ENV_VAR = "CONTENT_RISK_LANGUAGE_BACKEND";

/* Async, pluggable detection. Returns the same shape as detectLanguage()
   plus a `source` field ("local-heuristic" or "aws-comprehend") and,
   when a remote backend was requested but unavailable, a `fallback`
   note explaining why. Never throws — a failed remote call always
   degrades to the local heuristic rather than breaking the pipeline. */
async function detectLanguageAsync(text, opts = {}) {
  const backend = opts.backend || process.env[BACKEND_ENV_VAR] || DEFAULT_BACKEND;

  if (backend === "local") {
    return { ...detectLanguage(text), source: "local-heuristic" };
  }

  if (backend === "aws-comprehend") {
    try {
      // Lazy require: keeps this module (and its callers) loadable and
      // testable with zero network/SDK dependency when AWS isn't in use.
      const { detectLanguageAWS } = require("./aws-language.js");
      return await detectLanguageAWS(text);
    } catch (err) {
      return {
        ...detectLanguage(text),
        source: "local-heuristic",
        fallback: `aws-comprehend unavailable: ${err.message}`,
      };
    }
  }

  throw new Error(`Unknown language backend "${backend}". Use "local" or "aws-comprehend".`);
}

module.exports = { detectLanguage, detectLanguageAsync, NAMES, STOPWORDS, SCRIPTS, DEFAULT_BACKEND, BACKEND_ENV_VAR };
