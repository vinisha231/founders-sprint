"use strict";

/* ============================================================
   AWS Comprehend-backed language detection — OPTIONAL backend.

   This is a pluggable alternative to the local heuristic detector
   in src/language.js. It is never required: if the AWS SDK isn't
   installed, credentials aren't configured, or the call fails for
   any reason, callers are expected to catch and fall back to the
   local heuristic (see detectLanguageAsync() in src/language.js,
   which does exactly this).

   Why Comprehend and not Translate: DetectDominantLanguage is
   purpose-built for language ID — cheaper and more accurate on
   short text than paying for a translation call just to read back
   its source-language side effect.

   Enable with: CONTENT_RISK_LANGUAGE_BACKEND=aws-comprehend
   Requires: @aws-sdk/client-comprehend — an OPTIONAL dependency
   (see package.json), lazy-required below so the base install and
   `npm test` stay offline and dependency-free by default. Also
   requires standard AWS credential resolution (env vars, shared
   config/profile, or an IAM role).

   PRIVACY NOTE: enabling this backend sends the raw message text
   (untruncated beyond a 5000-char safety cap) to AWS for language
   identification. That is content leaving the device to a third-
   party processor — a real deployment needs its own disclosure to
   parents and an appropriate data-processing agreement with AWS;
   this module does not make that decision for you, it only makes
   the integration possible if you've made that call. It does not
   change what SOURCES are legitimate to ingest from (see
   src/ingest.js) — it only changes how already-ingested text gets
   its language identified.
   ============================================================ */

const { NAMES: LOCAL_NAMES } = require("./language.js");

class AwsLanguageUnavailableError extends Error {}

let cachedClient = null;

function getClient() {
  if (cachedClient) return cachedClient;
  let ComprehendClient, DetectDominantLanguageCommand;
  try {
    ({ ComprehendClient, DetectDominantLanguageCommand } = require("@aws-sdk/client-comprehend"));
  } catch (err) {
    throw new AwsLanguageUnavailableError(
      "@aws-sdk/client-comprehend is not installed. Run `npm install @aws-sdk/client-comprehend` " +
      "to enable the AWS-backed language detector, or unset CONTENT_RISK_LANGUAGE_BACKEND to use " +
      "the local heuristic instead."
    );
  }
  cachedClient = {
    client: new ComprehendClient({ region: process.env.AWS_REGION || "us-east-1" }),
    DetectDominantLanguageCommand,
  };
  return cachedClient;
}

/* Async. Returns { language, name, confidence, source: "aws-comprehend" }.
   Throws AwsLanguageUnavailableError (SDK missing) or whatever error the
   AWS SDK raises (bad/missing credentials, network failure, throttling,
   etc.) — this module never fails silently into a wrong answer. Callers
   (see detectLanguageAsync in src/language.js) are responsible for
   catching and falling back to the local heuristic. */
async function detectLanguageAWS(text) {
  const s = String(text || "").trim();
  if (!s) return { language: "und", name: "Undetermined", confidence: 0, source: "aws-comprehend" };

  const { client, DetectDominantLanguageCommand } = getClient();
  const result = await client.send(new DetectDominantLanguageCommand({ Text: s.slice(0, 5000) }));
  const langs = result.Languages || [];
  if (langs.length === 0) {
    return { language: "und", name: "Undetermined", confidence: 0, source: "aws-comprehend" };
  }

  const top = langs.reduce((a, b) => (b.Score > a.Score ? b : a));
  const code = String(top.LanguageCode || "und").split("-")[0]; // e.g. "zh-TW" -> "zh"
  return {
    language: code,
    name: LOCAL_NAMES[code] || code,
    confidence: Math.round(top.Score * 100) / 100,
    source: "aws-comprehend",
  };
}

module.exports = { detectLanguageAWS, AwsLanguageUnavailableError };
