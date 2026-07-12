"use strict";

/* ============================================================
   Pipeline — ties the three phases together.

   ingest (normalize) -> classify (multilingual) -> route (alert).
   Detect-and-inform only; nothing here blocks, deletes, or acts on
   the child's device.
   ============================================================ */

const { normalizeMessage } = require("./ingest.js");
const { classify } = require("./classifier.js");
const { route, formatAlert, formatSummary } = require("./alerts.js");

/* Process one message. Returns immediate alerts (formatted) and the
   raw borderline findings to be batched. */
function processMessage(raw) {
  const msg = normalizeMessage(raw);
  const { language, languageName, findings } = classify(msg);
  const { immediate, batch } = route(findings);
  return {
    message: { id: msg.id, platform: msg.platform, direction: msg.direction, timestamp: msg.timestamp },
    language, languageName,
    immediate,                                   // findings to alert now
    batch,                                        // findings to batch
    alerts: immediate.map(formatAlert),           // OUTPUT FORMAT strings
  };
}

/* Process a stream of messages: emit every immediate alert, and roll
   all borderline findings into one summary. */
function processStream(rawMessages, period = "daily") {
  const results = [];
  const allImmediate = [];
  const allBatch = [];

  for (const raw of rawMessages) {
    const r = processMessage(raw);
    results.push(r);
    allImmediate.push(...r.immediate);
    allBatch.push(...r.batch);
  }

  return {
    results,
    immediateAlerts: allImmediate.map(formatAlert),
    summary: formatSummary(allBatch, period),
    counts: {
      messages: rawMessages.length,
      immediate: allImmediate.length,
      batched: allBatch.length,
    },
  };
}

module.exports = { processMessage, processStream };
