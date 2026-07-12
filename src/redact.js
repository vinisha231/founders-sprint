"use strict";

/* ============================================================
   Redaction — PHASE 2 output hygiene.

   Alerts must give the parent enough context to act WITHOUT
   re-exposing the full sensitive message. We return a short
   window around the trigger, mask the trigger token itself, and
   truncate. The full original text never leaves the pipeline in
   an alert.
   ============================================================ */

const MASK = "▇▇▇";
const WINDOW = 22; // chars of context on each side of the trigger

/* Build a redacted excerpt around [start,end) within `text`.
   The matched trigger is masked; surrounding context is trimmed. */
function redactExcerpt(text, start, end) {
  const s = String(text || "");
  if (start == null || end == null || start < 0 || end > s.length || start >= end) {
    // No known trigger span: return a masked, truncated head.
    const head = s.slice(0, WINDOW).replace(/\s+/g, " ").trim();
    return (head ? head + " " : "") + MASK;
  }

  const from = Math.max(0, start - WINDOW);
  const to = Math.min(s.length, end + WINDOW);

  const before = s.slice(from, start).replace(/\s+/g, " ");
  const after = s.slice(end, to).replace(/\s+/g, " ");

  let excerpt = (from > 0 ? "…" : "") + before + MASK + after + (to < s.length ? "…" : "");
  excerpt = excerpt.trim();

  // Hard cap so alerts stay short even with wide matches.
  if (excerpt.length > 70) excerpt = excerpt.slice(0, 69).trimEnd() + "…";
  return excerpt;
}

module.exports = { redactExcerpt, MASK };
