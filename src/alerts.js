"use strict";

/* ============================================================
   Alerting — PHASE 3.

   High-confidence flags alert immediately; borderline flags batch
   into a summary to avoid alert fatigue. Every alert carries a
   concrete next action. This layer NEVER blocks or deletes — it
   informs the parent, who decides.
   ============================================================ */

const IMMEDIATE_THRESHOLD = 0.70; // >= this -> alert now; else -> batch

// Concrete next steps. `immediate` is used for acute (>= threshold) flags,
// `review` for borderline ones. Guidance, never automated action.
const ACTIONS = {
  "grooming": {
    immediate: "This may need immediate attention. Review the conversation now and consider locking the app. If the contact is an unknown adult, preserve the messages and report to the platform and the NCMEC CyberTipline (report.cybertip.org).",
    review: "Borderline grooming signals. Review this conversation soon — watch for secrecy requests or pushes to move to another app.",
  },
  "sexual-solicitation": {
    immediate: "This may need immediate attention. Review the conversation, consider locking the app, and preserve the messages. Requests for images from a minor can be reported to the platform and NCMEC.",
    review: "Possible sexual content. Review the conversation with your child.",
  },
  "self-harm": {
    immediate: "This may need immediate attention. Talk with your child now and stay with them. If you believe they are in danger, contact a crisis line (in the US, call or text 988) or local emergency services.",
    review: "Your child's message shows possible distress. Check in with them soon.",
  },
  "violent-threat": {
    immediate: "Review the conversation. If the threat seems credible or imminent, contact the platform and, if there is immediate danger, local authorities. Save the messages.",
    review: "Possible threat language. Review the conversation.",
  },
  "harassment": {
    immediate: "Review the conversation with your child. Consider blocking the sender and reporting to the platform; save screenshots.",
    review: "Possible bullying. Included for your review — check in with your child.",
  },
};

function tierFor(confidence) {
  return confidence >= IMMEDIATE_THRESHOLD ? "immediate" : "review";
}

function suggestedAction(finding) {
  const perCat = ACTIONS[finding.category];
  if (!perCat) return "Review the conversation with your child.";
  return perCat[tierFor(finding.confidence)];
}

/* Context line: redacted excerpt + sender relationship (if known). */
function contextLine(finding) {
  const rel = {
    "not-mutual": "sender: not a mutual connection",
    "mutual": "sender: mutual connection",
    "unknown": "sender relationship unknown",
  }[finding.senderRelationship] || "sender relationship unknown";
  return `"${finding.excerpt}" · ${rel}`;
}

/* Render one finding in the required OUTPUT FORMAT. */
function formatAlert(finding) {
  const conf = finding.confidence.toFixed(2);
  return [
    `DETECTED: ${finding.category} | ${finding.language} | ${conf}`,
    `CONTEXT: ${contextLine(finding)}`,
    `SUGGESTED ACTION: ${suggestedAction(finding)}`,
  ].join("\n");
}

/* Split a message's findings into what to alert now vs. batch. */
function route(findings) {
  const immediate = [];
  const batch = [];
  for (const f of findings) {
    (f.confidence >= IMMEDIATE_THRESHOLD ? immediate : batch).push(f);
  }
  return { immediate, batch };
}

/* Roll batched (borderline) findings into a single digest. */
function formatSummary(batchedFindings, period = "daily") {
  if (batchedFindings.length === 0) {
    return `${period.toUpperCase()} SUMMARY: no borderline items to review.`;
  }
  const lines = batchedFindings.map((f, i) =>
    `  ${i + 1}. ${f.label} (${f.language}, ${f.confidence.toFixed(2)}) — ${contextLine(f)}`);
  return [
    `${period.toUpperCase()} SUMMARY — ${batchedFindings.length} borderline item(s) to review:`,
    ...lines,
    "  No immediate action needed. Review these when you can.",
  ].join("\n");
}

module.exports = { formatAlert, route, formatSummary, suggestedAction, tierFor, IMMEDIATE_THRESHOLD };
