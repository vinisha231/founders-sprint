"use strict";

/* ============================================================
   Ingestion — PHASE 1 (normalization only).

   This prototype consumes content the parent's app ALREADY has
   legitimate access to, and normalizes it for classification. It
   performs NO network access, NO scraping, and NO platform login.

   In a real build the upstream sources are, in priority order:
     • Google Family Link
     • Apple Screen Time / Communication Limits
     • YouTube Data API (supervised / linked accounts)
     • Platform comment-moderation APIs for the app's OWN managed account
     • On-device, explicitly-consented Android accessibility service
       (opt-in, disclosed, Android-only — no iOS equivalent exists)

   Anything requiring private/leaked endpoints, reverse-engineered
   APIs, or automated logins is OUT OF SCOPE by design — see
   assertLegitimateSource().
   ============================================================ */

const SANCTIONED_SOURCES = new Set([
  "family-link",
  "screen-time",
  "youtube-data-api",
  "comment-moderation-api",
  "android-accessibility", // opt-in, consented, Android-only
  "device-notification",   // sanctioned OS notification access
  "manual",                // pasted/typed in for testing
]);

/* Guardrail: reject sources that would require a ToS violation or
   surveillance overreach. Callers should surface the message, not
   silently continue. */
function assertLegitimateSource(source) {
  if (source == null || source === "") return; // unspecified -> treated as manual
  if (SANCTIONED_SOURCES.has(source)) return;
  throw new Error(
    `Refusing to ingest from "${source}". This system only consumes content via ` +
    `sanctioned integrations (${[...SANCTIONED_SOURCES].join(", ")}). ` +
    `Scraping, private/unofficial endpoints, and automated logins are out of scope.`
  );
}

/* Normalize a raw message into the shape the classifier expects.
   direction is relative to the CHILD: "incoming" (someone -> child)
   or "outgoing" (child -> someone). */
function normalizeMessage(raw) {
  const r = raw || {};
  assertLegitimateSource(r.source);

  const direction = r.direction === "outgoing" ? "outgoing" : "incoming";
  let rel = r.senderRelationship;
  if (rel !== "mutual" && rel !== "not-mutual") rel = "unknown";

  return {
    text: String(r.text || r.content || ""),
    direction,
    senderRelationship: rel,
    platform: r.platform || "unknown",
    source: r.source || "manual",
    timestamp: r.timestamp || new Date().toISOString(),
    id: r.id || null,
  };
}

module.exports = { normalizeMessage, assertLegitimateSource, SANCTIONED_SOURCES };
