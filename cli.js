#!/usr/bin/env node
"use strict";

/* ============================================================
   content-risk — CLI for the detection/alerting pipeline.

   Usage:
     content-risk "message text"          classify one message
     content-risk --file msgs.jsonl       classify a stream (one JSON per line)
     echo "text" | content-risk           read from stdin

   Options:
     --direction incoming|outgoing        default: incoming (relative to child)
     --relationship mutual|not-mutual|unknown   default: unknown
     --platform <name>                    e.g. instagram (metadata only)
     --period daily|weekly                summary window label (default: daily)
     --json                               machine-readable output
     --use-aws                            detect language via Amazon Comprehend
                                           instead of the local heuristic (falls
                                           back to local automatically on any
                                           AWS failure). Also enabled by setting
                                           CONTENT_RISK_LANGUAGE_BACKEND=aws-comprehend.
                                           Sends message text to AWS for language
                                           ID only — see src/aws-language.js.
     --help

   Detect-and-inform only: this tool never blocks, deletes, or acts
   on a child's device. The parent decides.
   ============================================================ */

const fs = require("fs");
const { processMessage, processStream, processMessageAsync, processStreamAsync } = require("./src/pipeline.js");

function parseArgs(argv) {
  const opts = { direction: "incoming", relationship: "unknown", platform: "unknown", period: "daily", json: false, useAws: false };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") opts.json = true;
    else if (a === "--use-aws") opts.useAws = true;
    else if (a === "--help" || a === "-h") opts.help = true;
    else if (a === "--file") opts.file = argv[++i];
    else if (a === "--direction") opts.direction = argv[++i];
    else if (a === "--relationship") opts.relationship = argv[++i];
    else if (a === "--platform") opts.platform = argv[++i];
    else if (a === "--period") opts.period = argv[++i];
    else positional.push(a);
  }
  opts.text = positional.join(" ");
  return opts;
}

function readStdin() {
  try { return fs.readFileSync(0, "utf8"); } catch { return ""; }
}

function banner() {
  process.stdout.write("🛡  Content-Risk Detector — detect & alert only (never blocks; the parent decides)\n\n");
}

function printSingle(result, json) {
  if (json) { process.stdout.write(JSON.stringify(result, null, 2) + "\n"); return; }
  process.stdout.write(`language: ${result.languageName} (${result.language})\n`);
  if (result.fallback) {
    process.stdout.write(`note: ${result.fallback}\n`);
  }
  if (result.alerts.length === 0 && result.batch.length === 0) {
    process.stdout.write("No risk categories flagged.\n");
    return;
  }
  if (result.alerts.length) {
    process.stdout.write("\n── IMMEDIATE ALERT ──\n");
    process.stdout.write(result.alerts.join("\n\n") + "\n");
  }
  if (result.batch.length) {
    const { formatSummary } = require("./src/alerts.js");
    process.stdout.write("\n" + formatSummary(result.batch) + "\n");
  }
}

function loadJsonl(file) {
  return fs.readFileSync(file, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l, i) => {
      try { return JSON.parse(l); }
      catch { throw new Error(`Invalid JSON on line ${i + 1} of ${file}`); }
    });
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help) {
    process.stdout.write(fs.readFileSync(__filename, "utf8").split("Usage:")[1].split("========")[0].replace(/\n   /g, "\n").trimEnd() + "\n");
    return;
  }

  const backendOpts = opts.useAws ? { backend: "aws-comprehend" } : {};

  // Stream mode.
  if (opts.file) {
    const messages = loadJsonl(opts.file);
    const out = opts.useAws
      ? await processStreamAsync(messages, opts.period, backendOpts)
      : processStream(messages, opts.period);
    if (opts.json) { process.stdout.write(JSON.stringify(out, null, 2) + "\n"); return; }
    banner();
    process.stdout.write(`Scanned ${out.counts.messages} message(s): ${out.counts.immediate} immediate, ${out.counts.batched} batched.\n`);
    if (out.immediateAlerts.length) {
      process.stdout.write("\n══ IMMEDIATE ALERTS ══\n\n" + out.immediateAlerts.join("\n\n") + "\n");
    }
    process.stdout.write("\n" + out.summary + "\n");
    return;
  }

  // Single-message mode (arg or stdin).
  let text = opts.text;
  if (!text) text = readStdin().trim();
  if (!text) {
    process.stderr.write("No input. Pass a message, --file <jsonl>, or pipe text on stdin. Try --help.\n");
    process.exit(2);
  }

  const messageInput = {
    text,
    direction: opts.direction,
    senderRelationship: opts.relationship,
    platform: opts.platform,
    source: "manual",
  };
  const result = opts.useAws
    ? await processMessageAsync(messageInput, backendOpts)
    : processMessage(messageInput);
  if (!opts.json) banner();
  printSingle(result, opts.json);
}

main().catch((err) => {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
});
