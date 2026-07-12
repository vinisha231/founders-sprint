#!/usr/bin/env node
"use strict";

/* Test suite for the content-risk pipeline.  Run: node test.js       */

const fs = require("fs");
const path = require("path");
const { detectLanguage, detectLanguageAsync } = require("./src/language.js");
const { classify, classifyAsync } = require("./src/classifier.js");
const { redactExcerpt, MASK } = require("./src/redact.js");
const { formatAlert, route, tierFor, IMMEDIATE_THRESHOLD } = require("./src/alerts.js");
const { normalizeMessage, assertLegitimateSource } = require("./src/ingest.js");
const { processMessage, processStream, processMessageAsync, processStreamAsync } = require("./src/pipeline.js");

let pass = 0, fail = 0;
const fails = [];
function check(name, cond) {
  if (cond) pass++; else { fail++; fails.push(name); }
  console.log(`  ${cond ? "✓" : "✗"} ${name}`);
}

// Helper: classify a message and return its findings.
function find(text, opts = {}) {
  return classify({ text, direction: opts.direction || "incoming", senderRelationship: opts.rel || "unknown" }).findings;
}
const has = (findings, cat) => findings.some((f) => f.category === cat);
const conf = (findings, cat) => (findings.find((f) => f.category === cat) || {}).confidence || 0;

async function runTests() {

console.log("\nLanguage detection");
check("1. Detects English", detectLanguage("the quick brown fox and you").language === "en");
check("2. Detects Spanish", detectLanguage("no le digas a nadie que eres tan joven").language === "es");
check("3. Detects French", detectLanguage("tu es seul chez toi ce soir").language === "fr");
check("4. Detects Portuguese", detectLanguage("você não conta para os seus pais").language === "pt");
check("5. Detects German", detectLanguage("du bist so reif und ich sage nicht").language === "de");
check("6. Detects Arabic by script", detectLanguage("لا تخبر والديك").language === "ar");
check("7. Detects Russian by script", detectLanguage("хочу умереть").language === "ru");
check("8. Detects Hindi by script", detectLanguage("मैं मरना चाहता हूँ").language === "hi");
check("9. Empty string is undetermined", detectLanguage("").language === "und");

console.log("\nClassification — categories");
check("10. Grooming: multi-signal is high confidence", conf(find("you're so mature, don't tell your parents, add me on telegram", { rel: "not-mutual" }), "grooming") >= IMMEDIATE_THRESHOLD);
check("11. Grooming: single signal is borderline", (() => { const c = conf(find("what's your address?", { rel: "unknown" }), "grooming"); return c >= 0.45 && c < IMMEDIATE_THRESHOLD; })());
check("12. Sexual solicitation (English)", has(find("send me a pic", { rel: "not-mutual" }), "sexual-solicitation"));
check("13. Sexual solicitation (Spanish)", has(find("mándame fotos desnuda", { rel: "not-mutual" }), "sexual-solicitation"));
check("14. Harassment (English)", has(find("you're a worthless loser, nobody likes you"), "harassment"));
check("15. Harassment (Portuguese)", has(find("ninguém gosta de você, perdedor"), "harassment"));
check("16. Violent threat (English)", has(find("i'm going to hurt you"), "violent-threat"));
check("17. Violent threat (Spanish)", has(find("te voy a matar"), "violent-threat"));
check("17b. Violent threat: textspeak (\"imma beat u up\")", has(find("imma beat u up"), "violent-threat"));
check("17c. Violent threat: textspeak (\"ur dead\")", has(find("shut up ur dead"), "violent-threat"));

console.log("\nClassification — direction & multilingual self-harm");
check("18. Self-harm flagged on OUTGOING", has(find("i want to die", { direction: "outgoing" }), "self-harm"));
check("19. Self-harm NOT flagged on INCOMING", !has(find("i want to die", { direction: "incoming" }), "self-harm"));
check("20. Incoming 'kill yourself' is harassment, not self-harm", (() => { const f = find("kill yourself", { direction: "incoming" }); return has(f, "harassment") && !has(f, "self-harm"); })());
check("21. Self-harm (Spanish, outgoing)", has(find("quiero morirme, no puedo más", { direction: "outgoing" }), "self-harm"));
check("22. Self-harm (French, outgoing)", has(find("je veux mourir", { direction: "outgoing" }), "self-harm"));
check("23. Self-harm (German, outgoing)", has(find("ich will sterben", { direction: "outgoing" }), "self-harm"));
check("24. Self-harm (Arabic, outgoing)", has(find("أريد أن أموت", { direction: "outgoing" }), "self-harm"));
check("25. Self-harm (Russian, outgoing)", has(find("хочу умереть", { direction: "outgoing" }), "self-harm"));

console.log("\nConfidence modifiers & false positives");
check("26. not-mutual raises grooming confidence over mutual", conf(find("add me on snapchat", { rel: "not-mutual" }), "grooming") > conf(find("add me on snapchat", { rel: "mutual" }), "grooming"));
check("27. Benign message flags nothing", find("want to study for the math test tomorrow?").length === 0);
check("28. Benign Spanish flags nothing", find("vamos al cine el sábado").length === 0);
check("29. Confidence never exceeds 0.99", find("you're so mature, don't tell your parents, add me on telegram, where do you live, are you alone, send me a pic", { rel: "not-mutual" }).every((f) => f.confidence <= 0.99));

console.log("\nRedaction");
{
  const text = "please don't tell your parents about this ok";
  const f = find(text, { rel: "not-mutual" }).find((x) => x.category === "grooming");
  check("30. Excerpt contains the mask", f.excerpt.includes(MASK));
  check("31. Excerpt is shorter than the full message", f.excerpt.length < text.length + 4);
  check("32. Redaction masks the trigger span", redactExcerpt("abc SECRET def", 4, 10).includes(MASK) && !redactExcerpt("abc SECRET def", 4, 10).includes("SECRET"));
}

console.log("\nAlert routing & format");
check("33. tierFor >= threshold is immediate", tierFor(0.8) === "immediate" && tierFor(0.5) === "review");
{
  const findings = find("you're so mature, don't tell your parents, add me on telegram", { rel: "not-mutual" });
  const { immediate, batch } = route(findings);
  check("34. High-confidence grooming routes to immediate", immediate.length >= 1);
  const alert = formatAlert(immediate[0]);
  check("35. Alert has DETECTED/CONTEXT/SUGGESTED ACTION", /DETECTED:/.test(alert) && /CONTEXT:/.test(alert) && /SUGGESTED ACTION:/.test(alert));
  check("36. Alert shows language and confidence", /\| (en|es|fr|de|pt|ar|ru|hi) \| 0\.\d\d/.test(alert));
}
{
  const f = find("i can't go on", { direction: "outgoing" }).find((x) => x.category === "self-harm");
  const alert = formatAlert(f);
  check("37. Self-harm action references a crisis line, not blocking", /988|crisis/i.test(alert) && !/block|delete/i.test(alert));
}

console.log("\nIngestion guardrails");
check("38. Rejects a non-sanctioned source (scraping)", (() => { try { assertLegitimateSource("scraping"); return false; } catch { return true; } })());
check("39. Rejects a private-API source", (() => { try { assertLegitimateSource("instagram-private-api"); return false; } catch { return true; } })());
check("40. Accepts a sanctioned source", (() => { try { assertLegitimateSource("family-link"); return true; } catch { return false; } })());
check("41. normalizeMessage defaults direction to incoming", normalizeMessage({ text: "hi" }).direction === "incoming");
check("42. normalizeMessage normalizes unknown relationship", normalizeMessage({ text: "hi", senderRelationship: "bogus" }).senderRelationship === "unknown");

console.log("\nPipeline & guardrail: no network");
{
  const r = processMessage({ text: "add me on telegram and don't tell your parents", direction: "incoming", senderRelationship: "not-mutual", source: "manual" });
  check("43. processMessage returns formatted immediate alerts", r.alerts.length >= 1 && /DETECTED:/.test(r.alerts[0]));
}
{
  const messages = JSON.parse("[" + fs.readFileSync(path.join(__dirname, "examples/sample-stream.jsonl"), "utf8").trim().split("\n").join(",") + "]");
  const out = processStream(messages);
  check("44. processStream scans the sample stream", out.counts.messages === messages.length);
  check("45. Sample stream produces immediate alerts", out.counts.immediate >= 3);
  check("46. Sample stream produces a summary", /SUMMARY/.test(out.summary));
}
{
  // Static guardrail: the pipeline must not import networking or shell modules.
  const forbidden = /require\(['"](https?|net|dgram|child_process)['"]\)/;
  const srcFiles = fs.readdirSync(path.join(__dirname, "src")).map((f) => path.join(__dirname, "src", f));
  const offenders = srcFiles.filter((f) => forbidden.test(fs.readFileSync(f, "utf8")));
  check("47. No src module imports network/shell APIs", offenders.length === 0);
}

console.log("\nOptional AWS Comprehend backend — pluggable, local-fallback");
{
  // Default (no backend requested): detectLanguageAsync must behave
  // identically to the sync local heuristic it wraps.
  const sync = detectLanguage("the quick brown fox and you");
  const asyncDefault = await detectLanguageAsync("the quick brown fox and you");
  check("48. detectLanguageAsync (default) matches sync detectLanguage", asyncDefault.language === sync.language && asyncDefault.confidence === sync.confidence);
  check("49. detectLanguageAsync (default) reports local-heuristic source", asyncDefault.source === "local-heuristic");
}
{
  // aws-comprehend requested but the SDK isn't installed (it's an optional
  // dependency, not present in this checkout) -- must gracefully fall back
  // rather than throw, and must say why.
  const fallback = await detectLanguageAsync("hola que tal estas", { backend: "aws-comprehend" });
  const localOnly = detectLanguage("hola que tal estas");
  check("50. AWS backend unavailable falls back to the same language as local", fallback.language === localOnly.language);
  check("51. Fallback result reports local-heuristic source with a reason", fallback.source === "local-heuristic" && typeof fallback.fallback === "string" && /aws-comprehend/i.test(fallback.fallback));
}
{
  // classifyAsync must produce identical findings to classify() when using
  // the default backend -- the async/pluggable path is strictly additive.
  const msg = { text: "you're so mature, don't tell your parents, add me on telegram", senderRelationship: "not-mutual" };
  const syncResult = classify(msg);
  const asyncResult = await classifyAsync(msg);
  check("52. classifyAsync (default) matches classify() findings", JSON.stringify(syncResult.findings) === JSON.stringify(asyncResult.findings));
}
{
  // classifyAsync with aws-comprehend requested (falls back) must still
  // classify correctly -- a missing/failed AWS backend degrades detection
  // quality at worst, never breaks the pipeline or drops a real finding.
  const msg = { text: "you're so mature, don't tell your parents, add me on telegram", senderRelationship: "not-mutual" };
  const result = await classifyAsync(msg, { backend: "aws-comprehend" });
  check("53. classifyAsync with unavailable AWS backend still flags grooming", has(result.findings, "grooming"));
}
{
  // Full pipeline, async + aws-comprehend requested, on a single message:
  // must still produce a properly formatted immediate alert, plus a visible
  // fallback note explaining why the local heuristic was used instead.
  const r = await processMessageAsync(
    { text: "add me on telegram and don't tell your parents", direction: "incoming", senderRelationship: "not-mutual", source: "manual" },
    { backend: "aws-comprehend" }
  );
  check("54. processMessageAsync (AWS unavailable) still returns immediate alerts", r.alerts.length >= 1 && /DETECTED:/.test(r.alerts[0]));
  check("55. processMessageAsync reports the AWS fallback reason", typeof r.fallback === "string" && /aws-comprehend/i.test(r.fallback));
}
{
  // Full pipeline, async + aws-comprehend requested, on the sample stream:
  // counts must match the sync/local run exactly -- fallback is transparent
  // to the caller, not just to a single message.
  const messages = JSON.parse("[" + fs.readFileSync(path.join(__dirname, "examples/sample-stream.jsonl"), "utf8").trim().split("\n").join(",") + "]");
  const localOut = processStream(messages);
  const awsOut = await processStreamAsync(messages, "daily", { backend: "aws-comprehend" });
  check("56. processStreamAsync (AWS unavailable) matches processStream counts", JSON.stringify(localOut.counts) === JSON.stringify(awsOut.counts));
}
{
  // Unknown backend name is a real configuration error, not a silent
  // fallback -- it should surface clearly rather than being swallowed.
  let threw = false;
  try { await detectLanguageAsync("hi", { backend: "not-a-real-backend" }); }
  catch { threw = true; }
  check("57. Unknown language backend throws instead of silently succeeding", threw);
}
{
  // Detection-only boundary: the AWS SDK is referenced from exactly one
  // src module. Nothing else in src/ depends on it, so the base pipeline
  // (ingest/classify/alert) stays offline and dependency-free regardless
  // of whether the optional AWS backend is ever used.
  const srcFiles = fs.readdirSync(path.join(__dirname, "src"));
  const awsRefs = srcFiles.filter((f) => /@aws-sdk/.test(fs.readFileSync(path.join(__dirname, "src", f), "utf8")));
  check("58. Only src/aws-language.js references the AWS SDK", awsRefs.length === 1 && awsRefs[0] === "aws-language.js");
}

console.log(`\n${fail === 0 ? "✓ PASS" : "✗ FAIL"} — ${pass} passed, ${fail} failed`);
if (fail) console.log("  failed: " + fails.join(", "));
console.log("");
process.exit(fail === 0 ? 0 : 1);

}

runTests();
