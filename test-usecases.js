#!/usr/bin/env node
"use strict";

/* Validates all 62 use cases in use-cases.js against the engine.
   One test per use case: asserts verdict + required/absent rule ids.
   Run: node test-usecases.js                                          */

const SG = require("./scanner.js");
const { SHIP_GUARD_USE_CASES: CASES } = require("./use-cases.js");

function scan(code) {
  const lines = SG.normalizeLines(code);
  const validate = SG.runValidate(code, lines);
  const secure = SG.runSecure(code, lines);
  return {
    verdict: SG.decideVerdict(validate, secure).level,
    sIds: secure.map((f) => f.id),
    vIds: validate.map((f) => f.id),
  };
}

let pass = 0, fail = 0;
const failures = [];

for (const uc of CASES) {
  const r = scan(uc.code);
  const problems = [];

  if (uc.expect.verdict && r.verdict !== uc.expect.verdict)
    problems.push(`verdict ${r.verdict} (expected ${uc.expect.verdict})`);

  for (const id of uc.expect.secure || [])
    if (!r.sIds.includes(id)) problems.push(`missing secure '${id}'`);

  for (const id of uc.expect.validate || [])
    if (!r.vIds.includes(id)) problems.push(`missing validate '${id}'`);

  for (const id of uc.expect.absent || [])
    if (r.sIds.includes(id)) problems.push(`should NOT flag '${id}'`);

  if (problems.length === 0) {
    pass++;
  } else {
    fail++;
    failures.push(`  ✗ [${uc.id}] ${uc.title}\n      ${problems.join("; ")}\n      got: secure=[${r.sIds}] validate=[${r.vIds}]`);
  }
}

console.log(`\nUse-case validation — ${CASES.length} scenarios`);
if (failures.length) console.log("\n" + failures.join("\n"));

// Coverage sanity: every secure + validate rule id should appear somewhere.
const covered = new Set();
for (const uc of CASES) (uc.expect.secure || []).concat(uc.expect.validate || []).forEach((id) => covered.add(id));
const allRuleIds = SG.SECURE_RULES.map((r) => r.id).concat(SG.VALIDATE_RULES.map((r) => r.id), ["missing-auth", "no-tests", "tests-present"]);
const uncovered = allRuleIds.filter((id) => !covered.has(id));

console.log(`\n${fail === 0 ? "✓ PASS" : "✗ FAIL"} — ${pass}/${CASES.length} use cases validated`);
if (uncovered.length) console.log(`  note: rule ids not asserted by any use case: ${uncovered.join(", ")}`);
console.log("");

process.exit(fail === 0 ? 0 : 1);
