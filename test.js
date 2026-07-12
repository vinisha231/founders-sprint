#!/usr/bin/env node
"use strict";

/* Minimal test suite for the shared scanner engine.
   Run: node test.js  (or) npm test                                    */

const SG = require("./scanner.js");

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log("  ✓ " + name); }
  else { fail++; console.log("  ✗ " + name); }
}

function scan(src) {
  const lines = SG.normalizeLines(src);
  const validate = SG.runValidate(src, lines);
  const secure = SG.runSecure(src, lines);
  return { validate, secure, verdict: SG.decideVerdict(validate, secure) };
}
const hasId = (arr, id) => arr.some((f) => f.id === id);

console.log("\nSECURE rules");
{
  const r = scan(`const invoice = db.query("SELECT * FROM invoices WHERE id = " + req.params.id);`);
  check("flags SQL injection", hasId(r.secure, "sql-injection"));
}
{
  const r = scan(`const note = Invoice.findById(req.params.id);`);
  check("flags broken object-level auth (IDOR)", hasId(r.secure, "broken-object-auth"));
}
{
  const r = scan(`const apiKey = "AKIAIOSFODNN7EXAMPLE";`);
  check("flags hardcoded AWS key", hasId(r.secure, "hardcoded-secret"));
}
{
  const r = scan(`const url = "postgres://admin:SuperSecret123@db.internal:5432/app";`);
  check("flags connection string with creds", hasId(r.secure, "conn-string"));
}
{
  const r = scan(`app.get('/api/x', (req, res) => { res.send('ok'); });`);
  check("flags new route with no auth", hasId(r.secure, "missing-auth"));
}
{
  const r = scan(`fetch('http://payments.partner.com/charge');`);
  check("flags insecure http:// call", hasId(r.secure, "http-url"));
}
{
  const r = scan(`el.innerHTML = req.body.text;`);
  check("flags XSS via innerHTML", hasId(r.secure, "xss-innerhtml"));
}

console.log("\nVALIDATE rules");
{
  const r = scan(`function foo() { console.log('debug'); return 1; }`);
  check("flags leftover console.log", hasId(r.validate, "console-log"));
}
{
  const r = scan(`function foo() { return 1; } // TODO fix this`);
  check("flags TODO", hasId(r.validate, "todo-fixme"));
}
{
  const r = scan(`function foo() { return 1; }`);
  check("flags missing tests for logic", hasId(r.validate, "no-tests"));
}

console.log("\nVerdicts & false-positives");
{
  const clean = `app.get('/x', requireAuth, async (req,res) => {
    const row = await Model.findOne({ where: { id: req.params.id, ownerId: req.user.id } });
    res.json({ id: row.id });
  });
  describe('x', () => { it('works', () => expect(1).toBe(1)); });`;
  const r = scan(clean);
  check("clean owner-scoped + auth + tests => not blocked", r.verdict.level !== "block");
  check("clean code raises no secure findings", r.secure.filter(f => f.severity !== "ok").length === 0);
}
{
  const r = scan(`el.textContent = req.body.text;`);
  check("textContent is NOT flagged as XSS", !hasId(r.secure, "xss-innerhtml"));
}
{
  const r = scan(`fetch('http://localhost:3000/api');`);
  check("localhost http is NOT flagged", !hasId(r.secure, "http-url"));
}

console.log("\nDiff handling");
{
  const diff = `--- a/app.js
+++ b/app.js
@@ -1,2 +1,3 @@
 const x = 1;
-const safe = 2;
+const apiKey = "sk-live-abcdef1234567890";`;
  const r = scan(diff);
  check("scans added diff lines", hasId(r.secure, "hardcoded-secret"));

  const diff2 = `--- a/app.js
+++ b/app.js
@@ -1,2 +1,1 @@
-const apiKey = "AKIAIOSFODNN7EXAMPLE";
 const x = 1;`;
  const r2 = scan(diff2);
  check("ignores REMOVED diff lines", !hasId(r2.secure, "hardcoded-secret"));
}

console.log(`\n${fail === 0 ? "✓ PASS" : "✗ FAIL"} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
