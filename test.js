#!/usr/bin/env node
"use strict";

/* 50 unit tests for the shared scanner engine (scanner.js).
   Run: node test.js   ·   full validation: npm test                    */

const SG = require("./scanner.js");

let pass = 0, fail = 0;
const fails = [];
function check(name, cond) {
  if (cond) { pass++; }
  else { fail++; fails.push(name); }
  console.log(`  ${cond ? "✓" : "✗"} ${name}`);
}

function scan(src) {
  const lines = SG.normalizeLines(src);
  const validate = SG.runValidate(src, lines);
  const secure = SG.runSecure(src, lines);
  return { validate, secure, verdict: SG.decideVerdict(validate, secure) };
}
const sHas = (r, id) => r.secure.some((f) => f.id === id);
const vHas = (r, id) => r.validate.some((f) => f.id === id);

console.log("\nSECURE — true positives");
check("1. SQL injection via concatenation", sHas(scan(`db.query("SELECT * FROM t WHERE id=" + req.params.id)`), "sql-injection"));
check("2. SQL injection via template literal", sHas(scan("db.query(`SELECT * FROM t WHERE id=${req.body.id}`)"), "sql-injection"));
check("3. Command injection via template", sHas(scan("exec(`ls ${req.query.dir}`)"), "command-injection"));
check("4. Command injection via concat", sHas(scan(`execSync("rm " + req.body.f)`), "command-injection"));
check("5. Hardcoded AWS key", sHas(scan(`const k = "AKIAIOSFODNN7EXAMPLE"`), "hardcoded-secret"));
check("6. Hardcoded password literal", sHas(scan(`const password = "letmein99"`), "hardcoded-secret"));
check("7. Stripe live key", sHas(scan(`const k = "sk-live-ABCD1234567890efgh"`), "hardcoded-secret"));
check("8. GitHub token", sHas(scan(`const t = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"`), "hardcoded-secret"));
check("9. Connection string with creds", sHas(scan(`const u = "postgres://user:pw@host:5432/db"`), "conn-string"));
check("10. Path traversal via readFile", sHas(scan(`fs.readFile(req.query.path)`), "path-traversal"));
check("11. Path traversal via sendFile", sHas(scan(`res.sendFile(req.params.file)`), "path-traversal"));
check("12. XSS via innerHTML", sHas(scan(`el.innerHTML = req.body.html`), "xss-innerhtml"));
check("13. XSS via document.write", sHas(scan(`document.write(location.hash)`), "xss-innerhtml"));
check("14. XSS via dangerouslySetInnerHTML", sHas(scan(`<p dangerouslySetInnerHTML={{__html: x}} />`), "xss-innerhtml"));
check("15. Broken object auth (findById)", sHas(scan(`User.findById(req.params.id)`), "broken-object-auth"));
check("16. Broken object auth (findByPk)", sHas(scan(`Order.findByPk(req.params.orderId)`), "broken-object-auth"));
check("17. Insecure HTTP call", sHas(scan(`fetch("http://api.example.com/x")`), "http-url"));
check("18. Insecure cookie", sHas(scan(`res.cookie('session', tok, { maxAge: 1 })`), "insecure-cookie"));
check("19. Weak crypto MD5", sHas(scan(`crypto.createHash('md5')`), "weak-crypto"));
check("20. Weak crypto SHA1", sHas(scan(`crypto.createHash('sha1')`), "weak-crypto"));
check("21. eval of input", sHas(scan(`const r = eval(req.body.x)`), "eval-use"));
check("22. new Function of input", sHas(scan(`const f = new Function("return " + x)`), "eval-use"));
check("23. Error leak (stack)", sHas(scan(`res.status(500).send(err.stack)`), "error-leak"));
check("24. Error leak (message)", sHas(scan(`res.json({ error: err.message })`), "error-leak"));
check("25. Missing auth on new route", sHas(scan(`app.get('/x', (req, res) => res.send('ok'))`), "missing-auth"));

console.log("\nSECURE — true negatives (no false positives)");
check("26. Parameterized query is safe", !sHas(scan(`db.query('SELECT * FROM t WHERE id=$1', [id])`), "sql-injection"));
check("27. execFile is safe", !sHas(scan(`execFile("ls", ["-la", dir])`), "command-injection"));
check("28. Env-var secret is safe", !sHas(scan(`const key = process.env.API_KEY`), "hardcoded-secret"));
check("29. textContent is safe", !sHas(scan(`el.textContent = req.body.html`), "xss-innerhtml"));
check("30. Owner-scoped findOne is safe", !sHas(scan(`Model.findOne({ where: { id: req.params.id, userId: req.user.id } })`), "broken-object-auth"));
check("31. HTTPS call is safe", !sHas(scan(`fetch("https://api.example.com/x")`), "http-url"));
check("32. localhost HTTP is not flagged", !sHas(scan(`fetch("http://localhost:3000/x")`), "http-url"));
check("33. Cookie with HttpOnly is safe", !sHas(scan(`res.cookie('session', tok, { httpOnly: true })`), "insecure-cookie"));
check("34. path.basename resolved is safe", !sHas(scan(`fs.readFileSync(path.basename(req.params.file))`), "path-traversal"));
check("35. Route with requireAuth is not missing-auth", !sHas(scan(`app.get('/x', requireAuth, (req, res) => res.send('ok'))`), "missing-auth"));

console.log("\nVALIDATE rules");
check("36. Flags console.log", vHas(scan(`function f(){ console.log(x); return 1 }`), "console-log"));
check("37. Flags TODO", vHas(scan(`function f(){ return 1 } // TODO later`), "todo-fixme"));
check("38. Flags empty catch", vHas(scan(`try { go() } catch (e) {}`), "empty-catch"));
check("39. Flags missing tests for logic", vHas(scan(`function calc(a){ return a * 2 }`), "no-tests"));
check("40. Detects tests present (describe/it)", vHas(scan(`describe('x', () => { it('works', () => {}) })`), "tests-present"));
check("41. Detects tests present (test/expect)", vHas(scan(`test('x', () => { expect(1).toBe(1) })`), "tests-present"));
check("42. No false console.log on clean code", !vHas(scan(`const x = compute(2)`), "console-log"));

console.log("\nVERDICT logic");
check("43. Critical secret => block", scan(`const k = "AKIAIOSFODNN7EXAMPLE"`).verdict.level === "block");
check("44. High finding => block", scan(`el.innerHTML = req.body.x`).verdict.level === "block");
check("45. Medium-only secure => warn", scan(`fetch("http://api.example.com/x")`).verdict.level === "warn");
check("46. Validate med (empty catch) => warn", scan(`try { go() } catch (e) {}`).verdict.level === "warn");
check("47. Clean non-logic => pass", scan(`const total = a + b`).verdict.level === "pass");

console.log("\nDIFF handling");
{
  const added = `--- a/f.js\n+++ b/f.js\n@@ -1,1 +1,2 @@\n const x=1;\n+const k = "AKIAIOSFODNN7EXAMPLE";`;
  check("48. Scans added diff lines", sHas(scan(added), "hardcoded-secret"));
  const removed = `--- a/f.js\n+++ b/f.js\n@@ -1,2 +1,1 @@\n-const k = "AKIAIOSFODNN7EXAMPLE";\n const x=1;`;
  check("49. Ignores removed diff lines", !sHas(scan(removed), "hardcoded-secret"));
}

console.log("\nREPORT format");
{
  const r = scan(`db.query("SELECT * FROM t WHERE id=" + req.params.id)`);
  const report = SG.buildShipReport(r.verdict, r.validate, r.secure);
  check("50. Ship report has BUILD/VALIDATE/SECURE + human-review flag",
    /BUILD:/.test(report) && /VALIDATE:/.test(report) && /SECURE:/.test(report) && /human review/i.test(report));
}

console.log(`\n${fail === 0 ? "✓ PASS" : "✗ FAIL"} — ${pass} passed, ${fail} failed`);
if (fail) console.log("  failed: " + fails.join(", "));
console.log("");
process.exit(fail === 0 ? 0 : 1);
