/* ============================================================
   Ship Guard — 62 real-world use cases.

   Each entry is a realistic code scenario with the verdict/rules
   Ship Guard SHOULD produce. Used two ways:
     • the web app loads them into the scanner (use-case gallery)
     • test-usecases.js asserts each one (62 validation tests)

   expect.verdict — "block" | "warn" | "pass"
   expect.secure  — secure rule ids that MUST be present
   expect.absent  — rule ids that MUST NOT be present
   expect.validate— validate rule ids that MUST be present

   Deliberately-insecure by design — excluded from scans via
   .shipguardignore. Not real application code.
   ============================================================ */
(function (root) {
  const USE_CASES = [
    // ---------- SQL injection ----------
    {
      id: "sqli-concat", category: "SQL Injection", vuln: true,
      title: "User id concatenated into a SELECT",
      code: `const rows = db.query("SELECT * FROM users WHERE id = " + req.params.id);`,
      expect: { verdict: "block", secure: ["sql-injection"] },
    },
    {
      id: "sqli-template", category: "SQL Injection", vuln: true,
      title: "Request body interpolated into a query template",
      code: "const rows = await db.query(`SELECT * FROM orders WHERE user = ${req.body.userId}`);",
      expect: { verdict: "block", secure: ["sql-injection"] },
    },
    {
      id: "sqli-update", category: "SQL Injection", vuln: true,
      title: "UPDATE built from request body",
      code: `await db.execute("UPDATE accounts SET balance = " + req.body.amount + " WHERE id = 1");`,
      expect: { verdict: "block", secure: ["sql-injection"] },
    },
    {
      id: "sqli-parameterized", category: "SQL Injection", vuln: false,
      title: "Parameterized query with bound values (safe)",
      code: `const rows = await db.query('SELECT * FROM users WHERE id = $1', [userId]);`,
      expect: { verdict: "pass", absent: ["sql-injection"] },
    },

    // ---------- Command injection ----------
    {
      id: "cmd-exec-template", category: "Command Injection", vuln: true,
      title: "Shell command with interpolated host",
      code: "exec(`ping -c 1 ${req.query.host}`);",
      expect: { verdict: "block", secure: ["command-injection"] },
    },
    {
      id: "cmd-execsync-concat", category: "Command Injection", vuln: true,
      title: "execSync with concatenated filename",
      code: `execSync("tar -xzf " + req.body.filename);`,
      expect: { verdict: "block", secure: ["command-injection"] },
    },
    {
      id: "cmd-execfile", category: "Command Injection", vuln: false,
      title: "execFile with argument array (safe)",
      code: `execFile("tar", ["-xzf", safePath], callback);`,
      expect: { verdict: "pass", absent: ["command-injection"] },
    },

    // ---------- Secrets ----------
    {
      id: "secret-aws", category: "Secrets", vuln: true,
      title: "Hardcoded AWS access key id",
      code: `const accessKeyId = "AKIAIOSFODNN7EXAMPLE";`,
      expect: { verdict: "block", secure: ["hardcoded-secret"] },
    },
    {
      id: "secret-password", category: "Secrets", vuln: true,
      title: "Hardcoded password literal",
      code: `const password = "P@ssw0rd123";`,
      expect: { verdict: "block", secure: ["hardcoded-secret"] },
    },
    {
      id: "secret-apikey-obj", category: "Secrets", vuln: true,
      title: "API key in a config object",
      code: `const config = { apiKey: "abc123def456ghi" };`,
      expect: { verdict: "block", secure: ["hardcoded-secret"] },
    },
    {
      id: "secret-stripe", category: "Secrets", vuln: true,
      title: "Stripe live secret key",
      code: `const stripe = Stripe("sk-live-51H8xANEXAMPLEkey1234567890abcd");`,
      expect: { verdict: "block", secure: ["hardcoded-secret"] },
    },
    {
      id: "secret-github", category: "Secrets", vuln: true,
      title: "GitHub personal access token",
      code: `const token = "ghp_1234567890abcdefABCDEF1234567890abcd";`,
      expect: { verdict: "block", secure: ["hardcoded-secret"] },
    },
    {
      id: "secret-conn-string", category: "Secrets", vuln: true,
      title: "Mongo connection string with credentials",
      code: `const uri = "mongodb+srv://admin:s3cr3tPass@cluster0.mongodb.net/app";`,
      expect: { verdict: "block", secure: ["conn-string"] },
    },
    {
      id: "secret-from-env", category: "Secrets", vuln: false,
      title: "API key read from environment (safe)",
      code: `const apiKey = process.env.API_KEY;`,
      expect: { verdict: "pass", absent: ["hardcoded-secret"] },
    },

    // ---------- Broken object-level auth (IDOR) ----------
    {
      id: "idor-findbyid", category: "Broken Auth (IDOR)", vuln: true,
      title: "findById straight from the URL param",
      code: `const user = await User.findById(req.params.id);`,
      expect: { verdict: "block", secure: ["broken-object-auth"] },
    },
    {
      id: "idor-findbypk", category: "Broken Auth (IDOR)", vuln: true,
      title: "findByPk on an unchecked order id",
      code: `const order = await Order.findByPk(req.params.orderId);`,
      expect: { verdict: "block", secure: ["broken-object-auth"] },
    },
    {
      id: "idor-delete", category: "Broken Auth (IDOR)", vuln: true,
      title: "Delete by id with no ownership check",
      code: `await Invoice.delete(req.params.id);`,
      expect: { verdict: "block", secure: ["broken-object-auth"] },
    },
    {
      id: "idor-scoped", category: "Broken Auth (IDOR)", vuln: false,
      title: "Lookup scoped to the current user (safe)",
      code: `const invoice = await Invoice.findOne({ where: { id: req.params.id, ownerId: req.user.id } });`,
      expect: { verdict: "pass", absent: ["broken-object-auth"] },
    },

    // ---------- Missing authentication ----------
    {
      id: "auth-missing-delete", category: "Missing Auth", vuln: true,
      title: "DELETE route with no auth middleware",
      code: `app.delete('/api/users/:id', (req, res) => {\n  User.destroy({ where: { id: req.params.id } });\n  res.sendStatus(204);\n});`,
      expect: { verdict: "block", secure: ["missing-auth"] },
    },
    {
      id: "auth-missing-charge", category: "Missing Auth", vuln: true,
      title: "Payment route with no auth",
      code: `router.post('/charge', (req, res) => {\n  chargeCard(req.body.amount);\n  res.json({ ok: true });\n});`,
      expect: { verdict: "block", secure: ["missing-auth"] },
    },
    {
      id: "auth-present", category: "Missing Auth", vuln: false,
      title: "Route guarded by requireAuth (untested)",
      code: `app.get('/api/me', requireAuth, (req, res) => {\n  res.json({ id: req.user.id });\n});`,
      expect: { verdict: "warn", absent: ["missing-auth"] },
    },

    // ---------- XSS ----------
    {
      id: "xss-innerhtml", category: "XSS", vuln: true,
      title: "innerHTML assigned from a query param",
      code: `container.innerHTML = req.query.q;`,
      expect: { verdict: "block", secure: ["xss-innerhtml"] },
    },
    {
      id: "xss-innerhtml-concat", category: "XSS", vuln: true,
      title: "innerHTML += with user input",
      code: `el.innerHTML += "<li>" + userInput + "</li>";`,
      expect: { verdict: "block", secure: ["xss-innerhtml"] },
    },
    {
      id: "xss-doc-write", category: "XSS", vuln: true,
      title: "document.write of the URL hash",
      code: `document.write(location.hash);`,
      expect: { verdict: "block", secure: ["xss-innerhtml"] },
    },
    {
      id: "xss-react-dangerous", category: "XSS", vuln: true,
      title: "React dangerouslySetInnerHTML with user content",
      code: `<div dangerouslySetInnerHTML={{ __html: comment.body }} />`,
      expect: { verdict: "block", secure: ["xss-innerhtml"] },
    },
    {
      id: "xss-textcontent", category: "XSS", vuln: false,
      title: "textContent instead of innerHTML (safe)",
      code: `el.textContent = req.query.q;`,
      expect: { verdict: "pass", absent: ["xss-innerhtml"] },
    },

    // ---------- Path traversal ----------
    {
      id: "path-readfile", category: "Path Traversal", vuln: true,
      title: "readFile with a user-supplied path",
      code: `fs.readFile(req.query.path, "utf8", callback);`,
      expect: { verdict: "block", secure: ["path-traversal"] },
    },
    {
      id: "path-sendfile", category: "Path Traversal", vuln: true,
      title: "sendFile straight from a URL param",
      code: `res.sendFile(req.params.file);`,
      expect: { verdict: "block", secure: ["path-traversal"] },
    },
    {
      id: "path-createread", category: "Path Traversal", vuln: true,
      title: "createReadStream with concatenated name",
      code: `const s = fs.createReadStream("./uploads/" + req.body.name);`,
      expect: { verdict: "block", secure: ["path-traversal"] },
    },
    {
      id: "path-resolved", category: "Path Traversal", vuln: false,
      title: "Path resolved against a base dir (safe)",
      code: `const safe = path.resolve(UPLOAD_DIR, path.basename(req.params.file));\nconst data = fs.readFileSync(safe);`,
      expect: { verdict: "pass", absent: ["path-traversal"] },
    },

    // ---------- Transport ----------
    {
      id: "http-fetch", category: "Transport", vuln: true,
      title: "Plaintext HTTP request to a partner API",
      code: `fetch("http://api.partner.com/data");`,
      expect: { verdict: "warn", secure: ["http-url"] },
    },
    {
      id: "http-axios", category: "Transport", vuln: true,
      title: "axios GET over HTTP",
      code: `axios.get("http://internal.example.com/api");`,
      expect: { verdict: "warn", secure: ["http-url"] },
    },
    {
      id: "https-fetch", category: "Transport", vuln: false,
      title: "HTTPS request (safe)",
      code: `fetch("https://api.partner.com/data");`,
      expect: { verdict: "pass", absent: ["http-url"] },
    },

    // ---------- Cookies ----------
    {
      id: "cookie-no-flags", category: "Cookies", vuln: true,
      title: "Session cookie without HttpOnly/Secure",
      code: `res.cookie('sessionId', token, { maxAge: 3600000 });`,
      expect: { verdict: "warn", secure: ["insecure-cookie"] },
    },
    {
      id: "cookie-document", category: "Cookies", vuln: true,
      title: "Session id written to document.cookie without flags",
      code: `document.cookie = "sid=" + sessionId + "; path=/";`,
      expect: { verdict: "warn", secure: ["insecure-cookie"] },
    },
    {
      id: "cookie-secure", category: "Cookies", vuln: false,
      title: "Cookie with HttpOnly, Secure, SameSite (safe)",
      code: `res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });`,
      expect: { verdict: "pass", absent: ["insecure-cookie"] },
    },

    // ---------- Crypto ----------
    {
      id: "crypto-md5", category: "Crypto", vuln: true,
      title: "MD5 used to hash a password",
      code: `const hash = crypto.createHash('md5').update(pw).digest('hex');`,
      expect: { verdict: "warn", secure: ["weak-crypto"] },
    },
    {
      id: "crypto-sha1", category: "Crypto", vuln: true,
      title: "SHA-1 used for a signature",
      code: `const sig = crypto.createHash('sha1').update(data).digest('hex');`,
      expect: { verdict: "warn", secure: ["weak-crypto"] },
    },
    {
      id: "crypto-bcrypt", category: "Crypto", vuln: false,
      title: "bcrypt for password hashing (safe)",
      code: `const hash = await bcrypt.hash(plaintext, 12);`,
      expect: { verdict: "pass", absent: ["weak-crypto"] },
    },

    // ---------- Eval ----------
    {
      id: "eval-user", category: "Eval", vuln: true,
      title: "eval of a request body field",
      code: `const result = eval(req.body.expr);`,
      expect: { verdict: "block", secure: ["eval-use"] },
    },
    {
      id: "eval-newfunc", category: "Eval", vuln: true,
      title: "new Function built from a query param",
      code: `const fn = new Function("return " + req.query.code);`,
      expect: { verdict: "block", secure: ["eval-use"] },
    },
    {
      id: "eval-jsonparse", category: "Eval", vuln: false,
      title: "JSON.parse instead of eval (safe)",
      code: `const data = JSON.parse(req.body.payload);`,
      expect: { verdict: "pass", absent: ["eval-use"] },
    },

    // ---------- Error leakage ----------
    {
      id: "errleak-stack", category: "Error Leakage", vuln: true,
      title: "Stack trace returned to the client",
      code: `res.status(500).send(err.stack);`,
      expect: { verdict: "warn", secure: ["error-leak"] },
    },
    {
      id: "errleak-message", category: "Error Leakage", vuln: true,
      title: "Raw error message in the JSON response",
      code: `res.json({ error: err.message });`,
      expect: { verdict: "warn", secure: ["error-leak"] },
    },
    {
      id: "errleak-generic", category: "Error Leakage", vuln: false,
      title: "Generic message, details logged server-side (safe)",
      code: `logger.error(err);\nres.status(500).json({ error: 'Internal server error' });`,
      expect: { verdict: "pass", absent: ["error-leak"] },
    },

    // ---------- SSRF ----------
    {
      id: "ssrf-query-target", category: "SSRF", vuln: true,
      title: "Outbound fetch built from a query param",
      code: `fetch("https://api.example.com/" + req.query.target);`,
      expect: { verdict: "block", secure: ["ssrf"] },
    },

    // ---------- Open redirect ----------
    {
      id: "redirect-open", category: "Open Redirect", vuln: true,
      title: "Redirect target taken straight from the query string",
      code: `res.redirect(req.query.next);`,
      expect: { verdict: "warn", secure: ["open-redirect"] },
    },

    // ---------- Prototype pollution ----------
    {
      id: "proto-pollution-assign", category: "Prototype Pollution", vuln: true,
      title: "Object.assign merges req.body directly into config",
      code: `Object.assign(userConfig, req.body);`,
      expect: { verdict: "block", secure: ["prototype-pollution"] },
    },

    // ---------- Insecure deserialization ----------
    {
      id: "deserialize-pickle", category: "Insecure Deserialization", vuln: true,
      title: "pickle.loads on untrusted input",
      code: `data = pickle.loads(request.body)`,
      expect: { verdict: "block", secure: ["insecure-deserialization"] },
    },
    {
      id: "deserialize-yaml-unsafe", category: "Insecure Deserialization", vuln: true,
      title: "yaml.load without a safe loader",
      code: `config = yaml.load(uploaded_file)`,
      expect: { verdict: "block", secure: ["insecure-deserialization"] },
    },
    {
      id: "deserialize-yaml-safe", category: "Insecure Deserialization", vuln: false,
      title: "yaml.load with SafeLoader (safe)",
      code: `config = yaml.load(uploaded_file, Loader=yaml.SafeLoader)`,
      expect: { verdict: "pass", absent: ["insecure-deserialization"] },
    },

    // ---------- Weak randomness ----------
    {
      id: "weak-random-token", category: "Weak Randomness", vuln: true,
      title: "Math.random() used to build a session token",
      code: `const sessionId = "sess_" + Math.random();`,
      expect: { verdict: "warn", secure: ["weak-randomness"] },
    },
    {
      id: "strong-random-token", category: "Weak Randomness", vuln: false,
      title: "crypto.randomUUID() for a session id (safe)",
      code: `const sessionId = crypto.randomUUID();`,
      expect: { verdict: "pass", absent: ["weak-randomness"] },
    },

    // ---------- CORS misconfiguration ----------
    {
      id: "cors-wildcard-header", category: "CORS Misconfiguration", vuln: true,
      title: "Access-Control-Allow-Origin set to *",
      code: `res.setHeader('Access-Control-Allow-Origin', '*');`,
      expect: { verdict: "warn", secure: ["cors-misconfig"] },
    },
    {
      id: "cors-origin-true", category: "CORS Misconfiguration", vuln: true,
      title: "cors middleware configured with origin: true",
      code: `app.use(cors({ origin: true, credentials: true }));`,
      expect: { verdict: "warn", secure: ["cors-misconfig"] },
    },
    {
      id: "cors-allowlisted", category: "CORS Misconfiguration", vuln: false,
      title: "cors middleware with an explicit allow-listed origin (safe)",
      code: `app.use(cors({ origin: 'https://app.example.com' }));`,
      expect: { verdict: "pass", absent: ["cors-misconfig"] },
    },

    // ---------- Code smells (Validate) ----------
    {
      id: "smell-debug-enabled", category: "Code Smells", vuln: false,
      title: "Debug mode left on in server config",
      code: `const server = {\n  port: 3000,\n  debug: true,\n};`,
      expect: { verdict: "warn", validate: ["debug-mode-enabled"] },
    },
    {
      id: "smell-console", category: "Code Smells", vuln: false,
      title: "console.log left in a function",
      code: `function calculateTotal(items) {\n  console.log('items', items);\n  return items.reduce((a, b) => a + b.price, 0);\n}`,
      expect: { verdict: "warn", validate: ["console-log", "no-tests"] },
    },
    {
      id: "smell-todo", category: "Code Smells", vuln: false,
      title: "Unresolved TODO in a helper",
      code: `function applyDiscount(price) {\n  // TODO: handle promo codes\n  return price * 0.9;\n}`,
      expect: { verdict: "warn", validate: ["todo-fixme", "no-tests"] },
    },
    {
      id: "smell-empty-catch", category: "Code Smells", vuln: false,
      title: "Empty catch swallows the error",
      code: `try {\n  riskyOperation();\n} catch (e) {}`,
      expect: { verdict: "warn", validate: ["empty-catch"] },
    },

    // ---------- Clean, complete, tested ----------
    {
      id: "clean-tested-handler", category: "Clean", vuln: false,
      title: "Auth + owner-scoped query + tests",
      code: `app.get('/api/orders/:id', requireAuth, async (req, res) => {\n  const order = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });\n  if (!order) return res.status(404).json({ error: 'Not found' });\n  res.json({ id: order.id, total: order.total });\n});\n\ndescribe('GET /api/orders/:id', () => {\n  it('returns own order', () => expect(200).toBe(200));\n  it('rejects others', () => expect(404).toBe(404));\n});`,
      expect: { verdict: "pass", absent: ["missing-auth", "broken-object-auth"], validate: ["tests-present"] },
    },
    {
      id: "clean-validated-input", category: "Clean", vuln: false,
      title: "Schema-validated input with a test",
      code: `const schema = z.object({ email: z.string().email(), age: z.number().min(0) });\nfunction createUser(input) {\n  const data = schema.parse(input);\n  return db.insert('users', data);\n}\n\ntest('rejects invalid email', () => {\n  expect(() => schema.parse({ email: 'nope' })).toThrow();\n});`,
      expect: { verdict: "pass", absent: ["sql-injection"], validate: ["tests-present"] },
    },
  ];

  if (root) root.SHIP_GUARD_USE_CASES = USE_CASES;
})(typeof window !== "undefined" ? window : this);
