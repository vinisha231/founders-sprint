/* Demo fixtures for the Ship Guard web app. These deliberately contain
   insecure code so the scanner has something to catch — they are NOT real
   application code. Excluded from scans via .shipguardignore. */
(function (root) {
  const SAMPLES = {
    vulnerable: `// PATCH: add endpoint to fetch an invoice
app.get('/api/invoices/:id', (req, res) => {
  const id = req.params.id;
  const invoice = db.query(
    "SELECT * FROM invoices WHERE id = " + id
  );
  res.json(invoice);
});

app.post('/api/invoices/:id/notes', (req, res) => {
  const note = Invoice.findById(req.params.id);
  note.text = req.body.text;
  note.save();
  res.send('<div>' + req.body.text + '</div>');
});`,

    secrets: `const stripe = require('stripe')('sk-live-4eC39Hq8f2a9bXcVdE1234567890');

const config = {
  dbUrl: "postgres://admin:SuperSecret123@db.internal:5432/app",
  apiKey: "AKIAIOSFODNN7EXAMPLE",
  jwtSecret: "hunter2hunter2hunter2",
};

fetch('http://payments.partner.com/charge', { method: 'POST' });

res.cookie('session', token, { maxAge: 900000 });`,

    clean: `// PATCH: fetch the current user's invoice
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({ windowMs: 60000, max: 30 });

app.get('/api/invoices/:id', requireAuth, limiter, async (req, res) => {
  try {
    const invoice = await Invoice.findOne({
      where: { id: req.params.id, ownerId: req.user.id },
    });
    if (!invoice) return res.status(404).json({ error: 'Not found' });
    res.json({ id: invoice.id, total: invoice.total, status: invoice.status });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});

// tests/invoices.test.js
describe('GET /api/invoices/:id', () => {
  it('returns the owner\\'s invoice', async () => { expect(200).toBe(200); });
  it('rejects another user\\'s invoice', async () => { expect(404).toBe(404); });
  it('requires auth', async () => { expect(401).toBe(401); });
});`,
  };

  if (root) root.SHIP_GUARD_SAMPLES = SAMPLES;
})(typeof window !== "undefined" ? window : this);
