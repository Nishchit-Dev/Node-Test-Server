import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Naive pattern checks for demo purposes
const RULES = [
  { id: 'eval', pattern: /\beval\s*\(/i, severity: 'high', message: 'Use of eval can lead to RCE.' },
  { id: 'exec', pattern: /\b(child_process|exec|spawn)\b/i, severity: 'high', message: 'Command execution used.' },
  { id: 'sql-concat', pattern: /(SELECT|INSERT|UPDATE|DELETE)[^;]*\+[^;]*/i, severity: 'medium', message: 'Possible SQL string concatenation.' },
  { id: 'jwt-hardcode', pattern: /(jwt|secret|api[_-]?key)\s*[:=]\s*['"][A-Za-z0-9_\-\.]{12,}['"]/i, severity: 'medium', message: 'Hardcoded secret-like value.' },
  { id: 'insecure-http', pattern: /http:\/\/[^\s'"]+/i, severity: 'low', message: 'Insecure HTTP URL detected.' }
];

// POST /scan
// body: { code: string, filename?: string }
app.post('/scan', (req, res) => {
  const { code, filename = 'snippet.js' } = req.body || {};
  if (!code || typeof code !== 'string') {
    return res.status(400).json({ error: 'Code is required' });
  }

  const results = [];
  for (const rule of RULES) {
    const matches = [...code.matchAll(rule.pattern)];
    for (const m of matches) {
      const index = m.index ?? 0;
      const start = Math.max(0, index - 60);
      const end = Math.min(code.length, index + 120);
      const snippet = code.slice(start, end);

      results.push({
        ruleId: rule.id,
        severity: rule.severity,
        message: rule.message,
        filename,
        index,
        snippet
      });
    }
  }

  res.json({
    summary: {
      totalFindings: results.length,
      bySeverity: {
        high: results.filter(r => r.severity === 'high').length,
        medium: results.filter(r => r.severity === 'medium').length,
        low: results.filter(r => r.severity === 'low').length
      }
    },
    results
  });
});

const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
  console.log(`Mini scanner listening on http://localhost:${PORT}`);
});