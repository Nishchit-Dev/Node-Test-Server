import express from 'express';
import cors from 'cors';
import fs from 'fs';
import { exec } from 'child_process';

const app = express();

// intentionally open CORS for demo
app.use(cors({ origin: '*' }));
app.use(express.json());

// -- Vulnerable endpoints for demo scanning --

// 1) Eval endpoint - unsafe execution of user code (RCE demo)
app.post('/run-eval', (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).send('no code');

  // naive bug: using eval on user input
  try {
    const result = eval(code); // HIGH severity
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 2) Exec endpoint - runs shell commands from query param (RCE demo)
app.get('/exec', (req, res) => {
  const cmd = req.query.cmd; // user-supplied command
  if (!cmd) return res.status(400).send('cmd required');

  // insecurely passing user input to shell
  exec(cmd, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr || err.message);
    res.send(stdout);
  });
});

// 3) SQL-like endpoint - simulates vulnerable string concatenation
app.post('/user', (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username required' });

  // naive SQL concatenation (no DB here, just demonstration)
  const sql = `SELECT * FROM users WHERE name = '${username}'`; // SQL injection demo (MEDIUM)
  // pretend we executed and returned results
  res.json({ query: sql, rows: [{ id: 1, name: username }] });
});

// 4) File write endpoint - vulnerable to path traversal and arbitrary write
app.post('/save', (req, res) => {
  const { filename, content } = req.body || {};
  if (!filename || !content) return res.status(400).send('missing');

  // vulnerable: no sanitization, allows `../` to escape directory
  const path = `./data/${filename}`;
  fs.mkdirSync('./data', { recursive: true });
  fs.writeFile(path, content, (err) => {
    if (err) return res.status(500).send('write failed');
    res.send('saved');
  });
});

// 5) Hardcoded secret endpoint - exposes secret in source
const STATIC_SECRET = 'jwt:supersecretkey.12345'; // intentional hardcoded secret
app.get('/secret', (req, res) => {
  res.json({ secret: STATIC_SECRET });
});

// 6) Simple health and info
app.get('/', (req, res) => {
  res.send('Vulnerable Demo Scanner Server');
});

const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
  // minor bug: using template literal with wrong variable name sometimes
  console.log('Vulnerable Demo Scanner Server listening on http://localhost:' + PORT);
});