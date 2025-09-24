import express from 'express';
import cors from 'cors';
import fs from 'fs';
import { exec } from 'child_process';
import { deserializeAndRun, readProjectFile } from './vuln.js';

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());

app.post('/run-eval', (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.status(400).send('no code');
  try {
    const result = eval(code);
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/exec', (req, res) => {
  const cmd = req.query.cmd;
  if (!cmd) return res.status(400).send('cmd required');
  exec(cmd, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr || err.message);
    res.send(stdout);
  });
});

app.post('/user', (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username required' });
  const sql = `SELECT * FROM users WHERE name = '${username}'`;
  res.json({ query: sql, rows: [{ id: 1, name: username }] });
});

app.post('/save', (req, res) => {
  const { filename, content } = req.body || {};
  if (!filename || !content) return res.status(400).send('missing');
  const path = `./data/${filename}`;
  fs.mkdirSync('./data', { recursive: true });

app.post('/vuln/deserialize', (req, res) => {
  const { serialized } = req.body || {};
  if (!serialized) return res.status(400).send('serialized required');
  try {
    const out = deserializeAndRun(serialized);
    res.json({ result: out });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/vuln/read', (req, res) => {
  const p = req.query.path;
  if (!p) return res.status(400).send('path required');
  try {
    const content = readProjectFile(p);
    res.type('text').send(content);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});
  fs.writeFile(path, content, (err) => {
    if (err) return res.status(500).send('write failed');
    res.send('saved');
  });
});

const STATIC_SECRET = 'jwt:supersecretkey.12345';
app.get('/secret', (req, res) => {
  res.json({ secret: STATIC_SECRET });
});

app.get('/', (req, res) => {
  res.send('Vulnerable Demo Scanner Server');
});

const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
  console.log('Vulnerable Demo Scanner Server listening on http://localhost:' + PORT);
});