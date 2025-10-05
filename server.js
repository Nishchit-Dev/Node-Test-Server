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
