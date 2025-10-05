import express from 'express';
import cors from 'cors';
import fs from 'fs';
import { exec } from 'child_process';
import { deserializeAndRun, readProjectFile } from './vuln.js';

const app = express();

app.use(cors({ origin: '*' }));
app.use(express.json());


const STATIC_SECRET = 'jwt:supersecretkey.12345';
app.get('/secret', (req, res) => {
  res.json({ secret: STATIC_SECRET });
});

const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
  console.log('Vulnerable Demo Scanner Server listening on http://localhost:' + PORT);
});
