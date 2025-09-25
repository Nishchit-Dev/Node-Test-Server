// secure-server.mjs
import express from 'express';
import cors from 'cors';
import fs from 'fs/promises';
import path from 'path';
import { execFile } from 'child_process';
import { fileURLToPath } from 'url';
import { promisify } from 'util';

const execFileP = promisify(execFile);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

/**
 * SECURITY CHANGES SUMMARY (high-level):
 * - Remove arbitrary eval (replaced with strict calculator endpoint that only accepts numeric expressions).
 * - Replace dangerous `exec` with a whitelist executed via execFile (no shell interpolation).
 * - Prevent SQL injection by validating usernames; do NOT interpolate user input into SQL strings.
 * - Prevent directory traversal while saving/reading files; only allow safe filenames and ensure resolved path is inside allowed dir.
 * - Replace insecure deserialization endpoint with safe JSON parse endpoint (no code execution).
 * - Do NOT expose secrets from source code. Use environment variables and require a header to access secret.
 * - Limit JSON body size, restrict CORS to configured origins, and simple in-memory rate limiting.
 */

/* ---------- Config ---------- */
// Use a safe default origin or set via env
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',');
const DATA_DIR = path.resolve(__dirname, 'data');
const PROJECTS_DIR = path.resolve(__dirname, 'projects');
// Admin secret must be set in env if you want /secret to be enabled
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || null;

// Basic in-memory rate limiter (per IP)
const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX = 60; // max requests per window
const ipCounters = new Map();

function rateLimiter(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const now = Date.now();
  let entry = ipCounters.get(ip);
  if (!entry || now - entry.start >= RATE_LIMIT_WINDOW_MS) {
    entry = { start: now, count: 0 };
    ipCounters.set(ip, entry);
  }
  entry.count += 1;
  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  next();
}

/* ---------- Middleware ---------- */
// Restrict CORS to allowed origins (do NOT use '*' in production)
app.use(cors({
  origin: (origin, cb) => {
    // allow non-browser requests with no origin
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS blocked'), false);
  }
}));

app.use(express.json({ limit: '12kb' })); // limit size to mitigate large payload attacks
app.use(rateLimiter);

/* ---------- Helpers ---------- */
async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

function isSafeFilename(filename) {
  // only allow simple filenames like "name.txt" or "data-01.json"
  return /^[A-Za-z0-9_\-]{1,60}\.(txt|json)$/.test(filename);
}

function isSafeUsername(username) {
  // allow only alphanumeric + underscore, reasonable length
  return /^[A-Za-z0-9_]{1,30}$/.test(username);
}

async function safeWriteFile(dir, filename, content) {
  if (!isSafeFilename(filename)) throw new Error('invalid filename');
  const target = path.resolve(dir, filename);
  if (!target.startsWith(dir + path.sep)) throw new Error('invalid path');
  // limit content length
  if (typeof content !== 'string' || content.length > 200_000) throw new Error('content too large');
  await fs.writeFile(target, content, { encoding: 'utf8', flag: 'w' });
  return target;
}

async function safeReadFile(baseDir, relativePath) {
  // relativePath should be a simple path within baseDir
  const resolved = path.resolve(baseDir, relativePath);
  if (!resolved.startsWith(baseDir + path.sep)) throw new Error('path outside allowed directory');
  // disallow reading sensitive files by name
  const banned = ['.env', 'secrets.json', 'config.json'];
  if (banned.includes(path.basename(resolved))) throw new Error('access to file disallowed');
  return await fs.readFile(resolved, 'utf8');
}

/* ---------- Endpoints ---------- */

/**
 * Safe evaluator for simple arithmetic expressions only.
 * Accepts expressions composed of digits, whitespace and + - * / ( ) . 
 * DOES NOT allow letters or other characters.
 * Example: { "expr": " (2 + 3.5) * 4 - 10 / 2 " }
 */
app.post('/evaluate', (req, res) => {
  const { expr } = req.body || {};
  if (typeof expr !== 'string') return res.status(400).json({ error: 'expr required' });

  // Validation: only numbers, parentheses, whitespace and operators
  const safeRegex = /^[0-9+\-*/().\s]+$/;
  if (!safeRegex.test(expr)) return res.status(400).json({ error: 'expression contains invalid characters' });

  // As an extra precaution, reject very long expressions
  if (expr.length > 500) return res.status(400).json({ error: 'expression too long' });

  try {
    // Evaluate using Function in a controlled way (only math characters allowed by regex)
    // This is safe because the regex disallows letters and other dangerous tokens.
    // We convert consecutive dots that could produce weird tokens e.g. '...'
    // But the regex already allows only . so further checks could be added if desired.
    // Use parentheses and operators only.
    // eslint-disable-next-line no-new-func
    const result = Function(`"use strict"; return (${expr})`)();
    if (!Number.isFinite(result) && typeof result !== 'number') {
      return res.status(400).json({ error: 'invalid arithmetic result' });
    }
    return res.json({ result });
  } catch (e) {
    return res.status(400).json({ error: 'invalid expression', detail: e.message });
  }
});

/**
 * Safe command execution limited to a whitelist.
 * Query params:
 *   cmd=<command>
 *   args=<comma-separated-args> (optional)
 *
 * Allowed commands are intentionally tiny. We use execFile (no shell)
 * and validate each arg to avoid injections.
 */
const CMD_WHITELIST = new Set(['ls', 'pwd', 'whoami', 'date']);

app.get('/exec', async (req, res) => {
  const cmd = req.query.cmd;
  const argsRaw = req.query.args || '';
  if (!cmd) return res.status(400).send('cmd required');
  if (!CMD_WHITELIST.has(cmd)) return res.status(403).send('command not allowed');

  // parse args: comma-separated
  const args = argsRaw === '' ? [] : String(argsRaw).split(',').map(s => s.trim()).filter(Boolean);
  // validate args: allow simple tokens only
  for (const a of args) {
    if (!/^[A-Za-z0-9._\-\/]+$/.test(a) || a.length > 200) {
      return res.status(400).send('invalid arg');
    }
  }

  try {
    const { stdout } = await execFileP(cmd, args, { timeout: 5000, maxBuffer: 1024 * 100 });
    res.type('text').send(stdout);
  } catch (e) {
    res.status(500).json({ error: 'execution failed', detail: e.message });
  }
});

/**
 * User lookup - DO NOT interpolate user input into SQL strings.
 * If you have a real DB, use parameterized queries (e.g., with pg or mysql libraries).
 * Here we validate input and return a simulated row.
 */
app.post('/user', (req, res) => {
  const { username } = req.body || {};
  if (typeof username !== 'string' || !isSafeUsername(username)) {
    return res.status(400).json({ error: 'invalid username. only alphanumeric and underscore allowed' });
  }

  // Example of how a parameterized query would look (pseudocode):
  // const row = await db.query('SELECT * FROM users WHERE name = $1', [username]);
  // Don't construct SQL by concatenation.

  // Simulated response (replace with real DB call)
  return res.json({
    query: 'SELECT * FROM users WHERE name = $1',
    params: [username],
    rows: [{ id: 1, name: username }]
  });
});

/**
 * Save file - safe file writing.
 * Body: { filename, content }
 * Filename is validated (no path separators), content size limited.
 */
app.post('/save', async (req, res) => {
  const { filename, content } = req.body || {};
  if (typeof filename !== 'string' || typeof content !== 'string') return res.status(400).send('missing filename or content');

  try {
    await ensureDir(DATA_DIR);
    const target = await safeWriteFile(DATA_DIR, filename, content);
    res.json({ saved: path.relative(__dirname, target) });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/**
 * Safe JSON parse endpoint (replaces unsafe "deserialize and run"):
 * only parses JSON and returns the parsed object. Does NOT execute functions or code.
 * Body: { data: '<json-string>' }
 */
app.post('/parse-json', (req, res) => {
  const { data } = req.body || {};
  if (typeof data !== 'string') return res.status(400).json({ error: 'data string required' });
  if (data.length > 200_000) return res.status(400).json({ error: 'payload too large' });

  try {
    // JSON.parse will not execute code, it only parses JSON structures.
    const parsed = JSON.parse(data);
    // Optional: further validate parsed shape if expecting a specific schema.
    res.json({ parsed });
  } catch (e) {
    res.status(400).json({ error: 'invalid JSON', detail: e.message });
  }
});

/**
 * Read a project file safely (no traversal, no sensitive files).
 * Query param: path=<relativePathWithinProjects>
 */
app.get('/vuln/read', async (req, res) => {
  const p = req.query.path;
  if (!p || typeof p !== 'string') return res.status(400).send('path required');
  // prevent attempts to go up directories
  if (p.includes('..') || path.isAbsolute(p)) return res.status(400).send('invalid path');

  try {
    const content = await safeReadFile(PROJECTS_DIR, p);
    res.type('text').send(content);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

/**
 * Secret: return admin secret only if correct header is presented and ADMIN_TOKEN is configured.
 * Do NOT put secrets in source code. Keep in environment variables or a secrets manager.
 */
app.get('/secret', (req, res) => {
  if (!ADMIN_TOKEN) return res.status(404).json({ error: 'secret endpoint not configured' });
  const token = req.header('x-admin-token');
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  // return minimal info — avoid returning raw secret value unless truly needed.
  res.json({ message: 'authorized', secretProvided: true });
});

/* Basic health */
app.get('/', (req, res) => {
  res.send('Secure Demo Server');
});

/* Start server */
const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
  console.log(`Secure Demo Server listening on http://localhost:${PORT}`);
});
