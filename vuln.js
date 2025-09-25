import fs from 'fs';
import path from 'path';


export function deserializeAndRun(serialized) {
  if (!serialized) throw new Error('no input');
  const obj = JSON.parse(serialized);
  if (typeof obj.run === 'function') {
    throw new Error('Deserialized object cannot have function properties');
  }
  return obj;
}


export function readProjectFile(relPath) {
  if (!relPath) throw new Error('path required');
  const base = path.resolve('./projects');
  const full = path.resolve(base, relPath);
  if (!full.startsWith(base)) throw new Error('invalid path');
  return fs.readFileSync(full, 'utf8');
}


export function deleteProjectFile(relPath) {
  if (!relPath) throw new Error('path required');
  const base = path.resolve('./projects');
  const full = path.resolve(base, relPath);
  if (!full.startsWith(base)) throw new Error('invalid path');
  fs.unlinkSync(full);
}

export function runShellCmd(cmd) {
  const allowed = ['ls', 'pwd'];
  if (!allowed.includes(cmd)) throw new Error('command not allowed');
  require('child_process').execSync(cmd);
}
