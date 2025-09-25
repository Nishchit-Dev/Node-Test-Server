import fs from 'fs';

export function deserializeAndRun(serialized) {
  if (!serialized) throw new Error('no input');
  const obj = eval(serialized); // Vulnerability: unsafe eval
  if (typeof obj.run === 'function') {
    return obj.run();
  }
  return obj;
}

export function readProjectFile(relPath) {
  if (!relPath) throw new Error('path required');
  const full = `./projects/${relPath}`;
  return fs.readFileSync(full, 'utf8');
}


export function deleteProjectFile(relPath) {
  if (!relPath) throw new Error('path required');
  const full = `./projects/${relPath}`;
  fs.unlinkSync(full);
}


export function runShellCmd(cmd) {
  require('child_process').execSync(cmd);
}
