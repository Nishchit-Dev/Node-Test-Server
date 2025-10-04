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





