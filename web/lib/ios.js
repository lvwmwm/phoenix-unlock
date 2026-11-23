import { entryData, readZip, storedEntry, writeZip } from './zip.js';

const FRAMEWORK_SUFFIX = 'PhoenixFatClient.framework/PhoenixFatClient';
const JS_BUNDLE = 'Payload/Discord.app/main.jsbundle';
const MH_MAGIC_64 = 0xfeedfacf;
const CPU_TYPE_ARM64 = 0x0100000c;

const ANCHOR = hex('090140f93f0900f1c000005408a947f91f0500b16000005408b4503968000036');
const PATCH = hex('20008052c0035fd6'); // mov w0, #1; ret
const STAFF_SIG = hex('8901029300d506010093013402003b020203450502002213');
const STAFF_PATCH = hex('95017601'); // LoadConstTrue r1; Ret r1

function hex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function findAll(haystack, needle) {
  const hits = [], n = needle.length;
  outer: for (let i = 0; i + n <= haystack.length; i++) {
    for (let j = 0; j < n; j++) if (haystack[i + j] !== needle[j]) continue outer;
    hits.push(i);
    i += n - 1;
  }
  return hits;
}

/** Verify thin arm64, unencrypted; patch both gates. Returns a new Uint8Array. */
export function patchMachO(u8) {
  if (u8.length < 32) throw new Error('PhoenixFatClient binary is too small');
  const v = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  if (v.getUint32(0, true) !== MH_MAGIC_64) throw new Error('not a 64-bit Mach-O');
  if (v.getUint32(4, true) !== CPU_TYPE_ARM64) throw new Error('not arm64');
  if (v.getUint32(8, true) & 0x00ffffff) {
    throw new Error('arm64e binary — pointer authentication needs different handling');
  }

  // LC_ENCRYPTION_INFO / _64 with a nonzero cryptid means FairPlay encryption.
  const ncmds = v.getUint32(16, true);
  let off = 32;
  for (let i = 0; i < ncmds; i++) {
    const cmd = v.getUint32(off, true), size = v.getUint32(off + 4, true);
    if (cmd === 0x1f || cmd === 0x21) {
      if (v.getUint32(off + 16, true) !== 0) {
        throw new Error('the IPA is encrypted — decrypt it first (e.g. TrollDecrypt)');
      }
    }
    off += size;
  }

  const hits = findAll(u8, ANCHOR);
  if (hits.length !== 2) {
    throw new Error(`expected 2 gate evaluators, found ${hits.length} — unsupported build`);
  }
  const out = u8.slice();
  for (const at of hits) out.set(PATCH, at - 8);
  return out;
}

/** Force Hermes `isStaffEnv` to return true. */
function patchStaff(u8) {
  const hits = findAll(u8, STAFF_SIG);
  if (hits.length !== 1) throw new Error(`expected 1 isStaffEnv signature, found ${hits.length}`);
  const out = u8.slice();
  out.set(STAFF_PATCH, hits[0]);
  return out;
}

/** Take a decrypted IPA's bytes, return ZIP parts ready for a Blob. */
export async function buildPatchedIpa(u8, log = () => {}) {
  const entries = readZip(u8);
  const idx = entries.findIndex(
    (e) => e.name.includes('/Frameworks/') && e.name.endsWith(FRAMEWORK_SUFFIX)
  );
  if (idx < 0) throw new Error('PhoenixFatClient.framework not found in the IPA');
  const entry = entries[idx];
  log(`found ${entry.name} (${(entry.usize / 1048576).toFixed(1)} MB)`);

  entries[idx] = storedEntry(entry.name, patchMachO(await entryData(entry)));
  log('patched 2 access evaluators: 0x1bc4c94, 0x1bc4ce4');

  const jsIdx = entries.findIndex((e) => e.name === JS_BUNDLE);
  if (jsIdx >= 0) {
    entries[jsIdx] = storedEntry(JS_BUNDLE, patchStaff(await entryData(entries[jsIdx])));
    log('forced isStaffEnv to true (Discord experiments enabled)');
  }

  const { parts } = writeZip(entries);
  return parts;
}
