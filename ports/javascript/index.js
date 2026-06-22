#!/usr/bin/env node
// JavaScript port of the UEFISCAN core check: locate EFI firmware volumes,
// detect Secure Boot key variables, count unsigned PE/TE modules.
// Passive/offline only — analyses a firmware dump you already have. No network.
import { readFileSync } from "fs";

const SECUREBOOT_VARS = ["PK", "KEK", "db", "dbx"];
const REQUIRED_VARS = ["PK", "KEK", "db"];

function utf16le(s) {
  const b = Buffer.alloc(s.length * 2);
  for (let i = 0; i < s.length; i++) b.writeUInt16LE(s.charCodeAt(i), i * 2);
  return b;
}

export function findFirmwareVolumes(data) {
  const out = [];
  const sig = Buffer.from("_FVH", "ascii");
  let search = 0;
  for (;;) {
    const idx = data.indexOf(sig, search);
    if (idx === -1) break;
    const fvStart = idx - 40;
    if (fvStart >= 0 && fvChecksumOk(data, fvStart)) out.push(fvStart);
    search = idx + 1;
  }
  return out;
}

function fvChecksumOk(data, fvStart) {
  if (fvStart + 64 > data.length) return false;
  const headerLen = data.readUInt16LE(fvStart + 48);
  if (headerLen < 56 || headerLen % 2 !== 0 || fvStart + headerLen > data.length)
    return false;
  let total = 0;
  for (let i = 0; i < headerLen; i += 2) total = (total + data.readUInt16LE(fvStart + i)) & 0xffff;
  return total === 0;
}

export function findSecureBootVars(data) {
  const out = {};
  for (const name of SECUREBOOT_VARS) {
    const needle = Buffer.concat([utf16le(name), Buffer.from([0, 0])]);
    out[name] = data.indexOf(needle) !== -1;
  }
  return out;
}

// returns { total, signed, unsigned }
export function countModules(data) {
  let total = 0, signed = 0;
  const seen = new Set();
  let search = 0;
  for (;;) {
    const idx = data.indexOf("MZ", search, "ascii");
    if (idx === -1) break;
    search = idx + 1;
    const s = peSigned(data, idx);
    if (s !== null && !seen.has(idx)) {
      seen.add(idx);
      total++;
      if (s) signed++;
    }
  }
  search = 0;
  for (;;) {
    const idx = data.indexOf("VZ", search, "ascii");
    if (idx === -1) break;
    search = idx + 1;
    if (teValid(data, idx) && !seen.has(idx)) {
      seen.add(idx);
      total++; // TE never signed
    }
  }
  return { total, signed, unsigned: total - signed };
}

// null if not a PE, otherwise boolean signed
function peSigned(data, mz) {
  if (mz + 0x40 > data.length) return null;
  const lfanew = data.readUInt32LE(mz + 0x3c);
  const pe = mz + lfanew;
  if (pe < 0 || pe + 24 > data.length) return null;
  if (!(data[pe] === 0x50 && data[pe + 1] === 0x45 && data[pe + 2] === 0 && data[pe + 3] === 0))
    return null;
  const sizeOpt = data.readUInt16LE(pe + 20);
  const opt = pe + 24;
  if (sizeOpt < 2 || opt + sizeOpt > data.length) return null;
  const magic = data.readUInt16LE(opt);
  let numRva, dir;
  if (magic === 0x10b) { numRva = opt + 92; dir = opt + 96; }
  else if (magic === 0x20b) { numRva = opt + 108; dir = opt + 112; }
  else return null;
  if (numRva + 4 > data.length) return null;
  const n = data.readUInt32LE(numRva);
  if (n > 4) {
    const e = dir + 4 * 8;
    if (e + 8 <= data.length) {
      const rva = data.readUInt32LE(e);
      const sz = data.readUInt32LE(e + 4);
      if (rva !== 0 && sz !== 0) return true;
    }
  }
  return false;
}

function teValid(data, te) {
  if (te + 0x28 > data.length) return false;
  const sub = data[te + 0x14];
  return sub >= 10 && sub <= 13;
}

export function audit(data) {
  const fvs = findFirmwareVolumes(data);
  const sb = findSecureBootVars(data);
  const mods = countModules(data);
  let verdict = "PASS";
  const findings = [];
  if (data.length < 64) { verdict = "FAIL"; findings.push("too-small"); }
  if (fvs.length === 0) { verdict = "FAIL"; findings.push("no-firmware-volume"); }
  if (REQUIRED_VARS.some((v) => !sb[v])) { verdict = "FAIL"; findings.push("missing-secureboot-keys"); }
  if (mods.total > 0 && mods.unsigned > 0) { verdict = "FAIL"; findings.push("unsigned-modules"); }
  return {
    tool: "uefiscan",
    verdict,
    firmware_volumes: fvs.length,
    secureboot_vars: sb,
    modules: mods,
    findings,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const path = process.argv[2];
  if (!path) {
    process.stderr.write("usage: uefiscan <firmware.bin>\n");
    process.exit(2);
  }
  let data;
  try { data = readFileSync(path); }
  catch (e) { process.stderr.write(`error: ${e.message}\n`); process.exit(2); }
  const res = audit(data);
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.verdict === "PASS" ? 0 : 1);
}
