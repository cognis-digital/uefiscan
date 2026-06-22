// Offline tests for the JS UEFISCAN port. Run: node --test
import test from "node:test";
import assert from "node:assert/strict";
import { findFirmwareVolumes, findSecureBootVars, countModules, audit } from "./index.js";

function buildFV() {
  const headerLen = 56;
  const fv = Buffer.alloc(headerLen);
  for (let i = 0; i < 16; i++) fv[16 + i] = i;
  fv.write("_FVH", 40, "ascii");
  fv.writeUInt16LE(headerLen, 48);
  fv[55] = 2;
  let total = 0;
  for (let i = 0; i < headerLen; i += 2) total = (total + fv.readUInt16LE(i)) & 0xffff;
  fv.writeUInt16LE((-total) & 0xffff, 50);
  return Buffer.concat([fv, Buffer.alloc(0x1000, 0xff)]);
}

function buildPE(signed) {
  const peOff = 0x40, numDirs = 16, optSize = 112 + numDirs * 8;
  const dos = Buffer.alloc(peOff);
  dos.write("MZ", 0, "ascii");
  dos.writeUInt32LE(peOff, 0x3c);
  const sig = Buffer.from([0x50, 0x45, 0, 0]);
  const coff = Buffer.alloc(20);
  coff.writeUInt16LE(0x8664, 0);
  coff.writeUInt16LE(1, 2);
  coff.writeUInt16LE(optSize, 16);
  coff.writeUInt16LE(0x2022, 18);
  const opt = Buffer.alloc(optSize);
  opt.writeUInt16LE(0x20b, 0);
  opt.writeUInt16LE(11, 68);
  opt.writeUInt32LE(numDirs, 108);
  if (signed) {
    const sec = 112 + 4 * 8;
    opt.writeUInt32LE(0x800, sec);
    opt.writeUInt32LE(0x120, sec + 4);
  }
  return Buffer.concat([dos, sig, coff, opt]);
}

function v(name) {
  const b = Buffer.alloc(name.length * 2);
  for (let i = 0; i < name.length; i++) b.writeUInt16LE(name.charCodeAt(i), i * 2);
  return Buffer.concat([b, Buffer.from([0, 0])]);
}

function buildVars(dbx) {
  const parts = [];
  for (const n of ["PK", "KEK", "db"]) { parts.push(v(n), Buffer.alloc(16)); }
  if (dbx) parts.push(v("dbx"));
  return Buffer.concat(parts);
}

test("fv detected", () => {
  assert.deepEqual(findFirmwareVolumes(buildFV()), [0]);
});

test("fv garbage rejected", () => {
  const junk = Buffer.alloc(80);
  junk.write("_FVH", 40, "ascii");
  assert.deepEqual(findFirmwareVolumes(junk), []);
});

test("secureboot vars", () => {
  const sb = findSecureBootVars(buildVars(false));
  assert.equal(sb.PK, true);
  assert.equal(sb.dbx, false);
});

test("db not matched in dbx", () => {
  const sb = findSecureBootVars(v("dbx"));
  assert.equal(sb.db, false);
  assert.equal(sb.dbx, true);
});

test("modules signed/unsigned", () => {
  const data = Buffer.concat([buildPE(true), buildPE(false)]);
  const m = countModules(data);
  assert.equal(m.total, 2);
  assert.equal(m.signed, 1);
  assert.equal(m.unsigned, 1);
});

test("audit pass", () => {
  const data = Buffer.concat([buildFV(), buildVars(true), buildPE(true)]);
  assert.equal(audit(data).verdict, "PASS");
});

test("audit fail unsigned", () => {
  const data = Buffer.concat([buildFV(), buildVars(true), buildPE(false)]);
  assert.equal(audit(data).verdict, "FAIL");
});

test("audit too small", () => {
  assert.equal(audit(Buffer.from("MZ")).verdict, "FAIL");
});
