package main

import (
	"encoding/binary"
	"testing"
)

// buildFV builds a minimal EFI_FIRMWARE_VOLUME_HEADER with a valid checksum.
func buildFV() []byte {
	const headerLen = 56
	fv := make([]byte, headerLen)
	copy(fv[16:32], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	binary.LittleEndian.PutUint64(fv[32:], headerLen+0x1000)
	copy(fv[40:44], []byte("_FVH"))
	binary.LittleEndian.PutUint32(fv[44:], 0x0004FEFF)
	binary.LittleEndian.PutUint16(fv[48:], headerLen)
	fv[55] = 2
	var total uint16
	for i := 0; i < headerLen; i += 2 {
		total += binary.LittleEndian.Uint16(fv[i:])
	}
	binary.LittleEndian.PutUint16(fv[50:], -total)
	body := make([]byte, 0x1000)
	for i := range body {
		body[i] = 0xff
	}
	return append(fv, body...)
}

func buildPE(signed bool) []byte {
	const peOff = 0x40
	const numDirs = 16
	optSize := 112 + numDirs*8
	out := make([]byte, peOff)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[0x3C:], peOff)
	out = append(out, []byte("PE\x00\x00")...)
	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)
	binary.LittleEndian.PutUint16(coff[2:], 1)
	binary.LittleEndian.PutUint16(coff[16:], uint16(optSize))
	binary.LittleEndian.PutUint16(coff[18:], 0x2022)
	out = append(out, coff...)
	opt := make([]byte, optSize)
	binary.LittleEndian.PutUint16(opt[0:], 0x20B)
	binary.LittleEndian.PutUint16(opt[68:], 11)
	binary.LittleEndian.PutUint32(opt[108:], numDirs)
	if signed {
		secOff := 112 + 4*8
		binary.LittleEndian.PutUint32(opt[secOff:], 0x800)
		binary.LittleEndian.PutUint32(opt[secOff+4:], 0x120)
	}
	return append(out, opt...)
}

func utf16var(name string) []byte {
	b := utf16le(name)
	return append(b, 0x00, 0x00)
}

func buildVars(includeDbx bool) []byte {
	var out []byte
	names := []string{"PK", "KEK", "db"}
	if includeDbx {
		names = append(names, "dbx")
	}
	for _, n := range names {
		out = append(out, utf16var(n)...)
		out = append(out, make([]byte, 16)...)
	}
	return out
}

func TestFindFV(t *testing.T) {
	if got := FindFirmwareVolumes(buildFV()); len(got) != 1 || got[0] != 0 {
		t.Fatalf("expected one FV at 0, got %v", got)
	}
}

func TestFVRejectsGarbage(t *testing.T) {
	junk := make([]byte, 80)
	copy(junk[40:44], []byte("_FVH"))
	if got := FindFirmwareVolumes(junk); len(got) != 0 {
		t.Fatalf("expected no FV, got %v", got)
	}
}

func TestSecureBootVars(t *testing.T) {
	sb := FindSecureBootVars(buildVars(false))
	if !sb["PK"] || !sb["KEK"] || !sb["db"] || sb["dbx"] {
		t.Fatalf("bad sb vars: %v", sb)
	}
}

func TestDbNotMatchedInDbx(t *testing.T) {
	sb := FindSecureBootVars(utf16var("dbx"))
	if sb["db"] {
		t.Fatal("db must not match inside dbx")
	}
}

func TestModulesSignedUnsigned(t *testing.T) {
	data := append(buildPE(true), buildPE(false)...)
	total, signed, unsigned := CountModules(data)
	if total != 2 || signed != 1 || unsigned != 1 {
		t.Fatalf("got total=%d signed=%d unsigned=%d", total, signed, unsigned)
	}
}

func TestAuditPass(t *testing.T) {
	data := buildFV()
	data = append(data, buildVars(true)...)
	data = append(data, buildPE(true)...)
	res := Audit(data)
	if res["verdict"] != "PASS" {
		t.Fatalf("expected PASS, got %v", res["verdict"])
	}
}

func TestAuditFailUnsigned(t *testing.T) {
	data := buildFV()
	data = append(data, buildVars(true)...)
	data = append(data, buildPE(false)...)
	res := Audit(data)
	if res["verdict"] != "FAIL" {
		t.Fatalf("expected FAIL, got %v", res["verdict"])
	}
}

func TestAuditTooSmall(t *testing.T) {
	if Audit([]byte("MZ"))["verdict"] != "FAIL" {
		t.Fatal("tiny image should FAIL")
	}
}
