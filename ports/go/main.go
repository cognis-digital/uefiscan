// Go port of the UEFISCAN core check: locate EFI firmware volumes, detect
// Secure Boot key variables (PK/KEK/db/dbx), and count unsigned PE/TE modules.
// Passive/offline only — reads a firmware dump you already have. No network.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
)

var secureBootVars = []string{"PK", "KEK", "db", "dbx"}
var requiredVars = []string{"PK", "KEK", "db"}

// FindFirmwareVolumes returns byte offsets of valid EFI firmware volumes.
func FindFirmwareVolumes(data []byte) []int {
	var offsets []int
	sig := []byte("_FVH")
	search := 0
	for {
		idx := bytes.Index(data[search:], sig)
		if idx == -1 {
			break
		}
		idx += search
		fvStart := idx - 40
		if fvStart >= 0 && fvChecksumOK(data, fvStart) {
			offsets = append(offsets, fvStart)
		}
		search = idx + 1
	}
	return offsets
}

func fvChecksumOK(data []byte, fvStart int) bool {
	if fvStart+64 > len(data) {
		return false
	}
	headerLen := int(binary.LittleEndian.Uint16(data[fvStart+48:]))
	if headerLen < 56 || headerLen%2 != 0 || fvStart+headerLen > len(data) {
		return false
	}
	var total uint16
	for i := 0; i < headerLen; i += 2 {
		total += binary.LittleEndian.Uint16(data[fvStart+i:])
	}
	return total == 0
}

// FindSecureBootVars detects UTF-16LE Secure Boot variable names.
func FindSecureBootVars(data []byte) map[string]bool {
	present := map[string]bool{}
	for _, name := range secureBootVars {
		needle := utf16le(name)
		needle = append(needle, 0x00, 0x00)
		present[name] = bytes.Contains(data, needle)
	}
	return present
}

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// CountModules returns (total, signed, unsigned) PE/TE modules.
func CountModules(data []byte) (int, int, int) {
	total, signed := 0, 0
	seen := map[int]bool{}
	search := 0
	for {
		idx := bytes.Index(data[search:], []byte("MZ"))
		if idx == -1 {
			break
		}
		idx += search
		search = idx + 1
		if s, ok := peSigned(data, idx); ok && !seen[idx] {
			seen[idx] = true
			total++
			if s {
				signed++
			}
		}
	}
	search = 0
	for {
		idx := bytes.Index(data[search:], []byte("VZ"))
		if idx == -1 {
			break
		}
		idx += search
		search = idx + 1
		if teValid(data, idx) && !seen[idx] {
			seen[idx] = true
			total++ // TE never signed
		}
	}
	return total, signed, total - signed
}

func peSigned(data []byte, mz int) (bool, bool) {
	if mz+0x40 > len(data) {
		return false, false
	}
	lfanew := int(binary.LittleEndian.Uint32(data[mz+0x3C:]))
	pe := mz + lfanew
	if pe < 0 || pe+24 > len(data) || !bytes.Equal(data[pe:pe+4], []byte("PE\x00\x00")) {
		return false, false
	}
	sizeOpt := int(binary.LittleEndian.Uint16(data[pe+20:]))
	opt := pe + 24
	if sizeOpt < 2 || opt+sizeOpt > len(data) {
		return false, false
	}
	magic := binary.LittleEndian.Uint16(data[opt:])
	var numRva, dir int
	switch magic {
	case 0x10B:
		numRva, dir = opt+92, opt+96
	case 0x20B:
		numRva, dir = opt+108, opt+112
	default:
		return false, false
	}
	if numRva+4 > len(data) {
		return false, false
	}
	n := int(binary.LittleEndian.Uint32(data[numRva:]))
	if n > 4 {
		e := dir + 4*8
		if e+8 <= len(data) {
			rva := binary.LittleEndian.Uint32(data[e:])
			sz := binary.LittleEndian.Uint32(data[e+4:])
			if rva != 0 && sz != 0 {
				return true, true
			}
		}
	}
	return false, true
}

func teValid(data []byte, te int) bool {
	if te+0x28 > len(data) {
		return false
	}
	sub := data[te+0x14]
	return sub >= 10 && sub <= 13
}

func allRequired(sb map[string]bool) bool {
	for _, v := range requiredVars {
		if !sb[v] {
			return false
		}
	}
	return true
}

// Audit runs the full passive check and returns a verdict map.
func Audit(data []byte) map[string]any {
	fvs := FindFirmwareVolumes(data)
	sb := FindSecureBootVars(data)
	total, signed, unsigned := CountModules(data)
	verdict := "PASS"
	var findings []string
	if len(data) < 64 {
		verdict = "FAIL"
		findings = append(findings, "too-small")
	}
	if len(fvs) == 0 {
		verdict = "FAIL"
		findings = append(findings, "no-firmware-volume")
	}
	if !allRequired(sb) {
		verdict = "FAIL"
		findings = append(findings, "missing-secureboot-keys")
	}
	if total > 0 && unsigned > 0 {
		verdict = "FAIL"
		findings = append(findings, "unsigned-modules")
	}
	return map[string]any{
		"tool":             "uefiscan",
		"verdict":          verdict,
		"firmware_volumes": len(fvs),
		"secureboot_vars":  sb,
		"modules":          map[string]int{"total": total, "signed": signed, "unsigned": unsigned},
		"findings":         findings,
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: uefiscan <firmware.bin>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	res := Audit(data)
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
	if res["verdict"] == "PASS" {
		os.Exit(0)
	}
	os.Exit(1)
}
