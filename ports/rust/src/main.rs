// Rust port of the UEFISCAN core check: locate EFI firmware volumes, detect
// Secure Boot key variables, and count unsigned PE/TE modules. Passive/offline
// only — analyses a firmware dump you already have. No network. Std-only.
use std::{env, fs, process};

const SECUREBOOT_VARS: [&str; 4] = ["PK", "KEK", "db", "dbx"];
const REQUIRED_VARS: [&str; 3] = ["PK", "KEK", "db"];

fn u16le(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u32le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn find_subslice(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from > hay.len() || needle.len() > hay.len() - from {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

fn utf16le(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() * 2);
    for c in s.encode_utf16() {
        v.extend_from_slice(&c.to_le_bytes());
    }
    v
}

pub fn find_firmware_volumes(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(idx) = find_subslice(data, b"_FVH", search) {
        if idx >= 40 && fv_checksum_ok(data, idx - 40) {
            out.push(idx - 40);
        }
        search = idx + 1;
    }
    out
}

fn fv_checksum_ok(data: &[u8], fv_start: usize) -> bool {
    if fv_start + 64 > data.len() {
        return false;
    }
    let header_len = u16le(data, fv_start + 48) as usize;
    if header_len < 56 || header_len % 2 != 0 || fv_start + header_len > data.len() {
        return false;
    }
    let mut total: u16 = 0;
    let mut i = 0;
    while i < header_len {
        total = total.wrapping_add(u16le(data, fv_start + i));
        i += 2;
    }
    total == 0
}

pub fn find_secureboot_vars(data: &[u8]) -> Vec<(String, bool)> {
    SECUREBOOT_VARS
        .iter()
        .map(|name| {
            let mut needle = utf16le(name);
            needle.extend_from_slice(&[0, 0]);
            (name.to_string(), find_subslice(data, &needle, 0).is_some())
        })
        .collect()
}

/// returns (total, signed, unsigned)
pub fn count_modules(data: &[u8]) -> (usize, usize, usize) {
    let mut total = 0;
    let mut signed = 0;
    let mut seen: Vec<usize> = Vec::new();
    let mut search = 0;
    while let Some(idx) = find_subslice(data, b"MZ", search) {
        search = idx + 1;
        if let Some(s) = pe_signed(data, idx) {
            if !seen.contains(&idx) {
                seen.push(idx);
                total += 1;
                if s {
                    signed += 1;
                }
            }
        }
    }
    search = 0;
    while let Some(idx) = find_subslice(data, b"VZ", search) {
        search = idx + 1;
        if te_valid(data, idx) && !seen.contains(&idx) {
            seen.push(idx);
            total += 1; // TE never signed
        }
    }
    (total, signed, total - signed)
}

/// Some(signed) if a valid PE, None otherwise.
fn pe_signed(data: &[u8], mz: usize) -> Option<bool> {
    if mz + 0x40 > data.len() {
        return None;
    }
    let lfanew = u32le(data, mz + 0x3C) as usize;
    let pe = mz.checked_add(lfanew)?;
    if pe + 24 > data.len() || &data[pe..pe + 4] != b"PE\0\0" {
        return None;
    }
    let size_opt = u16le(data, pe + 20) as usize;
    let opt = pe + 24;
    if size_opt < 2 || opt + size_opt > data.len() {
        return None;
    }
    let magic = u16le(data, opt);
    let (numrva, dir) = match magic {
        0x10B => (opt + 92, opt + 96),
        0x20B => (opt + 108, opt + 112),
        _ => return None,
    };
    if numrva + 4 > data.len() {
        return None;
    }
    let n = u32le(data, numrva) as usize;
    if n > 4 {
        let e = dir + 4 * 8;
        if e + 8 <= data.len() {
            let rva = u32le(data, e);
            let sz = u32le(data, e + 4);
            if rva != 0 && sz != 0 {
                return Some(true);
            }
        }
    }
    Some(false)
}

fn te_valid(data: &[u8], te: usize) -> bool {
    if te + 0x28 > data.len() {
        return false;
    }
    let sub = data[te + 0x14];
    (10..=13).contains(&sub)
}

pub fn audit(data: &[u8]) -> (String, Vec<String>) {
    let fvs = find_firmware_volumes(data);
    let sb = find_secureboot_vars(data);
    let (total, _signed, unsigned) = count_modules(data);
    let mut verdict = "PASS".to_string();
    let mut findings = Vec::new();
    if data.len() < 64 {
        verdict = "FAIL".into();
        findings.push("too-small".into());
    }
    if fvs.is_empty() {
        verdict = "FAIL".into();
        findings.push("no-firmware-volume".into());
    }
    let missing = REQUIRED_VARS
        .iter()
        .any(|r| !sb.iter().any(|(k, v)| k == r && *v));
    if missing {
        verdict = "FAIL".into();
        findings.push("missing-secureboot-keys".into());
    }
    if total > 0 && unsigned > 0 {
        verdict = "FAIL".into();
        findings.push("unsigned-modules".into());
    }
    (verdict, findings)
}

fn main() {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: uefiscan <firmware.bin>");
            process::exit(2);
        }
    };
    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(2);
        }
    };
    let fvs = find_firmware_volumes(&data);
    let (total, signed, unsigned) = count_modules(&data);
    let (verdict, findings) = audit(&data);
    println!(
        "{{\"tool\":\"uefiscan\",\"verdict\":\"{}\",\"firmware_volumes\":{},\"modules\":{{\"total\":{},\"signed\":{},\"unsigned\":{}}},\"findings\":{:?}}}",
        verdict, fvs.len(), total, signed, unsigned, findings
    );
    process::exit(if verdict == "PASS" { 0 } else { 1 });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_fv() -> Vec<u8> {
        let header_len = 56usize;
        let mut fv = vec![0u8; header_len];
        for i in 0..16 {
            fv[16 + i] = i as u8;
        }
        fv[40..44].copy_from_slice(b"_FVH");
        fv[48..50].copy_from_slice(&(header_len as u16).to_le_bytes());
        fv[55] = 2;
        let mut total: u16 = 0;
        let mut i = 0;
        while i < header_len {
            total = total.wrapping_add(u16le(&fv, i));
            i += 2;
        }
        let fix = (0u16).wrapping_sub(total);
        fv[50..52].copy_from_slice(&fix.to_le_bytes());
        fv.extend(vec![0xffu8; 0x1000]);
        fv
    }

    fn build_pe(signed: bool) -> Vec<u8> {
        let pe_off = 0x40usize;
        let num_dirs = 16usize;
        let opt_size = 112 + num_dirs * 8;
        let mut out = vec![0u8; pe_off];
        out[0] = b'M';
        out[1] = b'Z';
        out[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        out.extend_from_slice(b"PE\0\0");
        let mut coff = vec![0u8; 20];
        coff[0..2].copy_from_slice(&0x8664u16.to_le_bytes());
        coff[2..4].copy_from_slice(&1u16.to_le_bytes());
        coff[16..18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        coff[18..20].copy_from_slice(&0x2022u16.to_le_bytes());
        out.extend_from_slice(&coff);
        let mut opt = vec![0u8; opt_size];
        opt[0..2].copy_from_slice(&0x20Bu16.to_le_bytes());
        opt[68..70].copy_from_slice(&11u16.to_le_bytes());
        opt[108..112].copy_from_slice(&(num_dirs as u32).to_le_bytes());
        if signed {
            let sec = 112 + 4 * 8;
            opt[sec..sec + 4].copy_from_slice(&0x800u32.to_le_bytes());
            opt[sec + 4..sec + 8].copy_from_slice(&0x120u32.to_le_bytes());
        }
        out.extend_from_slice(&opt);
        out
    }

    fn var(name: &str) -> Vec<u8> {
        let mut v = utf16le(name);
        v.extend_from_slice(&[0, 0]);
        v
    }

    fn build_vars(dbx: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for n in ["PK", "KEK", "db"] {
            out.extend(var(n));
            out.extend(vec![0u8; 16]);
        }
        if dbx {
            out.extend(var("dbx"));
        }
        out
    }

    #[test]
    fn fv_detected() {
        assert_eq!(find_firmware_volumes(&build_fv()), vec![0]);
    }

    #[test]
    fn fv_garbage_rejected() {
        let mut junk = vec![0u8; 80];
        junk[40..44].copy_from_slice(b"_FVH");
        assert!(find_firmware_volumes(&junk).is_empty());
    }

    #[test]
    fn vars_present() {
        let sb = find_secureboot_vars(&build_vars(false));
        assert!(sb.iter().any(|(k, v)| k == "PK" && *v));
        assert!(sb.iter().any(|(k, v)| k == "dbx" && !*v));
    }

    #[test]
    fn db_not_in_dbx() {
        let sb = find_secureboot_vars(&var("dbx"));
        assert!(sb.iter().any(|(k, v)| k == "db" && !*v));
    }

    #[test]
    fn modules_counted() {
        let mut data = build_pe(true);
        data.extend(build_pe(false));
        assert_eq!(count_modules(&data), (2, 1, 1));
    }

    #[test]
    fn audit_pass() {
        let mut data = build_fv();
        data.extend(build_vars(true));
        data.extend(build_pe(true));
        assert_eq!(audit(&data).0, "PASS");
    }

    #[test]
    fn audit_fail_unsigned() {
        let mut data = build_fv();
        data.extend(build_vars(true));
        data.extend(build_pe(false));
        assert_eq!(audit(&data).0, "FAIL");
    }

    #[test]
    fn audit_too_small() {
        assert_eq!(audit(b"MZ").0, "FAIL");
    }
}
