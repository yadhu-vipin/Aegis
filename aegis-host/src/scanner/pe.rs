//! PE (Portable Executable) structure analysis.
//!
//! Malware overwhelmingly ships as Windows executables, and packers leave
//! structural fingerprints that survive every attempt to hide the *content*:
//! a section whose on-disk size is far smaller than its in-memory size (the
//! unpacker will fill it at runtime), a section that is both writable and
//! executable (self-modifying code), an entry point outside every section
//! (a hijacked start address), or a section name no real compiler emits.
//!
//! These are structural facts, so unlike string matching they cannot be evaded
//! by encrypting the payload — the loader still has to be told the truth.
//!
//! ## Parsing hostile input
//!
//! Every offset here comes from the file being scanned, and the file is
//! attacker-controlled. Nothing indexes without a bounds check, nothing
//! allocates from a length field, and a malformed header produces
//! `Ok(not a PE)` rather than an error or a panic. Refusing to parse is a
//! perfectly good outcome; crashing is not.

use crate::scanner::finding::{Finding, Severity};
use anyhow::Result;

#[derive(Debug, Default, Clone)]
pub struct PeResult {
    pub is_pe: bool,
    pub flagged: bool,
    pub flags: Vec<String>,
    pub findings: Vec<Finding>,
    pub risk: f32,
    pub section_count: usize,
}

/// Section characteristic flags (winnt.h).
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Section names emitted by mainstream toolchains. Anything else is not
/// automatically malicious, but packers pick distinctive names and it is a
/// cheap corroborating signal.
static KNOWN_SECTIONS: &[&str] = &[
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".xdata", ".rsrc",
    ".reloc", ".tls", ".debug", ".didat", ".gfids", ".sxdata", ".CRT", ".INIT", ".00cfg",
    ".textbss", ".drectve", ".symtab", ".shared", ".rodata", ".eh_fram", ".init", ".fini",
];

/// Section names strongly associated with specific packers.
static PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"), ("UPX1", "UPX"), ("UPX2", "UPX"),
    (".aspack", "ASPack"), (".adata", "ASPack"),
    (".themida", "Themida"), (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"), (".vmp1", "VMProtect"), (".vmp2", "VMProtect"),
    (".petite", "Petite"), (".MPRESS1", "MPRESS"), (".MPRESS2", "MPRESS"),
    ("nsp0", "NsPack"), ("nsp1", "NsPack"),
    (".enigma1", "Enigma"), (".enigma2", "Enigma"),
    ("PELock", "PELock"), (".packed", "generic packer"),
];

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Analyse a complete file as a PE image.
///
/// Returns `is_pe: false` for anything that is not a well-formed PE. That is
/// not an error — most downloads are not executables.
pub fn analyse(data: &[u8]) -> Result<PeResult> {
    let mut result = PeResult::default();

    // --- DOS header -------------------------------------------------------
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return Ok(result);
    }

    // e_lfanew at 0x3C points to the PE header. Attacker-controlled: bound it.
    let Some(pe_off) = u32_at(data, 0x3C).map(|v| v as usize) else {
        return Ok(result);
    };
    if pe_off < 64 || pe_off + 24 > data.len() {
        return Ok(result);
    }
    if data.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return Ok(result);
    }

    result.is_pe = true;

    // --- COFF header ------------------------------------------------------
    let coff = pe_off + 4;
    let Some(num_sections) = u16_at(data, coff + 2).map(|v| v as usize) else {
        return Ok(result);
    };
    let Some(opt_header_size) = u16_at(data, coff + 16).map(|v| v as usize) else {
        return Ok(result);
    };

    // A real PE has a handful of sections. An absurd count is either corruption
    // or a deliberate attempt to make a parser allocate.
    if num_sections == 0 || num_sections > 96 {
        result.findings.push(Finding::new(
            Severity::High,
            "Program file is malformed",
            format!("The program header declares {num_sections} sections. Real programs have a handful."),
            "A header this broken is either corrupt or deliberately malformed to confuse security \
             scanners into misreading the file or crashing.",
            0.55,
        ));
        result.flags = result.findings.iter().map(|f| f.one_line()).collect();
        result.risk = result.risk.max(0.55);
        result.flagged = true;
        return Ok(result);
    }
    result.section_count = num_sections;

    let opt_header = coff + 20;
    let Some(entry_point) = u32_at(data, opt_header + 16) else {
        return Ok(result);
    };

    // --- Section table ----------------------------------------------------
    let sec_table = opt_header + opt_header_size;
    let mut risk: f32 = 0.0;
    let mut findings: Vec<Finding> = Vec::new();

    let mut entry_in_section = false;
    let mut unknown_names: Vec<String> = Vec::new();

    for i in 0..num_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            findings.push(Finding::new(
                Severity::Medium,
                "Program file is truncated or malformed",
                "The section table claims to extend past the end of the file.".to_string(),
                "The file does not match its own description of itself - it is either damaged or                  crafted to confuse tools that parse it.",
                0.5,
            ));
            risk = risk.max(0.5);
            break;
        }

        let raw_name = &data[off..off + 8];
        let name: String = raw_name
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();

        let virtual_size = u32_at(data, off + 8).unwrap_or(0);
        let virtual_addr = u32_at(data, off + 12).unwrap_or(0);
        let raw_size = u32_at(data, off + 16).unwrap_or(0);
        let characteristics = u32_at(data, off + 36).unwrap_or(0);

        // Entry point must live inside some section.
        if entry_point >= virtual_addr
            && virtual_size > 0
            && entry_point < virtual_addr.saturating_add(virtual_size)
        {
            entry_in_section = true;
        }

        // Writable AND executable: legitimate compilers do not emit this. It is
        // the hallmark of code that rewrites itself at runtime.
        let wx = (characteristics & IMAGE_SCN_MEM_WRITE) != 0
            && (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if wx {
            findings.push(Finding::new(
                Severity::High,
                "Program can rewrite its own code while running",
                format!("Section '{name}' is marked both writable and executable."),
                "Compilers never produce this. It means the program modifies its own instructions \
                 as it runs, which is how packed malware unpacks its real payload in memory, where \
                 a file scanner cannot see it.",
                0.7,
            ));
            risk = risk.max(0.7);
        }

        // Virtual size far exceeding raw size means the section is filled at
        // runtime — the unpacking stub writing the real payload into memory.
        if raw_size > 0 && virtual_size > raw_size.saturating_mul(4) && virtual_size > 0x1000 {
            findings.push(Finding::new(
                Severity::High,
                "Program expands itself in memory when run",
                format!(
                    "Section '{name}' occupies {virtual_size} bytes in memory but only \
                     {raw_size} on disk."
                ),
                "The missing content is generated while the program runs. This is how packers \
                 work: the real code only exists once it has started, so nothing on disk reveals \
                 what it actually does.",
                0.55,
            ));
            risk = risk.max(0.55);
        }

        // An executable section with no on-disk content has to be populated by
        // something else before it can run.
        if raw_size == 0 && (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 && virtual_size > 0 {
            findings.push(Finding::new(
                Severity::High,
                "Program contains code that does not exist on disk",
                format!("Section '{name}' is marked executable but contains no data in the file."),
                "Code must be written into this space before it can run, meaning the program \
                 assembles its real instructions at runtime rather than shipping them where they \
                 could be inspected.",
                0.6,
            ));
            risk = risk.max(0.6);
        }

        // Known packer signature.
        if let Some((_, packer)) = PACKER_SECTIONS
            .iter()
            .find(|(sec, _)| sec.eq_ignore_ascii_case(&name))
        {
            findings.push(Finding::new(
                Severity::High,
                format!("Program is compressed with {packer}"),
                format!("Section name '{name}' is the signature of the {packer} packer."),
                "Packing compresses a program so its contents cannot be examined until it runs. \
                 Legitimate software occasionally does this to save space; malware does it to \
                 hide what it will do.",
                0.6,
            ));
            risk = risk.max(0.6);
        } else if !name.is_empty() && !KNOWN_SECTIONS.iter().any(|s| s.eq_ignore_ascii_case(&name))
        {
            unknown_names.push(name.clone());
        }
    }

    if !entry_in_section && entry_point != 0 {
        findings.push(Finding::new(
            Severity::High,
            "Program starts from an address it never declared",
            format!(
                "The entry point 0x{entry_point:X} falls outside every section the file declares."
            ),
            "The program begins executing somewhere it told the system nothing about. This is what \
             happens when a file has been tampered with to inject code, or when it is hiding where \
             execution really begins.",
            0.65,
        ));
        risk = risk.max(0.65);
    }

    // Individually weak; several together is a real signal.
    if unknown_names.len() >= 2 {
        let r = 0.3;
        findings.push(Finding::new(
            Severity::Low,
            "Program was not built by a standard compiler",
            format!(
                "{} unrecognised section names: {}",
                unknown_names.len(),
                unknown_names.join(", ")
            ),
            "Mainstream compilers emit a well-known set of section names. Unusual ones suggest \
             the file was assembled by a packer or a custom tool rather than built normally.",
            r,
        ));
        risk = risk.max(r);
    }

    result.flags = findings.iter().map(|f| f.one_line()).collect();
    result.findings = findings;
    result.risk = risk.min(1.0);
    result.flagged = !result.findings.is_empty();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid PE for testing.
    fn build_pe(sections: &[(&str, u32, u32, u32, u32)], entry_point: u32) -> Vec<u8> {
        // (name, virtual_size, virtual_addr, raw_size, characteristics)
        let pe_off = 0x80usize;
        let opt_size = 0xE0usize;
        let sec_table = pe_off + 4 + 20 + opt_size;
        let total = sec_table + sections.len() * 40 + 64;

        let mut d = vec![0u8; total];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        d[pe_off + 6..pe_off + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        d[pe_off + 20..pe_off + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());

        let opt = pe_off + 4 + 20;
        d[opt + 16..opt + 20].copy_from_slice(&entry_point.to_le_bytes());

        for (i, (name, vsize, vaddr, rsize, chars)) in sections.iter().enumerate() {
            let o = sec_table + i * 40;
            let nb = name.as_bytes();
            let n = nb.len().min(8);
            d[o..o + n].copy_from_slice(&nb[..n]);
            d[o + 8..o + 12].copy_from_slice(&vsize.to_le_bytes());
            d[o + 12..o + 16].copy_from_slice(&vaddr.to_le_bytes());
            d[o + 16..o + 20].copy_from_slice(&rsize.to_le_bytes());
            d[o + 36..o + 40].copy_from_slice(&chars.to_le_bytes());
        }
        d
    }

    const R_X: u32 = 0x6000_0020; // read + execute + code
    const R_W: u32 = 0xC000_0040; // read + write + initialised data

    #[test]
    fn non_pe_input_is_reported_as_such() {
        for data in [b"\x89PNG\r\n\x1a\n".as_slice(), b"%PDF-1.4", b"hello", b""] {
            let res = analyse(data).unwrap();
            assert!(!res.is_pe, "non-PE treated as PE");
            assert!(!res.flagged);
        }
    }

    #[test]
    fn ordinary_executable_is_not_flagged() {
        let pe = build_pe(
            &[
                (".text", 0x1000, 0x1000, 0x1000, R_X),
                (".rdata", 0x500, 0x2000, 0x500, 0x4000_0040),
                (".data", 0x400, 0x3000, 0x400, R_W),
            ],
            0x1500,
        );
        let res = analyse(&pe).unwrap();
        assert!(res.is_pe);
        assert_eq!(res.section_count, 3);
        assert!(!res.flagged, "clean PE flagged: {:?}", res.flags);
    }

    /// No mainstream compiler emits a W+X section. It means the code rewrites
    /// itself, which is what unpacking stubs and shellcode loaders do.
    #[test]
    fn writable_executable_section_is_flagged() {
        let pe = build_pe(&[(".text", 0x1000, 0x1000, 0x1000, R_X | 0x8000_0000)], 0x1500);
        let res = analyse(&pe).unwrap();
        assert!(res.flagged);
        assert!(res.risk >= 0.7, "risk was {}", res.risk);
        assert!(
            res.findings.iter().any(|f| f.title.contains("rewrite its own code")),
            "{:?}",
            res.findings
        );
    }

    /// Virtual size >> raw size means the section is filled at runtime.
    #[test]
    fn packed_section_size_mismatch_is_flagged() {
        let pe = build_pe(&[(".text", 0x10000, 0x1000, 0x400, R_X)], 0x1500);
        let res = analyse(&pe).unwrap();
        assert!(res.flagged);
        assert!(
            res.findings.iter().any(|f| f.why.contains("packers work")),
            "{:?}",
            res.findings
        );
    }

    #[test]
    fn upx_packer_sections_are_identified() {
        let pe = build_pe(
            &[
                ("UPX0", 0x5000, 0x1000, 0, R_X),
                ("UPX1", 0x2000, 0x6000, 0x2000, R_X),
            ],
            0x6100,
        );
        let res = analyse(&pe).unwrap();
        assert!(res.flagged);
        assert!(
            res.flags.iter().any(|f| f.contains("UPX")),
            "packer not identified: {:?}",
            res.flags
        );
    }

    #[test]
    fn entry_point_outside_all_sections_is_flagged() {
        let pe = build_pe(&[(".text", 0x1000, 0x1000, 0x1000, R_X)], 0x99999);
        let res = analyse(&pe).unwrap();
        assert!(res.flagged);
        assert!(
            res.findings
                .iter()
                .any(|f| f.title.contains("never declared")),
            "{:?}",
            res.findings
        );
    }

    /// Every offset comes from attacker-controlled bytes. Malformed headers
    /// must yield "not a PE", never a panic - a panic in a security scanner is
    /// an availability failure.
    #[test]
    fn malformed_headers_never_panic() {
        // e_lfanew pointing far past the end
        let mut d = vec![0u8; 128];
        d[0..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(!analyse(&d).unwrap().is_pe);

        // e_lfanew pointing into the DOS header itself
        d[0x3C..0x40].copy_from_slice(&4u32.to_le_bytes());
        assert!(!analyse(&d).unwrap().is_pe);

        // truncated at every length
        let full = build_pe(&[(".text", 0x1000, 0x1000, 0x1000, R_X)], 0x1500);
        for n in 0..full.len() {
            let _ = analyse(&full[..n]).unwrap();
        }
    }

    /// An absurd section count must be rejected rather than driving a huge loop.
    #[test]
    fn absurd_section_count_is_rejected() {
        let mut d = build_pe(&[(".text", 0x1000, 0x1000, 0x1000, R_X)], 0x1500);
        d[0x80 + 6..0x80 + 8].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let res = analyse(&d).unwrap();
        assert!(res.flagged);
        assert!(
            res.findings.iter().any(|f| f.title.contains("malformed")),
            "{:?}",
            res.findings
        );
    }
}
