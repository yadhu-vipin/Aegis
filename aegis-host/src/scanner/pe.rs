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

use crate::scanner::finding::{severity_for, Finding, Severity};
use anyhow::Result;

#[derive(Debug, Default, Clone)]
pub struct PeResult {
    pub is_pe: bool,
    pub flagged: bool,
    pub flags: Vec<String>,
    pub findings: Vec<Finding>,
    pub risk: f32,
    pub section_count: usize,
    pub import_dll_count: usize,
    pub import_function_count: usize,
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

/// Windows APIs worth reporting when a program *imports* them.
///
/// `(function, category, risk, why)`.
///
/// Imports are far stronger evidence than strings. `intent.rs` greps the raw
/// bytes for `"CreateRemoteThread"`, which any string in the file can trigger —
/// including one sitting in a help message or a false positive from compressed
/// data. An entry in the import table means the loader has been *told* to
/// resolve that function: the program cannot call it otherwise, and it cannot
/// be faked without actually intending to use it.
///
/// The converse is also true and worth remembering: a packed program imports
/// almost nothing, because it resolves everything at runtime via
/// `GetProcAddress`. An empty import table is itself a signal.
static DANGEROUS_IMPORTS: &[(&str, &str, f32, &str)] = &[
    // --- Code injection into other processes ---
    ("CreateRemoteThread", "process injection", 0.75,
     "starts code running inside another program's memory"),
    ("CreateRemoteThreadEx", "process injection", 0.75,
     "starts code running inside another program's memory"),
    ("WriteProcessMemory", "process injection", 0.7,
     "writes directly into another running program's memory"),
    ("VirtualAllocEx", "process injection", 0.65,
     "reserves memory inside another running program"),
    ("QueueUserAPC", "process injection", 0.7,
     "queues code to run inside another program's thread"),
    ("SetThreadContext", "process injection", 0.7,
     "redirects another program's thread to different code"),
    ("NtUnmapViewOfSection", "process hollowing", 0.8,
     "empties a running program so it can be replaced with different code"),

    // --- Surveillance ---
    ("SetWindowsHookExA", "keylogging", 0.7, "intercepts keyboard and mouse input system-wide"),
    ("SetWindowsHookExW", "keylogging", 0.7, "intercepts keyboard and mouse input system-wide"),
    ("GetAsyncKeyState", "keylogging", 0.5, "reads keyboard state without the window having focus"),
    ("BitBlt", "screen capture", 0.35, "copies the screen contents"),

    // --- Persistence ---
    //
    // Writing to the registry is how Windows programs store settings. Notepad
    // does it to remember your word-wrap preference. Persistence is about
    // *where* a program writes — the Run keys — and an import table cannot show
    // that: the key path is a string resolved at runtime, not a declaration.
    // `intent.rs` matches the specific autorun paths and treats those as
    // decisive; this stays low because the API alone says almost nothing.
    ("RegSetValueExA", "persistence", 0.1, "writes to the Windows registry"),
    ("RegSetValueExW", "persistence", 0.1, "writes to the Windows registry"),
    ("CreateServiceA", "persistence", 0.6, "installs a Windows service that starts automatically"),
    ("CreateServiceW", "persistence", 0.6, "installs a Windows service that starts automatically"),
    ("SetFileAttributesA", "hiding", 0.3, "changes file visibility"),
    ("SetFileAttributesW", "hiding", 0.3, "changes file visibility"),

    // --- Anti-analysis ---
    //
    // `IsDebuggerPresent` scores near zero despite being a genuine
    // anti-analysis API, because the MSVC C runtime calls it during start-up:
    // it is present in a large share of all Windows binaries ever compiled,
    // including `notepad.exe`. A signal that fires on everything distinguishes
    // nothing. Reported for context, weighted as the near-noise it is.
    ("IsDebuggerPresent", "anti-analysis", 0.05, "checks whether it is being examined"),
    ("CheckRemoteDebuggerPresent", "anti-analysis", 0.5, "checks whether it is being examined"),
    ("NtQueryInformationProcess", "anti-analysis", 0.45, "inspects process state, often to detect analysis"),
    ("OutputDebugStringA", "anti-analysis", 0.25, "can be used to detect a debugger"),

    // --- Dynamic resolution: how packed code hides what it calls ---
    //
    // Same base-rate problem, more severe. Essentially every non-trivial
    // Windows program calls `GetProcAddress` and `LoadLibrary` — that is how
    // optional OS features are used at all. What is suspicious is a program
    // that imports these *and almost nothing else*, which the import-count
    // check below already detects far more specifically.
    ("GetProcAddress", "dynamic API resolution", 0.05,
     "looks up functions by name at runtime instead of declaring them"),
    ("LoadLibraryA", "dynamic API resolution", 0.05, "loads additional code at runtime"),
    ("LoadLibraryW", "dynamic API resolution", 0.05, "loads additional code at runtime"),

    // --- Download-and-run ---
    ("URLDownloadToFileA", "payload download", 0.7, "downloads a file from the internet"),
    ("URLDownloadToFileW", "payload download", 0.7, "downloads a file from the internet"),
    ("InternetOpenUrlA", "network", 0.35, "opens a connection to a remote server"),
    ("InternetOpenUrlW", "network", 0.35, "opens a connection to a remote server"),
    ("WinExec", "process launch", 0.5, "runs another program"),
    ("ShellExecuteA", "process launch", 0.4, "runs another program or opens a file"),
    ("ShellExecuteW", "process launch", 0.4, "runs another program or opens a file"),

    // --- Credential access ---
    ("CryptUnprotectData", "credential access", 0.6,
     "decrypts saved passwords belonging to the current user"),
    ("LsaOpenPolicy", "credential access", 0.65, "opens the system's security policy store"),
];

/// DLLs whose mere presence in the import table is worth noting.
static NOTABLE_DLLS: &[(&str, &str, f32)] = &[
    ("wininet.dll", "internet access", 0.2),
    ("winhttp.dll", "internet access", 0.2),
    ("ws2_32.dll", "raw network sockets", 0.25),
    ("psapi.dll", "process enumeration", 0.2),
    ("dbghelp.dll", "debugging/memory inspection", 0.25),
    ("wtsapi32.dll", "session enumeration", 0.25),
];

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// One section's address mapping, for translating RVAs to file offsets.
#[derive(Debug, Clone, Copy)]
struct SectionMap {
    virtual_addr: u32,
    virtual_size: u32,
    raw_ptr: u32,
    raw_size: u32,
}

/// Translate a Relative Virtual Address to a file offset.
///
/// RVAs are where the loader will place data in memory; on disk that data lives
/// somewhere else entirely. Every RVA here comes from the file being scanned,
/// so this returns `None` for anything that does not land inside a real
/// section rather than producing an offset that could index out of bounds.
fn rva_to_offset(rva: u32, sections: &[SectionMap]) -> Option<usize> {
    for s in sections {
        // Use the larger of the two sizes: a section can be bigger on disk than
        // in memory or vice versa, and the mapping is valid across both.
        let span = s.virtual_size.max(s.raw_size);
        if rva >= s.virtual_addr && rva < s.virtual_addr.checked_add(span)? {
            let delta = rva - s.virtual_addr;
            if delta >= s.raw_size {
                return None; // inside the section but past its on-disk content
            }
            return s.raw_ptr.checked_add(delta).map(|v| v as usize);
        }
    }
    None
}

/// Read a NUL-terminated ASCII string, bounded.
fn cstr_at(data: &[u8], off: usize, max: usize) -> Option<String> {
    let slice = data.get(off..std::cmp::min(off + max, data.len()))?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if end == 0 {
        return None;
    }
    Some(
        slice[..end]
            .iter()
            .map(|&b| b as char)
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .collect(),
    )
}

/// What a program's import table says it intends to do.
#[derive(Debug, Default, Clone)]
pub struct ImportAnalysis {
    pub dll_count: usize,
    pub function_count: usize,
    pub findings: Vec<Finding>,
    pub risk: f32,
}

/// Walk the import table and report what the program declares it will call.
///
/// This is the strongest static signal available without executing anything.
/// A string match on `"CreateRemoteThread"` can come from anywhere in the file;
/// an *import* means the Windows loader has been instructed to resolve that
/// function before the program starts. It cannot be faked without intent.
fn analyse_imports(
    data: &[u8],
    opt_header: usize,
    sections: &[SectionMap],
) -> Option<ImportAnalysis> {
    let magic = u16_at(data, opt_header)?;
    // PE32 (0x10B) and PE32+ (0x20B) place the data directories differently.
    let (dir_start, thunk_size, is_64) = match magic {
        0x10B => (opt_header + 96, 4usize, false),
        0x20B => (opt_header + 112, 8usize, true),
        _ => return None,
    };

    // Data directory index 1 is the import table.
    let import_rva = u32_at(data, dir_start + 8)?;
    if import_rva == 0 {
        // No imports at all. Real programs always import something; a program
        // with none resolves everything at runtime, which is what packed and
        // shellcode-style binaries do.
        return Some(ImportAnalysis {
            findings: vec![Finding::new(
                Severity::Medium,
                "Program declares no dependencies at all",
                "The import table is empty.".to_string(),
                "Every normal Windows program declares the system functions it needs. One that \
                 declares none is resolving them secretly while it runs, which is how packed \
                 code hides what it is going to do.",
                0.5,
            )],
            risk: 0.5,
            ..Default::default()
        });
    }

    let mut desc_off = rva_to_offset(import_rva, sections)?;
    let mut dlls: Vec<String> = Vec::new();
    let mut hits: Vec<(&str, &str, f32, &str)> = Vec::new();
    let mut function_count = 0usize;

    // Bounded: a malformed table must not spin forever.
    for _ in 0..256 {
        // IMAGE_IMPORT_DESCRIPTOR is 20 bytes; an all-zero one terminates.
        let orig_thunk = u32_at(data, desc_off)?;
        let name_rva = u32_at(data, desc_off + 12)?;
        let first_thunk = u32_at(data, desc_off + 16)?;
        if orig_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        if let Some(dll) = rva_to_offset(name_rva, sections).and_then(|o| cstr_at(data, o, 64)) {
            dlls.push(dll.to_lowercase());
        }

        // Prefer the Import Name Table; fall back to the IAT.
        let thunk_rva = if orig_thunk != 0 { orig_thunk } else { first_thunk };
        if let Some(mut thunk_off) = rva_to_offset(thunk_rva, sections) {
            for _ in 0..4096 {
                let entry = if is_64 {
                    let lo = u32_at(data, thunk_off)? as u64;
                    let hi = u32_at(data, thunk_off + 4)? as u64;
                    (hi << 32) | lo
                } else {
                    u32_at(data, thunk_off)? as u64
                };
                if entry == 0 {
                    break;
                }
                // High bit set means import-by-ordinal: no name to read.
                let by_ordinal = if is_64 {
                    entry & 0x8000_0000_0000_0000 != 0
                } else {
                    entry & 0x8000_0000 != 0
                };
                if !by_ordinal {
                    // IMAGE_IMPORT_BY_NAME: 2-byte hint, then the name.
                    if let Some(off) = rva_to_offset(entry as u32, sections) {
                        if let Some(func) = cstr_at(data, off + 2, 128) {
                            function_count += 1;
                            if let Some(d) = DANGEROUS_IMPORTS
                                .iter()
                                .find(|(n, ..)| n.eq_ignore_ascii_case(&func))
                            {
                                if !hits.iter().any(|(n, ..)| *n == d.0) {
                                    hits.push(*d);
                                }
                            }
                        }
                    }
                } else {
                    function_count += 1;
                }
                thunk_off += thunk_size;
            }
        }

        desc_off += 20;
    }

    // --- Turn hits into explained findings, grouped by what they achieve ----
    let mut findings = Vec::new();
    let mut risk: f32 = 0.0;

    let mut by_category: std::collections::BTreeMap<&str, Vec<(&str, f32, &str)>> =
        std::collections::BTreeMap::new();
    for (func, cat, r, why) in &hits {
        by_category.entry(cat).or_default().push((func, *r, why));
    }

    for (category, funcs) in by_category {
        let max_risk = funcs.iter().map(|(_, r, _)| *r).fold(0.0f32, f32::max);
        let names: Vec<&str> = funcs.iter().map(|(n, _, _)| *n).collect();
        let effects: Vec<&str> = funcs.iter().map(|(_, _, w)| *w).collect();

        findings.push(Finding::new(
            severity_for(max_risk),
            format!("Program is built to perform {category}"),
            format!(
                "Import table declares {}: {}",
                if names.len() == 1 { "this function" } else { "these functions" },
                names.join(", ")
            ),
            format!(
                "It {}. Unlike text found inside a file, an import is a declaration to Windows \
                 that the program intends to call this - it cannot be there by accident.",
                effects.join("; ")
            ),
            max_risk,
        ));
        risk = risk.max(max_risk);
    }

    for (dll, purpose, r) in NOTABLE_DLLS {
        if dlls.iter().any(|d| d == dll) {
            findings.push(Finding::new(
                Severity::Low,
                format!("Program links against {dll}"),
                format!("Import table includes {dll}."),
                format!("This library provides {purpose}."),
                *r,
            ));
            risk = risk.max(*r);
        }
    }

    // Very few imports is itself suspicious for the same reason as none.
    if function_count > 0 && function_count < 5 {
        findings.push(Finding::new(
            Severity::Medium,
            "Program declares almost no dependencies",
            format!("Only {function_count} imported function(s) across {} librar(ies).", dlls.len()),
            "Normal programs import dozens to hundreds of system functions. A handful usually \
             means the real dependencies are resolved at runtime to keep them out of sight.",
            0.45,
        ));
        risk = risk.max(0.45);
    }

    Some(ImportAnalysis {
        dll_count: dlls.len(),
        function_count,
        findings,
        risk: risk.min(1.0),
    })
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
    let mut section_maps: Vec<SectionMap> = Vec::new();

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
        let raw_ptr = u32_at(data, off + 20).unwrap_or(0);
        let characteristics = u32_at(data, off + 36).unwrap_or(0);

        section_maps.push(SectionMap {
            virtual_addr,
            virtual_size,
            raw_ptr,
            raw_size,
        });

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

    // --- Import table: what the program declares it will call --------------
    if let Some(imports) = analyse_imports(data, opt_header, &section_maps) {
        result.import_dll_count = imports.dll_count;
        result.import_function_count = imports.function_count;
        findings.extend(imports.findings);
        risk = risk.max(imports.risk);
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
        d[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32 magic
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

        // This fixture has no import table, and a real PE with zero imports is
        // legitimately suspicious (see empty_import_table_is_itself_a_signal),
        // so only assert that nothing STRUCTURAL was flagged — which is what
        // this test is actually about.
        let structural: Vec<&Finding> = res
            .findings
            .iter()
            .filter(|f| !f.title.contains("dependencies"))
            .collect();
        assert!(
            structural.is_empty(),
            "clean section layout flagged: {structural:?}"
        );
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

    /// Build a PE32 with a real, walkable import table.
    ///
    /// Layout inside one section at RVA 0x1000 / file offset 0x400:
    ///   descriptors | thunk array | IMAGE_IMPORT_BY_NAME entries | dll name
    fn build_pe_with_imports(dll: &str, funcs: &[&str]) -> Vec<u8> {
        let pe_off = 0x80usize;
        let opt_size = 0xE0usize;
        let sec_table = pe_off + 4 + 20 + opt_size;
        let sec_raw = 0x400usize;
        let sec_rva = 0x1000u32;
        let mut d = vec![0u8; sec_raw + 0x600];

        d[0..2].copy_from_slice(b"MZ");
        d[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        d[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        d[pe_off + 20..pe_off + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());

        let opt = pe_off + 4 + 20;
        d[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32
        d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point

        // Section: .text
        let o = sec_table;
        d[o..o + 5].copy_from_slice(b".text");
        d[o + 8..o + 12].copy_from_slice(&0x600u32.to_le_bytes()); // virtual size
        d[o + 12..o + 16].copy_from_slice(&sec_rva.to_le_bytes());
        d[o + 16..o + 20].copy_from_slice(&0x600u32.to_le_bytes()); // raw size
        d[o + 20..o + 24].copy_from_slice(&(sec_raw as u32).to_le_bytes());
        d[o + 36..o + 40].copy_from_slice(&R_X.to_le_bytes());

        let to_rva = |file_off: usize| (file_off - sec_raw) as u32 + sec_rva;

        // Lay out: descriptors(40) | thunks | names | dll
        let desc = sec_raw;
        let thunks = sec_raw + 40;
        let mut cursor = thunks + (funcs.len() + 1) * 4;

        let mut name_rvas = Vec::new();
        for f in funcs {
            let at = cursor;
            d[at..at + 2].copy_from_slice(&0u16.to_le_bytes()); // hint
            d[at + 2..at + 2 + f.len()].copy_from_slice(f.as_bytes());
            name_rvas.push(to_rva(at));
            cursor += 2 + f.len() + 1;
        }
        let dll_at = cursor;
        d[dll_at..dll_at + dll.len()].copy_from_slice(dll.as_bytes());

        for (i, rva) in name_rvas.iter().enumerate() {
            d[thunks + i * 4..thunks + i * 4 + 4].copy_from_slice(&rva.to_le_bytes());
        }

        d[desc..desc + 4].copy_from_slice(&to_rva(thunks).to_le_bytes()); // OriginalFirstThunk
        d[desc + 12..desc + 16].copy_from_slice(&to_rva(dll_at).to_le_bytes()); // Name
        d[desc + 16..desc + 20].copy_from_slice(&to_rva(thunks).to_le_bytes()); // FirstThunk

        // Import directory = data directory index 1, at opt+96 for PE32.
        d[opt + 104..opt + 108].copy_from_slice(&to_rva(desc).to_le_bytes());
        d[opt + 108..opt + 112].copy_from_slice(&40u32.to_le_bytes());
        d
    }

    /// The core of this analysis: an *import* is a declaration to Windows that
    /// the program intends to call something. Unlike a string match it cannot
    /// appear by accident, which makes it far stronger evidence.
    #[test]
    fn injection_apis_in_the_import_table_are_detected() {
        let pe = build_pe_with_imports(
            "kernel32.dll",
            &["CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"],
        );
        let res = analyse(&pe).unwrap();

        assert!(res.is_pe);
        assert_eq!(res.import_dll_count, 1, "DLL not parsed");
        assert_eq!(res.import_function_count, 3, "functions not parsed");
        assert!(
            res.findings.iter().any(|f| f.title.contains("process injection")),
            "injection imports not reported: {:?}",
            res.findings
        );
        assert!(res.risk >= 0.7, "risk was {}", res.risk);
    }

    #[test]
    fn keylogging_and_credential_apis_are_categorised() {
        let pe = build_pe_with_imports("user32.dll", &["SetWindowsHookExW", "CryptUnprotectData"]);
        let res = analyse(&pe).unwrap();
        let titles: Vec<&str> = res.findings.iter().map(|f| f.title.as_str()).collect();
        assert!(
            titles.iter().any(|t| t.contains("keylogging")),
            "{titles:?}"
        );
        assert!(
            titles.iter().any(|t| t.contains("credential access")),
            "{titles:?}"
        );
    }

    /// Ordinary imports must stay quiet, or the signal is worthless.
    #[test]
    fn benign_imports_are_not_flagged() {
        let pe = build_pe_with_imports(
            "kernel32.dll",
            &["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetLastError", "ExitProcess"],
        );
        let res = analyse(&pe).unwrap();
        assert_eq!(res.import_function_count, 6);
        assert!(
            !res.findings.iter().any(|f| f.title.contains("built to perform")),
            "benign imports flagged: {:?}",
            res.findings
        );
    }

    /// An empty import table means everything is resolved at runtime — the
    /// defining characteristic of packed code.
    #[test]
    fn empty_import_table_is_itself_a_signal() {
        let pe = build_pe(&[(".text", 0x1000, 0x1000, 0x1000, R_X)], 0x1500);
        let res = analyse(&pe).unwrap();
        assert!(
            res.findings.iter().any(|f| f.title.contains("no dependencies")),
            "empty imports not reported: {:?}",
            res.findings
        );
    }

    /// The import table is attacker-controlled. RVAs pointing anywhere must
    /// not index out of bounds.
    #[test]
    fn corrupt_import_table_does_not_panic() {
        let mut pe = build_pe_with_imports("kernel32.dll", &["CreateRemoteThread"]);
        let opt = 0x80 + 4 + 20;
        for bad in [0xFFFF_FFFFu32, 0x7FFF_FFFF, 1, 0x1000_0000] {
            pe[opt + 104..opt + 108].copy_from_slice(&bad.to_le_bytes());
            let _ = analyse(&pe).unwrap();
        }
        // Truncate at every length.
        let full = build_pe_with_imports("kernel32.dll", &["CreateRemoteThread"]);
        for n in (0..full.len()).step_by(7) {
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
