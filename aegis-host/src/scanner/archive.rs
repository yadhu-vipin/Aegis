//! Archive inspection — what a ZIP is carrying, without unpacking it.
//!
//! This closes the largest detection gap in the scanner. Every other check
//! looks at the container: magic bytes ask "is this really a ZIP?", structure
//! asks "is anything appended after it?", entropy asks "is it compressed?" —
//! and a ZIP answers all three innocently, because it *is* a ZIP and it *is*
//! compressed. Meanwhile `invoice.pdf.exe` sits inside scoring zero.
//!
//! Most malware arrives this way, and it is not an accident: an archive
//! defeats the naive checks and, when encrypted, defeats content scanning
//! outright.
//!
//! ## Why the central directory, and why no decompression
//!
//! A ZIP records every entry twice: once in a local header before the data,
//! and once in the central directory at the end. The central directory is the
//! authoritative index — it is what extraction tools read — so parsing it
//! yields every entry's name, sizes and flags for the cost of a seek. No
//! decompression happens here at all, which matters for three reasons:
//!
//! * a zip bomb cannot be triggered by a scanner that never inflates anything;
//! * the ratio that *identifies* a bomb is right there in the header;
//! * memory stays proportional to the entry count, not the payload.
//!
//! The listing is also reused by [`crate::scanner::autoexec`] to find macros
//! inside Office documents, which are ZIPs wearing a different extension.
//!
//! ## Parsing hostile input
//!
//! Same rule as `pe.rs`: every offset here comes from the file being scanned.
//! Nothing indexes without a bounds check, nothing allocates from a length
//! field, every loop is bounded, and a malformed archive yields "not a
//! readable archive" rather than an error or a panic.

use crate::scanner::finding::{Finding, Severity};
use anyhow::Result;

/// Largest number of entries walked.
///
/// Bounds the work an attacker can demand from one file. A real archive with
/// more entries than this still gets its first 16384 inspected, which is
/// plenty to find a planted executable — the interesting entry is never the
/// twenty-thousandth.
const MAX_ENTRIES: usize = 16_384;

/// Longest entry name read. Names beyond this are truncated for reporting; the
/// checks still run on what was read.
const MAX_NAME_LEN: usize = 1024;

/// How far back from EOF to search for the End Of Central Directory record.
///
/// The EOCD sits at the end followed only by an optional comment, and the
/// comment length field is 16 bits — so 64 KB plus the record itself is the
/// complete search space, not a heuristic.
const EOCD_SEARCH_WINDOW: usize = 65_535 + 22;

/// One entry, as described by the central directory.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    /// Entry path as stored, decoded lossily. May contain `/` separators.
    pub name: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// General-purpose bit 0: the entry's data is encrypted.
    pub encrypted: bool,
    /// True when the name ends in `/` and the entry has no content.
    pub is_directory: bool,
}

impl ZipEntry {
    /// The final path component — what a user sees after extraction.
    pub fn file_name(&self) -> &str {
        self.name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&self.name)
    }

    /// Lowercased final extension, if any.
    pub fn extension(&self) -> Option<String> {
        let name = self.file_name();
        name.rsplit_once('.').map(|(_, e)| e.to_lowercase())
    }

    /// True when the entry sits at the archive root rather than in a folder.
    pub fn is_at_root(&self) -> bool {
        !self.name.contains('/') && !self.name.contains('\\')
    }
}

/// Result of archive analysis.
#[derive(Debug, Default, Clone)]
pub struct ArchiveResult {
    /// A parseable ZIP central directory was found.
    pub is_archive: bool,
    pub flagged: bool,
    pub flags: Vec<String>,
    pub findings: Vec<Finding>,
    pub risk: f32,
    pub entry_count: usize,
}

fn u16_at(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8).map(|b| {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// Locate the central directory: `(offset, entry_count)`.
///
/// Searches backwards for the EOCD signature. Searching backwards rather than
/// forwards matters: `PK\x05\x06` can legitimately occur inside compressed
/// data, and the real record is the last one.
fn find_central_directory(data: &[u8]) -> Option<(usize, usize)> {
    let search_start = data.len().saturating_sub(EOCD_SEARCH_WINDOW);
    let window = data.get(search_start..)?;
    let rel = window.windows(4).rposition(|w| w == b"PK\x05\x06")?;
    let eocd = search_start + rel;

    let entries = u16_at(data, eocd + 10)? as usize;
    let cd_offset = u32_at(data, eocd + 16)? as u64;

    // 0xFFFFFFFF is the ZIP64 sentinel: the real values live in a ZIP64 EOCD
    // record, located via a locator immediately preceding this one.
    if cd_offset == 0xFFFF_FFFF || entries == 0xFFFF {
        if let Some((z_off, z_entries)) = zip64_central_directory(data, eocd) {
            return Some((z_off, z_entries));
        }
    }

    let cd_offset = usize::try_from(cd_offset).ok()?;
    if cd_offset >= data.len() {
        return None;
    }
    Some((cd_offset, entries))
}

/// Resolve the ZIP64 EOCD record via its locator.
fn zip64_central_directory(data: &[u8], eocd: usize) -> Option<(usize, usize)> {
    // The ZIP64 locator is exactly 20 bytes and sits immediately before EOCD.
    let locator = eocd.checked_sub(20)?;
    if data.get(locator..locator + 4)? != b"PK\x06\x07" {
        return None;
    }
    let z_eocd = usize::try_from(u64_at(data, locator + 8)?).ok()?;
    if data.get(z_eocd..z_eocd + 4)? != b"PK\x06\x06" {
        return None;
    }
    let entries = usize::try_from(u64_at(data, z_eocd + 32)?).ok()?;
    let cd_offset = usize::try_from(u64_at(data, z_eocd + 48)?).ok()?;
    if cd_offset >= data.len() {
        return None;
    }
    Some((cd_offset, entries))
}

/// Pull the true sizes out of a ZIP64 extended-information extra field.
///
/// When a size field holds `0xFFFFFFFF` the real 64-bit value lives in extra
/// field `0x0001`, whose contents are ordered but *optional* — only the fields
/// that overflowed are present. Reading them positionally without tracking
/// which ones were actually needed is how ZIP64 parsers produce garbage sizes.
fn zip64_sizes(extra: &[u8], need_uncompressed: bool, need_compressed: bool) -> (Option<u64>, Option<u64>) {
    let mut off = 0usize;
    while off + 4 <= extra.len() {
        let header_id = u16_at(extra, off).unwrap_or(0);
        let size = u16_at(extra, off + 2).unwrap_or(0) as usize;
        let body_start = off + 4;
        let Some(body) = extra.get(body_start..body_start.saturating_add(size)) else {
            break;
        };

        if header_id == 0x0001 {
            let mut cursor = 0usize;
            let mut uncompressed = None;
            let mut compressed = None;
            if need_uncompressed {
                uncompressed = u64_at(body, cursor);
                cursor += 8;
            }
            if need_compressed {
                compressed = u64_at(body, cursor);
            }
            return (uncompressed, compressed);
        }

        off = body_start.saturating_add(size);
    }
    (None, None)
}

/// Walk the central directory and return every entry it describes.
///
/// Returns `None` when the file is not a readable ZIP. That is not an error —
/// most downloads are not archives — and it is deliberately distinct from
/// `Some(vec![])`, which means "a valid but empty archive".
pub fn list_entries(data: &[u8]) -> Option<Vec<ZipEntry>> {
    let (cd_offset, declared_entries) = find_central_directory(data)?;

    // The declared count is attacker-controlled, so it steers the loop but
    // never sizes an allocation.
    let limit = declared_entries.min(MAX_ENTRIES);
    let mut entries = Vec::new();
    let mut off = cd_offset;

    for _ in 0..limit {
        if data.get(off..off + 4)? != b"PK\x01\x02" {
            break;
        }

        let flags = u16_at(data, off + 8)?;
        let compressed_size = u32_at(data, off + 20)? as u64;
        let uncompressed_size = u32_at(data, off + 24)? as u64;
        let name_len = u16_at(data, off + 28)? as usize;
        let extra_len = u16_at(data, off + 30)? as usize;
        let comment_len = u16_at(data, off + 32)? as usize;

        let name_start = off + 46;
        let name_bytes = data.get(name_start..name_start.checked_add(name_len)?)?;
        let name = String::from_utf8_lossy(&name_bytes[..name_len.min(MAX_NAME_LEN)]).into_owned();

        let extra_start = name_start + name_len;
        let extra = data
            .get(extra_start..extra_start.checked_add(extra_len)?)
            .unwrap_or(&[]);

        let need_uncompressed = uncompressed_size == 0xFFFF_FFFF;
        let need_compressed = compressed_size == 0xFFFF_FFFF;
        let (z_uncompressed, z_compressed) = if need_uncompressed || need_compressed {
            zip64_sizes(extra, need_uncompressed, need_compressed)
        } else {
            (None, None)
        };

        let is_directory = name.ends_with('/') || name.ends_with('\\');

        entries.push(ZipEntry {
            compressed_size: z_compressed.unwrap_or(compressed_size),
            uncompressed_size: z_uncompressed.unwrap_or(uncompressed_size),
            // Bit 0 of the general-purpose flags. Set means the data is
            // encrypted and no scanner can read it — not this one, and not
            // the antivirus either.
            encrypted: flags & 1 != 0,
            is_directory,
            name,
        });

        off = extra_start
            .checked_add(extra_len)?
            .checked_add(comment_len)?;
    }

    Some(entries)
}

/// Extensions that execute when opened, grouped by how directly they do it.
///
/// `(extension, description, risk)`. The risk here is for the entry appearing
/// *inside an archive*, which is a much weaker signal than the same file
/// arriving loose — a ZIP legitimately contains executables, and flagging that
/// outright fires on every installer.
static EXECUTABLE_ENTRIES: &[(&str, &str, f32)] = &[
    // Runs directly, no interpreter, no prompt beyond SmartScreen.
    ("exe", "a Windows program", 0.15),
    ("msi", "a Windows installer", 0.15),
    ("dll", "a Windows code library", 0.15),
    ("com", "a DOS/Windows program", 0.3),
    ("scr", "a screensaver, which is an ordinary program with a different extension", 0.5),
    ("cpl", "a Control Panel applet, which is an ordinary program", 0.5),
    ("pif", "a shortcut that Windows executes as a program", 0.55),
    // Shortcut files. Carry an arbitrary command line and a chosen icon, so
    // they can look like anything at all.
    ("lnk", "a Windows shortcut, which can run any command while showing any icon", 0.6),
    // Script hosts. No compilation step, so these are what phishing campaigns
    // ship: the payload is plain text until Windows runs it.
    ("js", "a script Windows runs without asking", 0.4),
    ("jse", "an encoded script Windows runs without asking", 0.6),
    ("vbs", "a Visual Basic script", 0.5),
    ("vbe", "an encoded Visual Basic script", 0.6),
    ("wsf", "a Windows Script Host file", 0.55),
    ("wsh", "a Windows Script Host settings file", 0.5),
    ("hta", "an HTML Application, which runs with full local privileges", 0.6),
    ("ps1", "a PowerShell script", 0.45),
    ("bat", "a batch file", 0.4),
    ("cmd", "a batch file", 0.4),
    ("reg", "a registry edit applied on double-click", 0.35),
    // Container formats that mount and can auto-run.
    ("iso", "a disc image, which mounts as a drive when opened", 0.4),
    ("img", "a disc image, which mounts as a drive when opened", 0.4),
    ("vhd", "a virtual disk, which mounts as a drive when opened", 0.4),
    ("vhdx", "a virtual disk, which mounts as a drive when opened", 0.4),
];

fn executable_entry(ext: &str) -> Option<(&'static str, f32)> {
    EXECUTABLE_ENTRIES
        .iter()
        .find(|(e, ..)| *e == ext)
        .map(|(_, desc, risk)| (*desc, *risk))
}

/// Analyse a complete file as an archive.
///
/// Non-archives return `is_archive: false` with no findings.
pub fn analyse(data: &[u8], filename: &str) -> Result<ArchiveResult> {
    let Some(entries) = list_entries(data) else {
        return Ok(ArchiveResult::default());
    };

    let mut findings: Vec<Finding> = Vec::new();
    let mut risk: f32 = 0.0;
    let files: Vec<&ZipEntry> = entries.iter().filter(|e| !e.is_directory).collect();

    // --- 1. Path traversal (zip-slip) --------------------------------------
    //
    // An entry named `../../windows/system32/x.dll` writes outside the folder
    // the user chose. No archiving tool produces this and no legitimate
    // workflow needs it, so unlike most checks here there is no benign case to
    // trade off against.
    let traversal: Vec<&&ZipEntry> = files
        .iter()
        .filter(|e| {
            e.name.split(['/', '\\']).any(|c| c == "..")
                || e.name.starts_with('/')
                || e.name.starts_with('\\')
                // Drive-absolute, e.g. `C:\Windows\...`
                || e.name.as_bytes().get(1) == Some(&b':')
        })
        .collect();

    if let Some(first) = traversal.first() {
        let r = 0.8;
        findings.push(Finding::new(
            Severity::Critical,
            "Archive tries to write files outside the folder you extract it to",
            format!(
                "{} of {} entries escape the extraction directory, including {:?}.",
                traversal.len(),
                files.len(),
                truncate(&first.name, 120)
            ),
            "Extracting this would place files somewhere you did not choose — a startup folder, \
             a system directory, or over an existing program. Archiving tools do not create paths \
             like this; it has to be done deliberately.",
            r,
        ));
        risk = risk.max(r);
    }

    // --- 2. Right-to-left override in entry names --------------------------
    //
    // U+202E reverses the display of everything after it, so `invoice\u{202E}
    // fdp.exe` renders as `invoiceexe.pdf`. The extension shown to the user is
    // not the extension Windows uses.
    if let Some(e) = files.iter().find(|e| contains_bidi_override(&e.name)) {
        let r = 0.85;
        findings.push(Finding::new(
            Severity::Critical,
            "Archive contains a file whose name is rigged to display incorrectly",
            format!(
                "Entry {:?} contains a Unicode text-direction override character.",
                truncate(&e.name.replace(['\u{202E}', '\u{202D}', '\u{200F}'], "<RLO>"), 120)
            ),
            "That character reverses how the rest of the name is displayed, so a program can be \
             shown to you as a PDF or an image. What you see in the extraction window is not what \
             Windows will run. There is no legitimate use for this in a filename.",
            r,
        ));
        risk = risk.max(r);
    }

    // --- 3. Double extensions inside ---------------------------------------
    //
    // The case this module exists for: `invoice.pdf.exe`, invisible to every
    // other check because the archive itself is a perfectly ordinary ZIP.
    let disguised: Vec<(&str, String, String)> = files
        .iter()
        .filter_map(|e| {
            crate::scanner::structure::check_double_extension(e.file_name())
                .map(|(v, a)| (e.file_name(), v, a))
        })
        .collect();

    if let Some((name, visible, actual)) = disguised.first() {
        let r = 0.75;
        findings.push(Finding::new(
            Severity::Critical,
            "Archive contains a program disguised as a document",
            format!(
                "Entry {:?} ends in .{actual}, but the .{visible} before it is what draws the eye.{}",
                truncate(name, 120),
                if disguised.len() > 1 {
                    format!(" {} entries do this.", disguised.len())
                } else {
                    String::new()
                }
            ),
            format!(
                "Windows hides known file extensions by default, so after extraction this usually \
                 displays as a harmless .{visible} file with a matching icon. Double-clicking it \
                 runs a .{actual} program. Putting it inside an archive is how it gets past \
                 scanners that only look at the outer file."
            ),
            r,
        ));
        risk = risk.max(r);
    }

    // --- 4. Encrypted entries ----------------------------------------------
    //
    // The archive is readable but its contents are not — not by Aegis, and not
    // by Windows Defender either. That is precisely why malware campaigns ship
    // password-protected archives with the password in the email body: it
    // moves the decryption step to a human, past every automated check.
    let encrypted = files.iter().filter(|e| e.encrypted).count();
    if encrypted > 0 {
        let r = 0.5;
        findings.push(Finding::new(
            Severity::High,
            "Archive contents are password-protected and cannot be examined",
            format!("{encrypted} of {} entries are encrypted.", files.len()),
            "Nothing can scan inside an encrypted archive — not Aegis, and not the antivirus on \
             your machine either. Sending a password-protected archive with the password written \
             in the accompanying message is a standard way of delivering malware past automated \
             scanning, because the only thing that can open it is a person.",
            r,
        ));
        risk = risk.max(r);
    }

    // --- 5. Compression ratio consistent with a zip bomb -------------------
    let total_compressed: u64 = files.iter().map(|e| e.compressed_size).sum();
    let total_uncompressed: u64 = files.iter().map(|e| e.uncompressed_size).sum();
    if let Some(finding) = bomb_finding(total_compressed, total_uncompressed, files.len()) {
        risk = risk.max(finding.risk);
        findings.push(finding);
    }

    // --- 6. Executable and script content ----------------------------------
    //
    // Deliberately weak on its own. An archive containing a program is normal —
    // that is what an installer is — so this reports rather than accuses, and
    // only the delivery *pattern* below carries real weight.
    let mut exec_entries: Vec<(&str, &'static str, f32)> = Vec::new();
    for e in &files {
        if let Some(ext) = e.extension() {
            if let Some((desc, r)) = executable_entry(&ext) {
                exec_entries.push((e.file_name(), desc, r));
            }
        }
    }

    if !exec_entries.is_empty() {
        let max_entry_risk = exec_entries.iter().map(|(_, _, r)| *r).fold(0.0f32, f32::max);
        let worst = exec_entries
            .iter()
            .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(n, d, _)| (*n, *d))
            .unwrap_or(("", ""));

        // The delivery pattern: a small archive whose executable sits at the
        // root, ready to be double-clicked the moment it is extracted. A source
        // tree or an installer bundle has depth and dozens of supporting files;
        // a malware drop is one file in an otherwise empty archive.
        let root_execs = files
            .iter()
            .filter(|e| {
                e.is_at_root()
                    && e.extension()
                        .map(|x| executable_entry(&x).is_some())
                        .unwrap_or(false)
            })
            .count();
        let is_delivery_shape = files.len() <= 3 && root_execs > 0;

        let r = if is_delivery_shape {
            (max_entry_risk + 0.3).min(0.7)
        } else {
            max_entry_risk
        };

        findings.push(Finding::new(
            crate::scanner::finding::severity_for(r),
            if is_delivery_shape {
                "Archive contains nothing but a program to run"
            } else {
                "Archive contains programs or scripts"
            },
            format!(
                "{} of {} entries can execute. The most direct is {:?}, {}.",
                exec_entries.len(),
                files.len(),
                truncate(worst.0, 120),
                worst.1
            ),
            if is_delivery_shape {
                "An archive holding one runnable file and little else is how malware is delivered: \
                 the archive gets it past scanning, and extracting leaves the program sitting in \
                 your Downloads folder ready to double-click. Installers and legitimate bundles \
                 normally carry many supporting files."
                    .to_string()
            } else {
                "This is normal for installers and software packages. It is reported so you know \
                 what extracting the archive would put on your machine, not because it is \
                 suspicious by itself."
                    .to_string()
            },
            r,
        ));
        risk = risk.max(r);
    }

    // --- 7. An archive wearing a document's name ---------------------------
    //
    // Distinct from the double-extension check: here the *outer* file claims to
    // be a document while actually being an archive full of programs.
    let outer_ext = std::path::Path::new(filename)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();
    if matches!(outer_ext.as_str(), "pdf" | "doc" | "txt" | "rtf" | "jpg" | "png")
        && !exec_entries.is_empty()
    {
        let r = 0.7;
        findings.push(Finding::new(
            Severity::High,
            "File claims to be a document but is an archive of programs",
            format!(
                "The name ends in .{outer_ext}, the contents are a ZIP archive, and {} entries \
                 inside can execute.",
                exec_entries.len()
            ),
            "Two separate disguises at once: the extension does not match the format, and what is \
             actually inside is runnable code. Neither happens by accident.",
            r,
        ));
        risk = risk.max(r);
    }

    let risk = risk.min(1.0);
    let flags = findings.iter().map(|f| f.one_line()).collect::<Vec<_>>();
    Ok(ArchiveResult {
        is_archive: true,
        flagged: !findings.is_empty(),
        flags,
        findings,
        risk,
        entry_count: entries.len(),
    })
}

/// Decide whether the declared sizes describe a decompression bomb.
///
/// Both conditions have to hold. Ratio alone is a false-positive machine: a
/// 10 KB file of zeros compresses about 1000:1 and is completely harmless.
/// Absolute size alone flags every large legitimate archive. It is the
/// combination — enormous expansion from almost nothing — that has no benign
/// explanation.
fn bomb_finding(compressed: u64, uncompressed: u64, entry_count: usize) -> Option<Finding> {
    const MIN_EXPANDED: u64 = 1024 * 1024 * 1024; // 1 GB
    const MIN_RATIO: u64 = 100;

    if compressed == 0 || uncompressed < MIN_EXPANDED {
        return None;
    }
    let ratio = uncompressed / compressed.max(1);
    if ratio < MIN_RATIO {
        return None;
    }

    Some(Finding::new(
        Severity::High,
        "Archive expands to an enormous size when extracted",
        format!(
            "{entry_count} entries totalling {} compressed expand to {} — a ratio of {ratio}:1.",
            human_bytes(compressed),
            human_bytes(uncompressed)
        ),
        "An archive this small that unpacks to this much is a decompression bomb. Extracting it \
         fills the disk and can hang whatever opens it. Aegis reads the sizes from the archive's \
         index rather than unpacking, so nothing was expanded to find this.",
        0.6,
    ))
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}...")
}

/// True when a name carries a Unicode character that reverses display order.
///
/// Checked as chars rather than bytes so the same override cannot slip through
/// by arriving in a different encoding.
pub fn contains_bidi_override(name: &str) -> bool {
    name.chars().any(|c| {
        matches!(
            c,
            '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO
                | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
                | '\u{200E}' | '\u{200F}' // LRM, RLM
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a ZIP with the given entries. Stored (uncompressed) so the bytes
    /// are predictable; the checks read the central directory, which is
    /// identical either way.
    ///
    /// `(name, content, encrypted, declared_uncompressed_override)`
    fn build_zip(entries: &[(&str, &[u8], bool, Option<u64>)]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();

        for (name, content, encrypted, uncompressed_override) in entries {
            let local_offset = out.len() as u32;
            let flags: u16 = if *encrypted { 1 } else { 0 };
            let declared = uncompressed_override.unwrap_or(content.len() as u64);
            let declared32 = u32::try_from(declared).unwrap_or(u32::MAX);

            // Local file header
            out.extend(b"PK\x03\x04");
            out.extend(20u16.to_le_bytes()); // version needed
            out.extend(flags.to_le_bytes());
            out.extend(0u16.to_le_bytes()); // stored
            out.extend([0u8; 4]); // time + date
            out.extend(0u32.to_le_bytes()); // crc
            out.extend((content.len() as u32).to_le_bytes());
            out.extend(declared32.to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes()); // extra len
            out.extend(name.as_bytes());
            out.extend(*content);

            // Central directory header
            central.extend(b"PK\x01\x02");
            central.extend(20u16.to_le_bytes()); // version made by
            central.extend(20u16.to_le_bytes()); // version needed
            central.extend(flags.to_le_bytes());
            central.extend(0u16.to_le_bytes()); // stored
            central.extend([0u8; 4]); // time + date
            central.extend(0u32.to_le_bytes()); // crc
            central.extend((content.len() as u32).to_le_bytes());
            central.extend(declared32.to_le_bytes());
            central.extend((name.len() as u16).to_le_bytes());
            central.extend(0u16.to_le_bytes()); // extra len
            central.extend(0u16.to_le_bytes()); // comment len
            central.extend(0u16.to_le_bytes()); // disk start
            central.extend(0u16.to_le_bytes()); // internal attrs
            central.extend(0u32.to_le_bytes()); // external attrs
            central.extend(local_offset.to_le_bytes());
            central.extend(name.as_bytes());
        }

        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend(&central);

        out.extend(b"PK\x05\x06");
        out.extend([0u8; 4]); // disk numbers
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend((entries.len() as u16).to_le_bytes());
        out.extend(cd_size.to_le_bytes());
        out.extend(cd_offset.to_le_bytes());
        out.extend(0u16.to_le_bytes()); // comment len
        out
    }

    #[test]
    fn ordinary_archive_is_not_flagged() {
        let zip = build_zip(&[
            ("docs/readme.txt", b"hello world, this is text", false, None),
            ("docs/notes.txt", b"more text here", false, None),
            ("images/logo.png", b"\x89PNG\r\n\x1a\nfake", false, None),
        ]);
        let res = analyse(&zip, "project.zip").unwrap();
        assert!(res.is_archive, "valid ZIP not recognised");
        assert_eq!(res.entry_count, 3);
        assert!(!res.flagged, "clean archive flagged: {:?}", res.flags);
        assert_eq!(res.risk, 0.0);
    }

    #[test]
    fn non_archive_is_reported_as_such() {
        for data in [
            b"\x89PNG\r\n\x1a\n".as_slice(),
            b"%PDF-1.4",
            b"MZ\x90\x00",
            b"",
            b"PK\x03\x04",       // header only, no central directory
            &[0xFFu8; 500],
        ] {
            let res = analyse(data, "x.bin").unwrap();
            assert!(!res.is_archive, "non-archive parsed as archive");
            assert!(!res.flagged);
        }
    }

    /// The case this module was written for. Before it, a ZIP containing
    /// `invoice.pdf.exe` scored exactly zero: the archive is a well-formed ZIP,
    /// its entropy is normal for a compressed file, and `structure.rs`
    /// deliberately does not flag executables inside archives.
    #[test]
    fn double_extension_inside_archive_is_caught() {
        let zip = build_zip(&[("invoice.pdf.exe", b"MZ\x90\x00payload", false, None)]);
        let res = analyse(&zip, "invoice.zip").unwrap();

        assert!(res.flagged, "disguised executable inside archive missed");
        assert!(res.risk >= 0.75, "risk too low: {}", res.risk);
        assert!(
            res.findings
                .iter()
                .any(|f| f.title.contains("disguised as a document")),
            "{:?}",
            res.findings
        );
    }

    /// A ZIP with an ordinary executable in it is an installer, not an attack.
    /// If this starts failing, every software download becomes a false
    /// positive and the signal is worthless.
    #[test]
    fn ordinary_installer_archive_stays_below_the_sandbox_threshold() {
        let mut entries: Vec<(&str, &[u8], bool, Option<u64>)> = vec![
            ("setup/setup.exe", b"MZ\x90\x00 installer", false, None),
            ("setup/data.cab", b"cabinet data here", false, None),
            ("setup/license.txt", b"license text", false, None),
            ("setup/readme.md", b"readme", false, None),
        ];
        entries.push(("setup/config.ini", b"[settings]", false, None));
        let res = analyse(&build_zip(&entries), "installer.zip").unwrap();
        assert!(
            res.risk < 0.4,
            "ordinary installer scored {} — that is a false positive on every software download: {:?}",
            res.risk,
            res.flags
        );
    }

    /// One executable alone at the root of an otherwise empty archive is the
    /// delivery shape, and scores higher than the same file inside a bundle.
    #[test]
    fn lone_root_executable_scores_above_a_bundle() {
        let lone = analyse(&build_zip(&[("update.exe", b"MZ\x90\x00", false, None)]), "u.zip")
            .unwrap();
        let bundle = analyse(
            &build_zip(&[
                ("app/app.exe", b"MZ\x90\x00", false, None),
                ("app/lib.dll", b"MZ\x90\x00", false, None),
                ("app/readme.txt", b"text", false, None),
                ("app/data.bin", b"data", false, None),
            ]),
            "b.zip",
        )
        .unwrap();

        assert!(
            lone.risk > bundle.risk,
            "delivery shape ({}) should outrank a bundle ({})",
            lone.risk,
            bundle.risk
        );
    }

    #[test]
    fn zip_slip_traversal_is_flagged() {
        for name in [
            "../../../Windows/System32/evil.dll",
            "..\\..\\startup\\run.bat",
            "/etc/cron.d/payload",
            "C:\\Windows\\Temp\\x.exe",
        ] {
            let res = analyse(&build_zip(&[(name, b"data", false, None)]), "a.zip").unwrap();
            assert!(res.flagged, "traversal {name:?} not flagged");
            assert!(
                res.findings.iter().any(|f| f.title.contains("outside the folder")),
                "traversal {name:?} produced wrong finding: {:?}",
                res.findings
            );
            assert!(res.risk >= 0.8);
        }
    }

    /// Ordinary relative paths must not trip the traversal check, or every
    /// archive with a folder in it becomes a critical finding.
    #[test]
    fn ordinary_paths_are_not_traversal() {
        for name in [
            "src/main.rs",
            "a/b/c/d.txt",
            "..hidden/file.txt", // leading dots, but not a `..` component
            "file..txt",
            "docs/v1.2/readme.md",
        ] {
            let res = analyse(&build_zip(&[(name, b"data", false, None)]), "a.zip").unwrap();
            assert!(
                !res.findings.iter().any(|f| f.title.contains("outside the folder")),
                "{name:?} wrongly flagged as traversal"
            );
        }
    }

    #[test]
    fn right_to_left_override_in_entry_name_is_flagged() {
        // Displays as "invoiceexe.pdf" while actually being an .exe
        let name = "invoice\u{202E}fdp.exe";
        let res = analyse(&build_zip(&[(name, b"MZ", false, None)]), "a.zip").unwrap();
        assert!(res.flagged);
        assert!(res.risk >= 0.85, "risk was {}", res.risk);
        assert!(
            res.findings.iter().any(|f| f.title.contains("display incorrectly")),
            "{:?}",
            res.findings
        );
    }

    /// Encrypted contents defeat every scanner, including the antivirus. That
    /// is the reason to report it, and the reason it is not decisive alone —
    /// people do legitimately password-protect archives.
    #[test]
    fn encrypted_entries_are_reported() {
        let zip = build_zip(&[("secret.docx", b"encrypted bytes", true, None)]);
        let res = analyse(&zip, "secret.zip").unwrap();
        assert!(res.flagged);
        assert!(
            res.findings.iter().any(|f| f.title.contains("password-protected")),
            "{:?}",
            res.findings
        );
        assert!(res.risk >= 0.5 && res.risk < 0.85, "risk was {}", res.risk);
    }

    /// Read from the index, never by expanding anything — the whole point is
    /// that identifying a bomb must not detonate it.
    #[test]
    fn decompression_bomb_is_identified_without_expanding_it() {
        let zip = build_zip(&[(
            "bomb.bin",
            &[0u8; 1024],
            false,
            Some(8 * 1024 * 1024 * 1024), // claims 8 GB from 1 KB
        )]);
        let res = analyse(&zip, "bomb.zip").unwrap();
        assert!(
            res.findings.iter().any(|f| f.title.contains("enormous size")),
            "bomb not identified: {:?}",
            res.findings
        );
    }

    /// A large archive that compresses normally is not a bomb. Ratio alone
    /// would flag this; requiring an enormous absolute expansion as well is
    /// what keeps ordinary large downloads out of the results.
    #[test]
    fn ordinary_large_archive_is_not_a_bomb() {
        // 2 KB compressing to 100 KB — a 50:1 ratio, below the threshold, and
        // nowhere near the 1 GB absolute floor.
        let zip = build_zip(&[("video.mkv", &[0u8; 2048], false, Some(2048 * 50))]);
        let res = analyse(&zip, "movie.zip").unwrap();
        assert!(
            !res.findings.iter().any(|f| f.title.contains("enormous size")),
            "50:1 ratio wrongly called a bomb"
        );

        // A genuinely large archive with a believable ratio is also fine.
        assert!(bomb_finding(1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024, 10).is_none());
        // Enormous expansion from almost nothing is not.
        assert!(bomb_finding(1024, 8 * 1024 * 1024 * 1024, 1).is_some());
    }

    /// The outer name lies AND the contents are runnable — two disguises.
    #[test]
    fn archive_wearing_a_document_extension_is_flagged() {
        let zip = build_zip(&[("run.exe", b"MZ\x90\x00", false, None)]);
        let res = analyse(&zip, "statement.pdf").unwrap();
        assert!(
            res.findings
                .iter()
                .any(|f| f.title.contains("claims to be a document")),
            "{:?}",
            res.findings
        );
        assert!(res.risk >= 0.7);
    }

    /// A .lnk inside an archive is the modern delivery vector — it carries an
    /// arbitrary command line and any icon it likes.
    #[test]
    fn shortcut_inside_archive_is_weighted_above_a_plain_executable() {
        let lnk = analyse(&build_zip(&[("invoice.lnk", b"L\0\0\0", false, None)]), "a.zip")
            .unwrap();
        let exe = analyse(&build_zip(&[("invoice.exe", b"MZ", false, None)]), "a.zip").unwrap();
        assert!(
            lnk.risk > exe.risk,
            "shortcut ({}) should outweigh a plain executable ({})",
            lnk.risk,
            exe.risk
        );
    }

    /// Every offset comes from the file. Truncation at any point, absurd
    /// counts, and garbage lengths must all produce a result rather than a
    /// panic.
    #[test]
    fn hostile_archives_never_panic() {
        let full = build_zip(&[
            ("a.txt", b"content", false, None),
            ("dir/b.exe", b"MZ\x90\x00", false, None),
        ]);

        for n in 0..full.len() {
            let _ = analyse(&full[..n], "x.zip").unwrap();
        }

        // Absurd entry count in the EOCD.
        let mut d = full.clone();
        let eocd = d.len() - 22;
        d[eocd + 10..eocd + 12].copy_from_slice(&0xFFFEu16.to_le_bytes());
        let _ = analyse(&d, "x.zip").unwrap();

        // Central directory offset pointing anywhere.
        for bad in [0u32, 1, 0xFFFF_FFFE, 0x7FFF_FFFF] {
            let mut d = full.clone();
            let eocd = d.len() - 22;
            d[eocd + 16..eocd + 20].copy_from_slice(&bad.to_le_bytes());
            let _ = analyse(&d, "x.zip").unwrap();
        }

        // Oversized name and extra lengths inside a central directory header.
        let mut d = full.clone();
        if let Some(cd) = d.windows(4).position(|w| w == b"PK\x01\x02") {
            d[cd + 28..cd + 30].copy_from_slice(&0xFFFFu16.to_le_bytes());
            d[cd + 30..cd + 32].copy_from_slice(&0xFFFFu16.to_le_bytes());
        }
        let _ = analyse(&d, "x.zip").unwrap();

        // Random bytes that happen to contain the signatures.
        let mut noise = vec![0x41u8; 4096];
        noise[100..104].copy_from_slice(b"PK\x05\x06");
        noise[500..504].copy_from_slice(b"PK\x01\x02");
        let _ = analyse(&noise, "x.zip").unwrap();
    }

    #[test]
    fn entry_helpers_handle_odd_names() {
        let e = |name: &str| ZipEntry {
            name: name.to_string(),
            compressed_size: 0,
            uncompressed_size: 0,
            encrypted: false,
            is_directory: false,
        };
        assert_eq!(e("a/b/c.txt").file_name(), "c.txt");
        assert_eq!(e("c.txt").file_name(), "c.txt");
        assert_eq!(e("a\\b\\c.txt").file_name(), "c.txt");
        assert_eq!(e("noext").extension(), None);
        assert_eq!(e("a/b.TXT").extension().as_deref(), Some("txt"));
        assert!(e("root.exe").is_at_root());
        assert!(!e("dir/root.exe").is_at_root());
    }
}
