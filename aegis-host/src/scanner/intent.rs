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

/// WinAPI strings commonly used by malware.
/// These appearing as embedded strings in a binary are high-confidence signals.
static WINAPI_RED_FLAGS: &[(&str, f32, &str)] = &[
    ("CreateRemoteThread",     0.6,  "Process injection via remote thread"),
    ("VirtualAllocEx",         0.5,  "Remote memory allocation — injection precursor"),
    ("WriteProcessMemory",     0.5,  "Remote memory write — injection precursor"),
    ("SetWindowsHookEx",       0.55, "Keylogger / global hook installation"),
    ("RegSetValue",            0.3,  "Registry write — possible persistence"),
    ("RegCreateKey",           0.25, "Registry key creation — possible persistence"),
    ("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0.7, "Autorun registry key — persistence"),
    ("InternetOpenA",          0.4,  "C2 call-home (WININET)"),
    ("InternetOpenW",          0.4,  "C2 call-home (WININET)"),
    ("URLDownloadToFile",      0.55, "Downloads additional payload"),
    ("ShellExecuteA",          0.35, "Shell execution — dropper behavior"),
    ("ShellExecuteW",          0.35, "Shell execution — dropper behavior"),
    ("CreateService",          0.5,  "Service installation — persistence"),
    ("OpenSCManager",          0.45, "Service control manager access"),
    ("IsDebuggerPresent",      0.35, "Anti-debug / sandbox evasion"),
    ("CheckRemoteDebuggerPresent", 0.4, "Anti-debug / sandbox evasion"),
    ("NtQueryInformationProcess",  0.4, "Anti-debug / sandbox evasion via NtAPI"),
    ("powershell",             0.35, "PowerShell invocation in binary"),
    ("cmd.exe",                0.3,  "CMD shell invocation in binary"),
    ("wscript.exe",            0.45, "WScript invocation — script dropper"),
    ("mshta.exe",              0.5,  "MSHTA execution — LOLBin abuse"),
    ("certutil",               0.45, "Certutil — LOLBin, often used to decode payloads"),
    ("bitsadmin",              0.45, "BITS job creation — payload download / persistence"),
    // Linux/Unix patterns
    ("/etc/passwd",            0.55, "Passwd file access"),
    ("/etc/shadow",            0.7,  "Shadow file access — credential theft"),
    ("chmod 777",              0.4,  "World-writable permission set"),
    ("curl | bash",            0.7,  "Pipe-to-bash — remote code execution pattern"),
    ("wget -O- |",             0.65, "Pipe-to-shell — remote code execution pattern"),
    ("nc -e /bin/sh",          0.8,  "Netcat reverse shell"),
    ("nc -e /bin/bash",        0.8,  "Netcat reverse shell"),
    ("/dev/tcp/",              0.7,  "Bash TCP socket — reverse shell pattern"),
    // Standard Antivirus Test Signature
    ("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", 1.0, "EICAR Antivirus Test File signature"),
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
    let mut cumulative_risk: f32 = 0.0;

    for &(pattern, risk, description) in WINAPI_RED_FLAGS {
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
                description = description,
                "Intent flag triggered"
            );
            flags.push(format!("[risk={risk:.2}] {pattern} ({enc}): {description}"));
            // Saturating: multiple flags accumulate but cap at 1.0
            cumulative_risk = (cumulative_risk + risk).min(1.0);
        }
    }

    let flagged = !flags.is_empty();
    Ok(IntentResult {
        flagged,
        flags,
        risk: cumulative_risk,
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
        assert!(res.flagged);
        assert!(res.risk >= 0.6);
    }

    #[test]
    fn test_cross_boundary_pattern() {
        let prefix = b"Executing CreateRemote";
        let chunk = b"Thread now!";
        let res = detect_dangerous_intent(chunk, Some(prefix)).unwrap();
        assert!(res.flagged);
        assert!(res.risk >= 0.6);
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
        assert!(res.risk >= 0.6, "risk was {}", res.risk);
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
