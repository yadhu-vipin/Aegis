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
];

/// Scan a chunk (and optionally a small prefix from the previous chunk for
/// cross-boundary context) for dangerous intent markers.
///
/// `context_prefix` is typically the last N bytes of the previous chunk, so
/// patterns split across a chunk boundary are not missed.
pub fn detect_dangerous_intent(data: &[u8], context_prefix: Option<&[u8]>) -> Result<IntentResult> {
    // Build the text we'll search — prefix + current chunk, lossy-decoded
    // so non-UTF8 bytes become replacement characters (no panic).
    let text: std::borrow::Cow<str> = if let Some(prefix) = context_prefix {
        let combined: Vec<u8> = prefix.iter().chain(data.iter()).copied().collect();
        std::borrow::Cow::Owned(String::from_utf8_lossy(&combined).into_owned())
    } else {
        String::from_utf8_lossy(data)
    };

    let mut flags: Vec<String> = Vec::new();
    let mut cumulative_risk: f32 = 0.0;

    for &(pattern, risk, description) in WINAPI_RED_FLAGS {
        if text.contains(pattern) {
            tracing::warn!(
                pattern = pattern,
                risk = risk,
                description = description,
                "Intent flag triggered"
            );
            flags.push(format!("[risk={:.2}] {}: {}", risk, pattern, description));
            // Use saturation arithmetic — multiple flags accumulate but cap at 1.0
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
