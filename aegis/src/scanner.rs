use std::path::Path;

/// The main entry point for static identity verification.
/// We use a byte slice &[u8] so we can scan 1MB chunks without copying them.
pub fn scan_file(data: &[u8], filename: &str) {
    // 1. Minimum Size Check
    // Prevents crashing if the chunk is too small to have a header.
    if data.len() < 4 {
        eprintln!("[Scanner] Chunk too small for identity verification.");
        return;
    }

    // 2. Identify the "Real" identity via Magic Bytes (The Sieve)
    let magic_bytes = &data[0..4];
    
    let real_type = match magic_bytes {
        // MZ Header = Windows Executable
        [0x4D, 0x5A, ..] => "exe",
        
        // %PDF Header
        [0x25, 0x50, 0x44, 0x46] => "pdf",
        
        // PK.. Header (ZIP or Office Docs)
        [0x50, 0x4B, 0x03, 0x04] => "zip",
        
        _ => "unknown",
    };

    // 3. Identify the "Claimed" identity from the filename
    let claimed_ext = get_extension(filename);

    eprintln!("[Scanner] Checking: {} (Detected: {}, Claimed: {})", filename, real_type, claimed_ext);

    // 4. THE CROSS-EXAMINATION
    // Catching Trojans masquerading as innocent files.
    perform_security_check(real_type, &claimed_ext);
}

/// Helper function to safely extract the extension from a filename.
fn get_extension(filename: &str) -> String {
    Path::new(filename)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase()
}

/// The logic gate that flags suspicious mismatches.
fn perform_security_check(real_type: &str, claimed_ext: &str) {
    match (real_type, claimed_ext) {
        // Trojan Check: Program hiding as a document/image
        ("exe", ext) if ext != "exe" => {
            eprintln!("[Scanner] 🚨 ALERT: TROJAN DETECTED! Executable masquerading as .{}", ext);
        }
        
        // Archive Check: Zip hiding as a Word/Excel doc
        ("zip", ext) if ext != "zip" && ext != "docx" && ext != "xlsx" => {
            eprintln!("[Scanner] ⚠️ WARNING: Hidden Archive detected inside .{}", ext);
        }

        // Integrity Check: Binary data inside a plain text file
        ("unknown", "txt") | ("unknown", "csv") => {
            eprintln!("[Scanner] ℹ️ Note: Non-text bytes found in a text-based format.");
        }

        // Clean Match
        (real, ext) if real == ext => {
            eprintln!("[Scanner] ✅ File identity verified.");
        }

        _ => {
            eprintln!("[Scanner] Static analysis complete. No major mismatches.");
        }
    }
}

/// Scans the binary content for "Red Flags" (Suspicious API strings).
/// This is called on EVERY 1MB chunk.
pub fn detect_dangerous_intent(data: &[u8]) {
    // Convert binary to readable text (lossy means it skips weird characters)
    let text = String::from_utf8_lossy(data);
    
    // WinAPI calls commonly used by malware for injection and persistence
    let red_flags = [
        "CreateRemoteThread", // Injection
        "SetWindowsHookEx",   // Keylogging
        "RegSetValue",        // Persistence (Registry)
        "InternetOpen",       // C2 Call-home
    ];

    for flag in red_flags {
        if text.contains(flag) {
            eprintln!("[Scanner] 🚩 CRITICAL: Found dangerous API reference: {}", flag);
            eprintln!("[Scanner] Potential behavioral threat detected in current chunk.");
        }
    }
}