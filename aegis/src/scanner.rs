use std::path::Path;

/// The main entry point for scanning a file.
/// We pass 'data' as a reference (&Vec<u8>) to avoid copying the whole file in memory again.
pub fn scan_file(data: &Vec<u8>, filename: &str) {
    // 1. Minimum Size Check
    // If a file is less than 4 bytes, it can't possibly have a valid Magic Number.
    if data.len() < 4 {
        eprintln!("[Scanner] File too small to analyze.");
        return;
    }

    // 2. Identify the "Real" identity (Magic Bytes)
    // We "peek" at the first 4 bytes of the binary data.
    let magic_bytes = &data[0..4];
    
    let real_type = match magic_bytes {
        // [0x4D, 0x5A, ..] = "MZ" in Hex. This is a Windows Executable (EXE/DLL).
        [0x4D, 0x5A, ..] => "exe",
        
        // [0x25, 0x50, 0x44, 0x46] = "%PDF" in Hex. This is a PDF document.
        [0x25, 0x50, 0x44, 0x46] => "pdf",
        
        // [0x50, 0x4B, 0x03, 0x04] = "PK.." This is a ZIP file or a modern Office Doc (.docx).
        [0x50, 0x4B, 0x03, 0x04] => "zip",
        
        // If it doesn't match our list, we label it unknown.
        _ => "unknown",
    };

    // 3. Identify the "Claimed" identity (File Extension)
    let claimed_ext = get_extension(filename);

    eprintln!("[Scanner] Checking: {} (Detected: {}, Claimed: {})", filename, real_type, claimed_ext);

    // 4. THE CROSS-EXAMINATION (Security Logic)
    // This is where we catch the "Lies."
    perform_security_check(real_type, &claimed_ext);
}

/// Helper function to safely extract the extension from a filename.
fn get_extension(filename: &str) -> String {
    Path::new(filename)
        .extension()                // Gets the part after the dot
        .and_then(|s| s.to_str())     // Converts OsStr to &str
        .unwrap_or("")               // If no extension, return empty string
        .to_lowercase()              // Normalize to lowercase (JPG vs jpg)
}

/// The logic gate that flags suspicious mismatches.
fn perform_security_check(real_type: &str, claimed_ext: &str) {
    match (real_type, claimed_ext) {
        // Case: It's an EXE, but trying to look like something else.
        ("exe", ext) if ext != "exe" => {
            eprintln!("[Scanner] 🚨 ALERT: TROJAN DETECTED! Executable masquerading as .{}", ext);
        }
        
        // Case: It's a ZIP/Archive, but hidden as a document.
        ("zip", ext) if ext != "zip" && ext != "docx" && ext != "xlsx" => {
            eprintln!("[Scanner] ⚠️ WARNING: Hidden Archive detected inside .{}", ext);
        }

        // Case: Unknown binary data in a text-based file.
        ("unknown", "txt") | ("unknown", "csv") => {
            eprintln!("[Scanner] ℹ️ Note: Non-text bytes found in a text file.");
        }

        // Case: Everything matches.
        (real, ext) if real == ext => {
            eprintln!("[Scanner] ✅ File identity verified.");
        }

        // Case: Fallback for everything else.
        _ => {
            eprintln!("[Scanner] Analysis complete. No major mismatches found.");
        }
    }
}
pub fn detect_dangerous_intent(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    
    // These are the Windows API calls malware loves
    let red_flags = [
        "CreateRemoteThread", // Used for Process Injection
        "SetWindowsHookEx",   // Used for Keylogging
        "RegSetValue",        // Used for Persistence (Autostart)
        "InternetOpen",       // Used to call home
    ];

    for flag in red_flags {
        if text.contains(flag) {
            eprintln!("[Scanner] 🚩 CRITICAL: Found dangerous API reference: {}", flag);
            eprintln!("[Scanner] Escalating to HCS Sandbox for behavioral analysis...");
        }
    }
}