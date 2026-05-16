use reqwest;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use tokio;

// Import your custom modules
mod hcs;
mod scanner;

#[derive(Deserialize)]
struct DownloadStruct {
    url: String,
    filename: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // 1. READ THE MESSAGE FROM CHROME
    // Native Messaging sends a 4-byte header containing the length of the JSON
    let mut length_buf = [0u8; 4];
    if let Err(_) = io::stdin().read_exact(&mut length_buf) {
        return Ok(()); // Exit gracefully if Chrome closes the pipe
    }

    let length = u32::from_le_bytes(length_buf);

    let mut json_buf = vec![0u8; length as usize];
    io::stdin().read_exact(&mut json_buf)?;

    // Parse the JSON into our struct
    let request: DownloadStruct = serde_json::from_slice(&json_buf)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // 2. INITIALIZE THE STREAMING CLIENT
    let client = reqwest::Client::new();
    let mut res = client
        .get(&request.url)
        .send()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // The "Cage" - Temporary quarantine file
    let tmp_path = "C:\\Aegis\\quarantine\\scan.tmp";
    let mut file = std::fs::File::create(tmp_path)?;

    // 3. THE STREAMING SIEVE-AND-CAGE LOOP
    let mut is_first = true;
    let mut is_malicious = false;

    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    {
        // LEVEL 1 & 2: Static & Forensic Scan
        // If the scanner returns 'false', the file is flagged as malicious
        if !scanner::deep_forensic_scan(&chunk, &request.filename, is_first) {
            is_malicious = true;
            break; // THE KILL SWITCH: Break loop, stopping the network stream
        }

        is_first = false;

        // Simple XOR Cipher (Key: 0xAC)
        fn xor_buffer(data: &mut [u8]) {
            for byte in data.iter_mut() {
                *byte ^= 0xAC;
            }
        }
        // Level 3 & 4: Write the chunk to disk (The Cage)
        file.write_all(&chunk)?;
    }

    // 4. THE VERDICT
    if is_malicious {
        // Cleanup: Remove the dangerous partial file
        drop(file); // Close file handle before deleting
        let _ = std::fs::remove_file(tmp_path);

        send_response(
            "BLOCKED",
            "Critical: File identity mismatch or malicious intent detected.",
        );
    } else {
        // Level 5: Behavioral Analysis (The Bubble)
        // Static scan passed, now we run it in the HCS Sandbox
        println!("[Aegis] Static scan passed. Moving to HCS Sandbox...");

        match hcs::start_behavioral_scan(tmp_path) {
            Ok(_) => send_response("COMPLETE", "File analyzed and verified clean.")?,
            Err(e) => send_response("ERROR", &format!("Sandbox execution failed: {}", e))?,
        }
    }

    Ok(())
}

/// Helper function to send JSON responses back to the Chrome Extension
fn send_response(status: &str, verdict: &str) -> io::Result<()> {
    let response = serde_json::json!({
        "status": status,
        "verdict": verdict
    });

    let response_str = response.to_string();
    let res_bytes = response_str.as_bytes();
    let res_len = res_bytes.len() as u32;

    // Standard Native Messaging Output: [4-byte length] + [JSON data]
    io::stdout().write_all(&res_len.to_le_bytes())?;
    io::stdout().write_all(res_bytes)?;
    io::stdout().flush()?;

    Ok(())
}
