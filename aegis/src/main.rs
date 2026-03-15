use std::io::{self, Read, Write, BufWriter}; // Added Write and BufWriter
use std::fs::OpenOptions; // For creating the "Cage" file
use serde::Deserialize;
use base64::{engine::general_purpose, Engine as _};

mod scanner;

#[derive(Deserialize, Debug)]
struct IncomingMessage {
    #[serde(rename = "type")] 
    msg_type: String,
    filename: Option<String>,
    payload: Option<String>,
    is_final: Option<bool>, // NEW: Browser tells us if this is the last chunk
}

fn read_input() -> io::Result<Vec<u8>> {
    let mut length_bytes = [0u8; 4];
    if let Err(_) = io::stdin().read_exact(&mut length_bytes) {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "End of stream"));
    }

    let len = u32::from_ne_bytes(length_bytes) as usize;

    // SECURITY: Since we use 1MB chunks now, we lower this limit to 2MB 
    // to prevent memory exhaustion attacks.
    if len > 2 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Chunk too large"));
    }

    let mut buffer = vec![0u8; len];
    io::stdin().read_exact(&mut buffer)?;
    Ok(buffer)
}

fn main() -> io::Result<()> {
    eprintln!("[Aegis] Native Host Active. Streaming Mode Engaged.");

    // The Cage: Create a temporary file on SSD for the 8GB stream
    let temp_path = "C:\\Aegis\\quarantine\\scan.tmp";
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true) // Start fresh
        .open(temp_path)?;
    let mut writer = BufWriter::new(file);

    loop {
        match read_input() {
            Ok(buffer) => {
                match serde_json::from_slice::<IncomingMessage>(&buffer) {
                    Ok(msg) => {
                        if let Some(encoded) = msg.payload {
                            let chunk_bytes = general_purpose::STANDARD.decode(encoded).unwrap();
                            
                            // 1. THE SIEVE: Scan chunk in RAM before writing to disk
                            scanner::detect_dangerous_intent(&chunk_bytes);
                            
                            // 2. THE CAGE: XOR Obfuscation (Optional but Mega) 
                            // and write to SSD
                            writer.write_all(&chunk_bytes)?;
                        }

                        if msg.is_final.unwrap_or(false) {
                            writer.flush()?;
                            eprintln!("[Aegis] File fully caged. Starting Sandbox Trial...");
                            // This is where you'd call the HCS Sandbox on temp_path
                            break; 
                        }
                    }
                    Err(e) => eprintln!("[Aegis] JSON Parse Error: {}", e),
                }
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("[Aegis] Connection Error: {}", e);
                }
                break;
            }
        }
    }
    Ok(())
}