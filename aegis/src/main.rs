use std::io::{self, Read};
use serde::Deserialize;
use base64::{engine::general_purpose, Engine as _};

// This line tells Rust: "Go find a file named scanner.rs and include it here"
mod scanner; 

#[derive(Deserialize, Debug)]
struct IncomingMessage {
    #[serde(rename = "type")] 
    msg_type: String,
    filename: Option<String>, // Make sure this is here for the extension check!
    payload: Option<String>, 
}

fn read_input() -> io::Result<Vec<u8>> {
    // 1. Read the 4-byte length header
    let mut length_bytes = [0u8; 4];
    io::stdin().read_exact(&mut length_bytes)?;

    // 2. Convert to number (Native Endian)
    let len = u32::from_ne_bytes(length_bytes) as usize;

    // 3. Security check: 64MiB limit
    if len > 64 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Message too large"));
    }

    // 4. Read the actual JSON message
    let mut buffer = vec![0u8; len];
    io::stdin().read_exact(&mut buffer)?;

    Ok(buffer)
}

fn handle_payload(msg: IncomingMessage) {
    
    if msg.msg_type == "DATA" {
        if let Some(encoded_data) = msg.payload {
            match general_purpose::STANDARD.decode(encoded_data) {
                Ok(binary_file) => {
                    // Extract the filename safely or use a placeholder
                    let fname = msg.filename.as_deref().unwrap_or("unknown_file");
                    
                    // CALLING YOUR SCANNER HERE:
                    scanner::scan_file(&binary_file, fname);
                }
                Err(e) => eprintln!("[Aegis] Base64 Decoding Error: {}", e),
            }
        }
    }
}

fn main() {
    eprintln!("[Aegis] Native Host Active. Monitoring stdin...");

    loop {
        match read_input() {
            Ok(buffer) => {
                match serde_json::from_slice::<IncomingMessage>(&buffer) {
                    Ok(msg) => handle_payload(msg),
                    Err(e) => eprintln!("[Aegis] JSON Parse Error: {}", e),
                }
            }
            Err(e) => {
                eprintln!("[Aegis] Connection lost or error: {}", e);
                break; 
            }
        }
    }
}