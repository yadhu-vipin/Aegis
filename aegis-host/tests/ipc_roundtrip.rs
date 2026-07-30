//! End-to-end native-messaging integration tests.
//!
//! These spawn the real `aegis-host` binary and speak Chrome's framing to it
//! over stdin/stdout. They exist because this project's characteristic bugs are
//! invisible to code review and only appear when the thing actually runs:
//!
//!   * log output leaking onto stdout silently corrupted the frame channel —
//!     every test here would fail to parse a frame if that regressed
//!   * `statvfs` called against a path that did not exist yet
//!
//! Per the build spec's bar, the suite covers hostile input rather than just
//! the happy path: oversized length fields, out-of-order sequence numbers,
//! malformed payloads, and a mid-transfer disconnect.

use std::io::{Read, Write};
use std::process::{Command, Stdio};

/// Repo root — the binary needs `aegis.toml` findable from its working dir.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aegis-host should have a parent directory")
        .to_path_buf()
}

/// Encode one Chrome native-messaging frame: 4-byte LE length + JSON.
fn frame(value: &serde_json::Value) -> Vec<u8> {
    let json = serde_json::to_vec(value).expect("serialize test message");
    let mut out = (json.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&json);
    out
}

/// Parse every complete frame out of a raw stdout buffer.
///
/// Deliberately strict: a stray byte on stdout (e.g. a `println!` that should
/// have been `eprintln!`) desynchronises the length prefix and shows up here as
/// a parse failure rather than being silently tolerated.
fn parse_frames(buf: &[u8]) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= buf.len() {
        let len = u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        assert!(
            len <= 1_048_576,
            "frame claims {len} bytes, above Chrome's 1MB ceiling — stdout is probably \
             desynchronised, which usually means something logged to stdout instead of stderr"
        );
        if pos + len > buf.len() {
            panic!(
                "truncated frame: header claims {len} bytes but only {} remain. \
                 stdout so far: {:?}",
                buf.len() - pos,
                String::from_utf8_lossy(buf)
            );
        }
        let value: serde_json::Value = serde_json::from_slice(&buf[pos..pos + len])
            .unwrap_or_else(|e| panic!("frame body is not valid JSON: {e}"));
        out.push(value);
        pos += len;
    }
    assert_eq!(
        pos,
        buf.len(),
        "{} trailing byte(s) after the last complete frame — stdout contains non-frame data",
        buf.len() - pos
    );
    out
}

/// Send raw bytes to a fresh host process, close stdin, and collect its frames.
fn run_host(input: &[u8]) -> (Vec<serde_json::Value>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_aegis-host"))
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn aegis-host");

    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(input)
        .expect("write frames to host stdin");
    // stdin dropped here -> pipe closes, host sees EOF.

    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("stdout piped")
        .read_to_end(&mut stdout)
        .expect("read host stdout");

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr piped")
        .read_to_string(&mut stderr)
        .expect("read host stderr");

    let _ = child.wait();
    (parse_frames(&stdout), stderr)
}

fn start_download(session: &str, filename: &str, len: usize) -> serde_json::Value {
    serde_json::json!({
        "type": "START_DOWNLOAD",
        "session_id": session,
        "filename": filename,
        "content_length": len,
    })
}

fn chunk(session: &str, seq: u64, is_last: bool, data: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    serde_json::json!({
        "type": "CHUNK",
        "session_id": session,
        "seq": seq,
        "is_last": is_last,
        "data": base64::engine::general_purpose::STANDARD.encode(data),
    })
}

fn verdicts(frames: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    frames
        .iter()
        .filter(|f| f.get("type").and_then(|t| t.as_str()) == Some("VERDICT"))
        .collect()
}

fn status_of(frame: &serde_json::Value) -> &str {
    frame.get("status").and_then(|s| s.as_str()).unwrap_or("")
}

// ---------------------------------------------------------------------------

/// Happy path: a benign PNG should ack its chunk and produce a verdict, and
/// stdout must contain nothing but well-formed frames.
#[test]
fn benign_png_round_trips() {
    let png = {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(std::iter::repeat_n(0u8, 1016));
        v
    };
    let sid = "test-benign";
    let mut input = frame(&start_download(sid, "photo.png", png.len()));
    input.extend(frame(&chunk(sid, 0, true, &png)));

    let (frames, stderr) = run_host(&input);

    assert!(
        frames
            .iter()
            .any(|f| f.get("type").and_then(|t| t.as_str()) == Some("CHUNK_ACK")),
        "expected a CHUNK_ACK for backpressure; frames={frames:?} stderr={stderr}"
    );
    let v = verdicts(&frames);
    assert_eq!(v.len(), 1, "expected exactly one VERDICT; frames={frames:?}");
    assert_eq!(
        v[0].get("session_id").and_then(|s| s.as_str()),
        Some(sid),
        "verdict must echo the session id"
    );
}

/// EICAR must be blocked. This is the canonical smoke test for this project —
/// it is the case that silently passed through in an earlier build.
#[test]
fn eicar_is_blocked() {
    // Split so this source file is not itself flagged by AV scanners.
    let eicar = format!(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}}${}-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        "EICAR"
    );
    let sid = "test-eicar";
    let mut input = frame(&start_download(sid, "sample.txt", eicar.len()));
    input.extend(frame(&chunk(sid, 0, true, eicar.as_bytes())));

    let (frames, stderr) = run_host(&input);
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "no verdict returned; stderr={stderr}");
    assert_eq!(
        status_of(v[0]),
        "BLOCKED",
        "EICAR must be BLOCKED, got {:?}",
        v[0]
    );
}

/// An executable wearing a .jpg extension must not be released.
#[test]
fn exe_masquerading_as_jpg_is_not_released() {
    let mut pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    pe.extend(std::iter::repeat_n(0u8, 512));
    let sid = "test-trojan";
    let mut input = frame(&start_download(sid, "holiday.jpg", pe.len()));
    input.extend(frame(&chunk(sid, 0, true, &pe)));

    let (frames, stderr) = run_host(&input);
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "no verdict returned; stderr={stderr}");
    assert_ne!(
        status_of(v[0]),
        "COMPLETE",
        "an MZ executable named .jpg must never be released; got {:?}",
        v[0]
    );
}

/// Out-of-order sequence numbers must be rejected, not silently accepted.
/// Previously `seq` was parsed and echoed in the ack but never validated, so
/// an attacker controlled the byte order of the quarantined file.
#[test]
fn out_of_order_sequence_is_rejected() {
    let sid = "test-seq";
    let mut input = frame(&start_download(sid, "data.bin", 2048));
    input.extend(frame(&chunk(sid, 0, false, b"first chunk data")));
    // Skip seq 1 entirely and jump to 5.
    input.extend(frame(&chunk(sid, 5, true, b"out of order data")));

    let (frames, stderr) = run_host(&input);
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "no verdict returned; stderr={stderr}");
    let last = v.last().expect("at least one verdict");
    assert_eq!(
        status_of(last),
        "REJECTED_MALFORMED",
        "out-of-order chunk must be rejected; got {last:?}"
    );
}

/// A duplicate/replayed chunk is the same violation as a gap.
#[test]
fn replayed_sequence_is_rejected() {
    let sid = "test-replay";
    let mut input = frame(&start_download(sid, "data.bin", 2048));
    input.extend(frame(&chunk(sid, 0, false, b"chunk zero")));
    input.extend(frame(&chunk(sid, 0, true, b"chunk zero again")));

    let (frames, _) = run_host(&input);
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "expected a rejection verdict");
    assert_eq!(
        status_of(v.last().unwrap()),
        "REJECTED_MALFORMED",
        "a replayed seq must be rejected"
    );
}

/// A transfer that ends without `is_last` is truncated. It must BLOCK.
///
/// This is the regression guard for the truncation attack: the old code broke
/// out of the loop and scored the partial file, and partial files score low, so
/// "send one benign chunk then disconnect" reliably produced COMPLETE.
#[test]
fn truncated_transfer_is_blocked_not_released() {
    let sid = "test-truncated";
    let mut input = frame(&start_download(sid, "big.bin", 10_000_000));
    // Benign-looking first chunk, then the pipe simply closes. No is_last.
    input.extend(frame(&chunk(sid, 0, false, b"harmless looking prefix data")));

    let (frames, stderr) = run_host(&input);
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "no verdict on truncated transfer; stderr={stderr}");
    let last = v.last().unwrap();
    assert_eq!(
        status_of(last),
        "BLOCKED",
        "a truncated transfer must BLOCK, never be released; got {last:?}"
    );
    assert_ne!(
        status_of(last),
        "COMPLETE",
        "truncated transfer was released — the truncation attack has regressed"
    );
}

/// A length prefix above Chrome's 1MB ceiling must be refused before any
/// allocation happens (CWE-789). The host must not try to allocate 4GB.
#[test]
fn oversized_length_prefix_is_refused() {
    let mut input = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
    input.extend_from_slice(b"{}"); // nowhere near the claimed length

    let (frames, stderr) = run_host(&input);
    // The host must not hang, must not OOM, and must say something coherent.
    assert!(
        !frames.is_empty(),
        "host produced no frame for an oversized length prefix; stderr={stderr}"
    );
    let combined = format!("{frames:?}{stderr}");
    assert!(
        combined.contains("exceeds maximum") || combined.contains("malformed"),
        "expected an explicit oversize rejection; frames={frames:?} stderr={stderr}"
    );
}

/// Chunk payloads that are not valid base64 are attacker-controlled input and
/// must produce a clean rejection, never a panic.
#[test]
fn malformed_base64_is_rejected_not_panicked() {
    let sid = "test-b64";
    let mut input = frame(&start_download(sid, "data.bin", 1024));
    input.extend(frame(&serde_json::json!({
        "type": "CHUNK",
        "session_id": sid,
        "seq": 0,
        "is_last": true,
        "data": "!!!! this is not base64 !!!!",
    })));

    let (frames, stderr) = run_host(&input);
    assert!(
        !stderr.contains("panicked"),
        "host panicked on malformed base64 — a panic is an availability failure \
         for a security tool; stderr={stderr}"
    );
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "expected a rejection verdict");
    assert_eq!(status_of(v.last().unwrap()), "REJECTED_MALFORMED");
}

/// An unknown message type must be rejected rather than ignored.
#[test]
fn unknown_message_type_is_rejected() {
    let input = frame(&serde_json::json!({ "type": "TOTALLY_MADE_UP" }));
    let (frames, _) = run_host(&input);
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "expected a rejection for an unknown type");
    assert_eq!(status_of(v[0]), "REJECTED_MALFORMED");
}

/// The quarantine directory name is duplicated across a language boundary:
/// `quarantine.subdir` in aegis.toml, and `QUARANTINE_SUBDIR` in the
/// extension's background.js. They cannot share a constant, so they can drift —
/// and they did. background.js said "aegis-quarantine" (hyphen) while
/// aegis.toml said "aegis_quarantine" (underscore), so the host rejected every
/// legitimate download as being outside the quarantine root.
///
/// Nothing else catches this: both files are individually valid, the extension
/// loads fine, and the host runs fine. It only shows up as "every download is
/// mysteriously rejected".
#[test]
fn quarantine_subdir_matches_config() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root");

    let toml_src = std::fs::read_to_string(root.join("aegis.toml")).expect("read aegis.toml");
    let cfg: toml::Value = toml_src.parse().expect("parse aegis.toml");
    let configured = cfg
        .get("quarantine")
        .and_then(|q| q.get("subdir"))
        .and_then(|s| s.as_str())
        .expect("aegis.toml [quarantine].subdir");

    let js = std::fs::read_to_string(root.join("extension/background.js"))
        .expect("read background.js");
    let line = js
        .lines()
        .find(|l| l.contains("const QUARANTINE_SUBDIR"))
        .expect("background.js must define QUARANTINE_SUBDIR");
    let js_value = line
        .split('"')
        .nth(1)
        .expect("QUARANTINE_SUBDIR must be a double-quoted string literal");

    assert_eq!(
        js_value, configured,
        "quarantine directory name has drifted: background.js says {js_value:?} but \
         aegis.toml says {configured:?}. The host resolves the quarantine root from \
         aegis.toml, so every download would be rejected as out-of-root."
    );
}

/// A message with no `type` field at all.
#[test]
fn missing_type_field_is_rejected() {
    let input = frame(&serde_json::json!({ "session_id": "x" }));
    let (frames, _) = run_host(&input);
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "expected a rejection for a type-less message");
    assert_eq!(status_of(v[0]), "REJECTED_MALFORMED");
}
