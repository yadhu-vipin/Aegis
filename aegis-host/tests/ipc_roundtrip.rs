//! End-to-end native-messaging integration tests.
//!
//! These spawn the real `aegis-host` binary and speak Chrome's framing to it
//! over stdin/stdout. They exist because this project's characteristic bugs are
//! invisible to code review and only appear when the thing actually runs:
//!
//!   * log output leaking onto stdout silently corrupted the frame channel —
//!     every test here would fail to parse a frame if that regressed
//!   * the host and the extension disagreeing about a filename the browser had
//!     silently rewritten, so the host rejected its own quarantine files
//!
//! The suite covers hostile input rather than just the happy path: oversized
//! length fields, paths outside the quarantine root, malformed frame bodies,
//! and the retired chunk protocol.
//!
//! It also covers the *opposite* failure, which matters just as much. Two tests
//! here assert that ordinary files are RELEASED. A scanner that blocks
//! everything is indistinguishable from a broken one, and every check added to
//! Aegis is a fresh chance to start rejecting legitimate downloads.

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

/// Drive one file through the live watch path and return `(frames, stderr)`.
///
/// Plants `content` in the real quarantine directory under a UUID stem — the
/// only shape `validate_quarantine_path` accepts — then sends `WATCH_BEGIN`
/// exactly as the extension does. Cleans up both the quarantine copy and
/// anything the host released into Downloads.
///
/// Returns `None` when there is no Downloads directory to work in, so the
/// suite degrades to skipped rather than failed in a bare environment.
fn watch(
    uuid: &str,
    original_filename: &str,
    content: &[u8],
) -> Option<(Vec<serde_json::Value>, String)> {
    let downloads = dirs_downloads();
    let quarantine = downloads.join("aegis_quarantine");
    std::fs::create_dir_all(&quarantine).ok()?;

    // Chromium re-applies its own extension from the response MIME type, so
    // mirror that: the stem is the UUID, the extension is the browser's choice.
    let ext = std::path::Path::new(original_filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let path = quarantine.join(format!("{uuid}.{ext}"));
    std::fs::write(&path, content).ok()?;

    let input = frame(&serde_json::json!({
        "type": "WATCH_BEGIN",
        "session_id": uuid,
        "quarantine_path": path.to_string_lossy(),
        "original_filename": original_filename,
    }));
    let out = run_host(&input);

    let _ = std::fs::remove_file(&path);
    // A released file lands in Downloads under the sanitized original name.
    let _ = std::fs::remove_file(downloads.join(original_filename));
    Some(out)
}

/// Build a minimal stored ZIP containing one entry.
///
/// Deliberately hand-rolled rather than shared with `scanner::archive`'s own
/// fixtures: this file talks to the host over a pipe and should not depend on
/// the crate's internals, or it stops being an integration test.
fn zip_with_entry(name: &str, content: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let sizes = |v: &mut Vec<u8>| {
        v.extend(0u32.to_le_bytes()); // crc
        v.extend((content.len() as u32).to_le_bytes()); // compressed
        v.extend((content.len() as u32).to_le_bytes()); // uncompressed
    };

    out.extend(b"PK\x03\x04");
    out.extend(20u16.to_le_bytes()); // version needed
    out.extend(0u16.to_le_bytes()); // flags
    out.extend(0u16.to_le_bytes()); // stored
    out.extend([0u8; 4]); // time + date
    sizes(&mut out);
    out.extend((name.len() as u16).to_le_bytes());
    out.extend(0u16.to_le_bytes()); // extra len
    out.extend(name.as_bytes());
    out.extend(content);

    let cd_offset = out.len() as u32;
    let mut central: Vec<u8> = Vec::new();
    central.extend(b"PK\x01\x02");
    central.extend(20u16.to_le_bytes()); // version made by
    central.extend(20u16.to_le_bytes()); // version needed
    central.extend(0u16.to_le_bytes()); // flags
    central.extend(0u16.to_le_bytes()); // stored
    central.extend([0u8; 4]); // time + date
    sizes(&mut central);
    central.extend((name.len() as u16).to_le_bytes());
    central.extend(0u16.to_le_bytes()); // extra len
    central.extend(0u16.to_le_bytes()); // comment len
    central.extend(0u16.to_le_bytes()); // disk start
    central.extend(0u16.to_le_bytes()); // internal attrs
    central.extend(0u32.to_le_bytes()); // external attrs
    central.extend(0u32.to_le_bytes()); // local header offset
    central.extend(name.as_bytes());

    let cd_size = central.len() as u32;
    out.extend(&central);

    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]); // disk numbers
    out.extend(1u16.to_le_bytes()); // entries on this disk
    out.extend(1u16.to_le_bytes()); // total entries
    out.extend(cd_size.to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend(0u16.to_le_bytes()); // comment len
    out
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

/// A benign file must be RELEASED.
///
/// The most important test in this file. Every check added to Aegis is another
/// chance to start blocking ordinary downloads, and that is the failure mode a
/// user actually notices — a scanner that blocks everything is indistinguishable
/// from a broken one.
#[test]
fn benign_png_is_released() {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(std::iter::repeat_n(0u8, 1016));
    png.extend(b"IEND\xAE\x42\x60\x82");

    let Some((frames, stderr)) = watch(
        "550e8400-e29b-41d4-a716-446655440001",
        "aegis-test-benign.png",
        &png,
    ) else {
        return; // no Downloads directory in this environment
    };

    let v = verdicts(&frames);
    assert!(!v.is_empty(), "no verdict returned; stderr={stderr}");
    assert_eq!(
        status_of(v.last().unwrap()),
        "COMPLETE",
        "a benign PNG must be released; got {:?}",
        v.last().unwrap()
    );
}

/// An executable wearing a .jpg extension must never reach Downloads.
#[test]
fn exe_masquerading_as_jpg_is_not_released() {
    let mut pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    pe.extend(std::iter::repeat_n(0u8, 512));

    let Some((frames, stderr)) =
        watch("550e8400-e29b-41d4-a716-446655440002", "holiday.jpg", &pe)
    else {
        return;
    };

    let v = verdicts(&frames);
    assert!(!v.is_empty(), "no verdict returned; stderr={stderr}");
    assert_ne!(
        status_of(v.last().unwrap()),
        "COMPLETE",
        "an MZ executable named .jpg must never be released; got {:?}",
        v.last().unwrap()
    );
}

/// The archive case, end to end over the real IPC channel.
///
/// This is the gap archive inspection was written to close, and it is worth a
/// full round trip rather than only a unit test: the outer file is a
/// structurally perfect ZIP, its entropy is normal for compressed data, and
/// `structure.rs` deliberately does not flag executables inside archives.
/// Every check except the archive walk sees a completely ordinary file.
#[test]
fn archive_hiding_a_disguised_executable_is_not_released() {
    let zip = zip_with_entry("invoice.pdf.exe", b"MZ\x90\x00 payload");

    let Some((frames, stderr)) =
        watch("550e8400-e29b-41d4-a716-446655440003", "invoice.zip", &zip)
    else {
        return;
    };

    let v = verdicts(&frames);
    assert!(!v.is_empty(), "no verdict returned; stderr={stderr}");
    let last = v.last().unwrap();
    assert_ne!(
        status_of(last),
        "COMPLETE",
        "a ZIP containing invoice.pdf.exe must not be released; got {last:?}"
    );
    assert!(
        format!("{last:?}").contains("invoice.pdf.exe"),
        "the verdict must name the entry responsible, or the user cannot act on \
         it: {last:?}"
    );
}

/// An ordinary archive must still be released.
///
/// The counterweight to the test above. Archive inspection is the check most
/// likely to start rejecting legitimate downloads, because archives containing
/// programs are completely normal — that is what an installer is.
#[test]
fn ordinary_archive_is_still_released() {
    let zip = zip_with_entry("docs/readme.txt", b"just some ordinary text content");

    let Some((frames, stderr)) = watch(
        "550e8400-e29b-41d4-a716-446655440004",
        "aegis-test-project.zip",
        &zip,
    ) else {
        return;
    };

    let v = verdicts(&frames);
    assert!(!v.is_empty(), "no verdict returned; stderr={stderr}");
    assert_eq!(
        status_of(v.last().unwrap()),
        "COMPLETE",
        "an ordinary archive must be released; got {:?}",
        v.last().unwrap()
    );
}

/// The Phase 1 chunk-streaming protocol was removed, and its removal must be an
/// explicit refusal rather than a silent no-op.
///
/// That protocol had the extension re-fetch the URL and stream the bytes here,
/// so the bytes scanned were not the bytes delivered and a server could serve
/// one thing to the scanner and another to the browser. If a future extension
/// ever regressed to sending START_DOWNLOAD, the worst possible outcome would
/// be for the host to quietly accept it.
#[test]
fn retired_chunk_protocol_is_refused() {
    for msg in [
        serde_json::json!({
            "type": "START_DOWNLOAD",
            "session_id": "t-retired",
            "filename": "x.bin",
            "content_length": 10,
        }),
        serde_json::json!({
            "type": "CHUNK",
            "session_id": "t-retired",
            "seq": 0,
            "is_last": true,
            "data": "AAAA",
        }),
    ] {
        let (frames, stderr) = run_host(&frame(&msg));
        let v = verdicts(&frames);
        assert!(!v.is_empty(), "no verdict for retired protocol; stderr={stderr}");
        assert_eq!(
            status_of(v[0]),
            "REJECTED_MALFORMED",
            "the retired chunk protocol must be refused explicitly; got {:?}",
            v[0]
        );
        assert!(
            !stderr.contains("panicked"),
            "host panicked handling a retired message type; stderr={stderr}"
        );
    }
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

/// Malformed frame bodies are attacker-controlled input and must produce a
/// clean rejection, never a panic.
///
/// A panic is an availability failure for a security tool, and a particularly
/// bad one here: the host dying drops the native port, the extension reads that
/// as "cannot verify", and every subsequent download is cancelled. One crafted
/// message would jam downloads entirely.
#[test]
fn malformed_frames_are_rejected_not_panicked() {
    for body in [
        serde_json::json!({ "type": "WATCH_BEGIN" }), // no session, no path
        serde_json::json!({ "type": "WATCH_BEGIN", "session_id": "" }),
        serde_json::json!({ "type": "WATCH_BEGIN", "session_id": "x", "quarantine_path": "" }),
        serde_json::json!({ "type": 42 }), // type is not a string
        serde_json::json!({ "type": "PING", "extra": [1, 2, {"deep": null}] }),
        serde_json::json!([1, 2, 3]), // not an object at all
        serde_json::json!("bare string"),
    ] {
        let (frames, stderr) = run_host(&frame(&body));
        assert!(
            !stderr.contains("panicked"),
            "host panicked on {body:?} — a panic drops the port and cancels every \
             subsequent download; stderr={stderr}"
        );
        assert!(
            !frames.is_empty(),
            "host said nothing at all about {body:?}; stderr={stderr}"
        );
    }
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

/// Chromium does NOT honour the extension we suggest.
///
/// `background.js` asks for `{uuid}.aegispart`, but Chromium re-applies its own
/// extension from the response MIME type, so a PDF lands on disk as
/// `{uuid}.pdf`. The host used to require a `.aegispart` suffix and therefore
/// rejected every real download as malformed — while working perfectly:
///
///   Redirecting "notes.pdf" -> aegis_quarantine/4a635126-....aegispart
///   REJECTED: quarantine filename "4a635126-....pdf" is not a .aegispart file
///
/// Nothing in the extension or the host looked wrong in isolation; the two
/// simply disagreed about a filename the browser had silently rewritten.
#[test]
fn quarantine_file_is_accepted_whatever_extension_chrome_picks() {
    let downloads = dirs_downloads();
    let quarantine = downloads.join("aegis_quarantine");
    if std::fs::create_dir_all(&quarantine).is_err() {
        return; // no Downloads dir in this environment; nothing to assert
    }

    // The extensions Chromium realistically substitutes, plus the uniquify
    // suffix it adds on collision.
    for name in [
        "550e8400-e29b-41d4-a716-446655440000.pdf",
        "550e8400-e29b-41d4-a716-446655440000.aegispart",
        "550e8400-e29b-41d4-a716-446655440000.exe",
        "550e8400-e29b-41d4-a716-446655440000.tar.gz",
        "550e8400-e29b-41d4-a716-446655440000 (1).pdf",
    ] {
        let path = quarantine.join(name);
        std::fs::write(&path, b"x").ok();

        let sid = format!("t-{}", name.len());
        let mut input = frame(&serde_json::json!({
            "type": "WATCH_BEGIN",
            "session_id": sid,
            "quarantine_path": path.to_string_lossy(),
            "original_filename": "notes.pdf",
        }));
        input.extend(frame(&serde_json::json!({ "type": "PING" })));

        let (frames, stderr) = run_host(&input);
        let rejected = frames.iter().any(|f| {
            f.get("status").and_then(|s| s.as_str()) == Some("REJECTED_MALFORMED")
                && f.get("verdict")
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| v.contains("UUID") || v.contains("aegispart"))
        });
        let _ = std::fs::remove_file(&path);

        assert!(
            !rejected,
            "host rejected its own quarantine file {name:?} on filename grounds. \
             Chromium chooses the extension, not us. frames={frames:?} stderr={stderr}"
        );
    }
}

/// A path outside the quarantine root must still be refused — the containment
/// check is the actual security property and must survive the relaxation above.
#[test]
fn path_outside_quarantine_root_is_still_rejected() {
    let input = frame(&serde_json::json!({
        "type": "WATCH_BEGIN",
        "session_id": "t-escape",
        "quarantine_path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "original_filename": "hosts",
    }));
    let (frames, _) = run_host(&input);
    let v = verdicts(&frames);
    assert!(!v.is_empty(), "expected a rejection");
    assert_eq!(
        status_of(v[0]),
        "REJECTED_MALFORMED",
        "a path outside the quarantine root must be refused: {:?}",
        v[0]
    );
}

fn dirs_downloads() -> std::path::PathBuf {
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    #[cfg(not(windows))]
    let home = std::env::var("HOME").unwrap_or_default();
    std::path::PathBuf::from(home).join("Downloads")
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
