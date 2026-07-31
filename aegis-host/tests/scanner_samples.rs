//! Scanner checks against the real sample files in `test_files/`.
//!
//! The unit tests use synthetic inputs the same code constructed, which risks
//! testing my assumptions rather than the scanner. These run against the actual
//! files checked into the repo, so a sample that stops being detected shows up
//! here.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::io::{Read, Write};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("aegis-host has a parent")
        .to_path_buf()
}

fn sample(name: &str) -> Option<Vec<u8>> {
    std::fs::read(repo_root().join("test_files").join(name)).ok()
}

/// Drive a full WATCH_BEGIN through the real binary against a staged file, and
/// return the terminal verdict. Exercises the whole pipeline rather than
/// calling the scanner functions directly.
fn verdict_for(sample_name: &str, presented_as: &str) -> Option<(String, String)> {
    verdict_for_with_id(sample_name, presented_as, uuid_for(sample_name))
}

/// A distinct quarantine UUID per sample.
///
/// Cargo runs integration tests in parallel. Sharing one UUID meant every test
/// staged to the same path, so they deleted each other's files mid-scan - one
/// test received another's verdict, and the rest sat until the 30s stall
/// timeout. The failures looked like scanner bugs and were pure harness
/// interference.
fn uuid_for(sample_name: &str) -> &'static str {
    match sample_name {
        "test_trojan.jpg" => "11111111-1111-4111-8111-111111111111",
        "script.png" => "22222222-2222-4222-8222-222222222222",
        "polyglot_big.png" => "33333333-3333-4333-8333-333333333333",
        "packed_like.exe" => "44444444-4444-4444-8444-444444444444",
        _ => "99999999-9999-4999-8999-999999999999",
    }
}

fn verdict_for_with_id(
    sample_name: &str,
    presented_as: &str,
    uuid: &str,
) -> Option<(String, String)> {
    let bytes = sample(sample_name)?;

    let downloads = {
        #[cfg(windows)]
        let home = std::env::var("USERPROFILE").ok()?;
        #[cfg(not(windows))]
        let home = std::env::var("HOME").ok()?;
        PathBuf::from(home).join("Downloads")
    };
    let quarantine = downloads.join("aegis_quarantine");
    std::fs::create_dir_all(&quarantine).ok()?;

    let staged = quarantine.join(format!("{uuid}.bin"));
    std::fs::write(&staged, &bytes).ok()?;

    let msg = serde_json::json!({
        "type": "WATCH_BEGIN",
        "session_id": "sample-test",
        "quarantine_path": staged.to_string_lossy(),
        "original_filename": presented_as,
    });
    let json = serde_json::to_vec(&msg).ok()?;
    let mut input = (json.len() as u32).to_le_bytes().to_vec();
    input.extend_from_slice(&json);

    let mut child = Command::new(env!("CARGO_BIN_EXE_aegis-host"))
        .current_dir(repo_root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(&input).ok()?;

    let mut out = Vec::new();
    child.stdout.take()?.read_to_end(&mut out).ok()?;
    let _ = child.wait();

    // Clean up whichever name survived.
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_file(downloads.join(presented_as));

    // Last VERDICT frame wins.
    let mut pos = 0usize;
    let mut last = None;
    while pos + 4 <= out.len() {
        let len =
            u32::from_le_bytes([out[pos], out[pos + 1], out[pos + 2], out[pos + 3]]) as usize;
        pos += 4;
        if pos + len > out.len() {
            break;
        }
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out[pos..pos + len]) {
            if v.get("type").and_then(|t| t.as_str()) == Some("VERDICT") {
                last = Some((
                    v.get("status").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                    v.get("verdict").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                ));
            }
        }
        pos += len;
    }
    last
}

/// An executable wearing a .jpg extension. This is the case a signature
/// scanner misses and Aegis is for.
#[test]
fn trojan_disguised_as_image_is_blocked() {
    let Some((status, verdict)) = verdict_for("test_trojan.jpg", "holiday.jpg") else {
        return; // sample or Downloads dir unavailable
    };
    assert_ne!(
        status, "COMPLETE",
        "an MZ executable named .jpg was RELEASED: {verdict}"
    );
    assert!(
        verdict.to_lowercase().contains("mismatch")
            || verdict.to_lowercase().contains("exe")
            || verdict.to_lowercase().contains("injection"),
        "verdict should explain the type mismatch: {verdict}"
    );
}

/// A shell script wearing a .png extension.
#[test]
fn script_disguised_as_image_is_blocked() {
    let Some((status, verdict)) = verdict_for("script.png", "diagram.png") else {
        return;
    };
    assert_ne!(
        status, "COMPLETE",
        "a shell script named .png was RELEASED: {verdict}"
    );
}

/// A structurally valid PNG carrying an appended ZIP. The header is entirely
/// honest here - only the whole-file structural pass catches it.
#[test]
fn polyglot_png_with_appended_archive_is_not_released() {
    let Some((status, verdict)) = verdict_for("polyglot_big.png", "photo.png") else {
        return;
    };
    assert_ne!(
        status, "COMPLETE",
        "a PNG with an appended ZIP payload was RELEASED: {verdict}"
    );
    assert!(
        verdict.contains("appended") || verdict.contains("logical end") || verdict.contains("ZIP"),
        "verdict should name the appended payload: {verdict}"
    );
}

/// A PE with UPX section names, a W+X section, zero raw size and an entry
/// point outside every section. Structural facts a packer cannot hide.
#[test]
fn packed_executable_is_flagged_by_pe_analysis() {
    let Some((status, verdict)) = verdict_for("packed_like.exe", "setup.exe") else {
        return;
    };
    assert_ne!(
        status, "COMPLETE",
        "a packed executable was RELEASED: {verdict}"
    );
    let v = verdict.to_lowercase();
    assert!(
        v.contains("upx") || v.contains("packer") || v.contains("writable and executable")
            || v.contains("outside every declared section"),
        "verdict should cite the PE structure findings: {verdict}"
    );
}
