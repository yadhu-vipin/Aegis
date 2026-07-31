//! Verification against containers produced by real tools, not by our own
//! encoder.
//!
//! Every ZIP fixture in `scanner/archive.rs` is built by the test module that
//! consumes it, which proves the checks work against *our understanding* of the
//! format. That is exactly the class of bug this project keeps hitting: the
//! code was right about a format the real world writes differently. A parser
//! validated only against its author's fixtures is validated against nothing.
//!
//! So these tests hand the scanner archives written by Windows itself
//! (`Compress-Archive`, i.e. .NET's `ZipFile`) and shortcuts written by
//! Explorer, and assert the results are the same as for the synthetic ones.
//!
//! They skip rather than fail where the platform cannot supply a real sample —
//! a Linux CI box has no Explorer — because a test that cannot run must not be
//! confused with one that passed.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "../src/scanner/mod.rs"]
mod scanner;

/// Run a PowerShell snippet, returning false if it failed for any reason.
#[cfg(windows)]
fn powershell(script: &str) -> bool {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn powershell(_script: &str) -> bool {
    false
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("aegis_real_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }
    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn win_path(p: &Path) -> String {
    p.display().to_string().replace('\'', "''")
}

/// A ZIP written by Windows must parse exactly like our hand-built fixtures.
///
/// `Compress-Archive` uses .NET's `ZipFile`, which deflates, writes data
/// descriptors, and orders the central directory its own way — none of which
/// our synthetic builder does.
#[test]
fn zip_written_by_windows_is_parsed() {
    let s = Scratch::new("zip");
    std::fs::write(s.path("readme.txt"), b"hello world, this is ordinary text").unwrap();
    std::fs::write(s.path("notes.txt"), b"more ordinary text content here").unwrap();

    let zip = s.path("real.zip");
    let ok = powershell(&format!(
        "Compress-Archive -Path '{}\\*.txt' -DestinationPath '{}' -Force",
        win_path(&s.0),
        win_path(&zip)
    ));
    if !ok || !zip.exists() {
        eprintln!("SKIP: Compress-Archive unavailable on this platform");
        return;
    }

    let data = std::fs::read(&zip).unwrap();
    let res = scanner::archive::analyse(&data, "real.zip").unwrap();

    assert!(
        res.is_archive,
        "a ZIP written by Windows was not recognised as an archive"
    );
    assert_eq!(res.entry_count, 2, "entries: {:?}", res.flags);
    assert!(
        !res.flagged,
        "an ordinary two-text-file archive was flagged: {:?}",
        res.flags
    );
}

/// The headline case, end to end, with a real archiver and a real executable:
/// a ZIP containing `invoice.pdf.exe` must not be released.
#[test]
fn real_zip_hiding_a_disguised_executable_is_blocked() {
    let s = Scratch::new("trojan");

    // A genuine PE, so the sample is a real executable rather than a stub.
    let system_exe = Path::new("C:\\Windows\\System32\\notepad.exe");
    if !system_exe.exists() {
        eprintln!("SKIP: no system executable to copy");
        return;
    }
    std::fs::copy(system_exe, s.path("invoice.pdf.exe")).unwrap();

    let zip = s.path("invoice.zip");
    let ok = powershell(&format!(
        "Compress-Archive -Path '{}' -DestinationPath '{}' -Force",
        win_path(&s.path("invoice.pdf.exe")),
        win_path(&zip)
    ));
    if !ok || !zip.exists() {
        eprintln!("SKIP: Compress-Archive unavailable on this platform");
        return;
    }

    let data = std::fs::read(&zip).unwrap();
    let res = scanner::whole_file_scan(&data, "invoice.zip").unwrap();

    // sandbox_threshold is 0.4 and the stub sandbox returns Suspicious, so
    // anything at or above it is blocked. Asserting against the threshold
    // rather than the raw number keeps this test about the outcome.
    assert!(
        res.risk_score >= 0.4,
        "a real ZIP containing invoice.pdf.exe scored {} - it would have been released. \
         Signals: {:?}",
        res.risk_score,
        res.descriptions
    );
    assert!(
        res.findings
            .iter()
            .any(|f| f.title.contains("disguised as a document")),
        "the disguise was not named in the findings: {:?}",
        res.findings
    );
}

/// An OOXML package written by a real archiver must not be flagged.
///
/// This is the false-positive canary. A `.docx` *is* a ZIP, so every archive
/// check runs against every Office document the user downloads; if the archive
/// module is too eager, this is where it shows up.
///
/// The package is built by .NET's `ZipFile` with the entry names Office
/// actually uses, rather than by our own encoder.
#[test]
fn ooxml_package_from_a_real_archiver_is_not_flagged() {
    let s = Scratch::new("ooxml");
    let src = s.path("src");
    std::fs::create_dir_all(src.join("word")).unwrap();
    std::fs::create_dir_all(src.join("docProps")).unwrap();
    std::fs::create_dir_all(src.join("_rels")).unwrap();
    std::fs::write(
        src.join("[Content_Types].xml"),
        br#"<?xml version="1.0"?><Types/>"#,
    )
    .unwrap();
    std::fs::write(src.join("word").join("document.xml"), b"<w:document/>").unwrap();
    std::fs::write(src.join("word").join("styles.xml"), b"<w:styles/>").unwrap();
    std::fs::write(src.join("docProps").join("core.xml"), b"<cp:coreProperties/>").unwrap();
    std::fs::write(src.join("_rels").join(".rels"), b"<Relationships/>").unwrap();

    let docx = s.path("report.docx");
    let ok = powershell(&format!(
        "Add-Type -AssemblyName System.IO.Compression.FileSystem; \
         [System.IO.Compression.ZipFile]::CreateFromDirectory('{}','{}')",
        win_path(&src),
        win_path(&docx)
    ));
    if !ok || !docx.exists() {
        eprintln!("SKIP: .NET ZipFile unavailable on this platform");
        return;
    }

    let data = std::fs::read(&docx).unwrap();
    let res = scanner::whole_file_scan(&data, "report.docx").unwrap();
    assert!(
        res.risk_score < 0.4,
        "an ordinary Office package scored {} - that is a false positive on every document \
         the user downloads. Signals: {:?}",
        res.risk_score,
        res.descriptions
    );

    // And the same package with a macro project in it must be caught, since
    // .docx is by definition the macro-free variant.
    std::fs::write(src.join("word").join("vbaProject.bin"), b"\xD0\xCF\x11\xE0macro").unwrap();
    let macro_docx = s.path("macro.docx");
    assert!(powershell(&format!(
        "Add-Type -AssemblyName System.IO.Compression.FileSystem; \
         [System.IO.Compression.ZipFile]::CreateFromDirectory('{}','{}')",
        win_path(&src),
        win_path(&macro_docx)
    )));
    let data = std::fs::read(&macro_docx).unwrap();
    let res = scanner::whole_file_scan(&data, "macro.docx").unwrap();
    assert!(
        res.risk_score >= 0.4,
        "a .docx carrying vbaProject.bin scored {} and would have been released",
        res.risk_score
    );
}

/// The user's own Office documents, if any can actually be read.
///
/// Kept separate from the canary above because it cannot be relied on: on this
/// machine every document in `OneDrive\Documents` is a cloud placeholder, and
/// reading one returns `os error 362` ("the cloud file provider is not
/// running") because the bytes are not on disk at all.
///
/// The first version of this test swallowed that error with a bare `continue`
/// and reported "no documents found" - it looked like a clean pass while
/// checking nothing. That is the exact failure mode this project keeps being
/// bitten by, so the counters below distinguish "found none", "found some and
/// could not read them", and "actually checked some".
#[test]
fn users_own_office_documents_are_not_flagged() {
    let candidates = [
        std::env::var("USERPROFILE")
            .map(|p| PathBuf::from(p).join("OneDrive").join("Documents"))
            .unwrap_or_default(),
        std::env::var("USERPROFILE")
            .map(|p| PathBuf::from(p).join("Documents"))
            .unwrap_or_default(),
        std::env::var("USERPROFILE")
            .map(|p| PathBuf::from(p).join("Downloads"))
            .unwrap_or_default(),
    ];

    let mut checked = 0usize;
    let mut found = 0usize;
    let mut unreadable: Vec<String> = Vec::new();

    for dir in candidates.iter().filter(|d| d.is_dir()) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten().take(200) {
            let path = entry.path();
            let is_office = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| matches!(e.to_lowercase().as_str(), "docx" | "xlsx" | "pptx"))
                .unwrap_or(false);
            if !is_office {
                continue;
            }
            found += 1;

            let data = match std::fs::read(&path) {
                Ok(d) => d,
                Err(e) => {
                    unreadable.push(format!("{:?}: {e}", path.file_name().unwrap_or_default()));
                    continue;
                }
            };
            if data.len() > 32 * 1024 * 1024 {
                continue;
            }

            let name = path.file_name().unwrap_or_default().to_string_lossy();
            let res = scanner::whole_file_scan(&data, &name).unwrap();
            assert!(
                res.risk_score < 0.4,
                "real Office document {name:?} scored {} - that is a false positive on an \
                 ordinary document. Signals: {:?}",
                res.risk_score,
                res.descriptions
            );
            checked += 1;
            if checked >= 5 {
                break;
            }
        }
        if checked >= 5 {
            break;
        }
    }

    eprintln!("checked {checked} of {found} Office documents found");
    if !unreadable.is_empty() {
        eprintln!(
            "NOT CHECKED - {} document(s) could not be read (cloud placeholders): {}",
            unreadable.len(),
            unreadable.join("; ")
        );
    }
    if found == 0 {
        eprintln!("SKIP: no Office documents on this machine");
    }
}

/// Authenticode against binaries Microsoft actually signed.
///
/// This is FFI into `wintrust.dll`; it compiles whether or not the arguments
/// are laid out correctly, and a wrong `cbStruct` or a missing
/// `WTD_STATEACTION_CLOSE` produces a plausible-looking wrong answer rather
/// than an error. The only way to know it works is to point it at a file
/// whose signature state is already known.
#[test]
fn microsoft_signed_binaries_verify_as_trusted() {
    use scanner::signature::TrustStatus;

    let system32 = PathBuf::from("C:\\Windows\\System32");
    if !system32.is_dir() {
        eprintln!("SKIP: not Windows");
        return;
    }

    let mut trusted = 0usize;
    let mut checked = 0usize;
    for name in ["notepad.exe", "kernel32.dll", "cmd.exe", "calc.exe"] {
        let path = system32.join(name);
        if !path.exists() {
            continue;
        }
        checked += 1;

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  {name}: unreadable ({e})");
                continue;
            }
        };
        let res = scanner::whole_file_scan_at(&data, name, Some(&path)).unwrap();
        let status = res.signature_status.clone();
        eprintln!("  {name}: {status:?}");

        match status {
            Some(TrustStatus::Trusted { publisher }) => {
                trusted += 1;
                assert!(
                    publisher.is_some(),
                    "{name} verified but no publisher name was extracted - the crypt32 path is \
                     not working even though WinVerifyTrust is"
                );
            }
            // Most of Windows is signed by catalog, not embedded signature.
            // Both are real signatures and both must verify.
            Some(TrustStatus::TrustedByCatalog { catalog }) => {
                trusted += 1;
                assert!(catalog.is_some(), "{name} verified but named no catalog");
            }
            other => panic!(
                "{name} is a signed Windows binary but produced: {other:?}. Reporting a signed \
                 system binary as unsigned means the check is wrong, not the file."
            ),
        }
    }

    assert!(checked > 0, "no system binaries found to check");
    assert_eq!(
        trusted, checked,
        "every Windows system binary is signed, one way or the other - {} of {} verified",
        trusted, checked
    );
    eprintln!("{trusted} of {checked} system binaries verified as trusted");
}

/// Find a system binary carrying an *embedded* Authenticode signature.
///
/// Most of Windows is catalog-signed, and a catalog signature behaves
/// differently under modification (see
/// `tampering_with_a_catalog_signed_file_breaks_its_trust`), so tests about
/// embedded signatures have to go looking for one rather than assuming.
fn find_embedded_signed_binary() -> Option<(PathBuf, Vec<u8>)> {
    use scanner::signature::TrustStatus;

    let system32 = PathBuf::from("C:\\Windows\\System32");
    for name in [
        "kernel32.dll",
        "ntdll.dll",
        "user32.dll",
        "advapi32.dll",
        "shell32.dll",
    ] {
        let path = system32.join(name);
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let res = scanner::whole_file_scan_at(&data, name, Some(&path)).unwrap();
        if matches!(res.signature_status, Some(TrustStatus::Trusted { .. })) {
            return Some((path, data));
        }
    }
    None
}

/// Modifying a signed binary must be detected.
///
/// This is the check that earns Authenticode its weight: `TRUST_E_BAD_DIGEST`
/// means the bytes are not the bytes that were signed.
#[test]
fn tampering_with_a_signed_binary_is_detected() {
    use scanner::signature::TrustStatus;

    let Some((_, data)) = find_embedded_signed_binary() else {
        eprintln!("SKIP: no embedded-signed system binary available");
        return;
    };

    let s = Scratch::new("tamper");
    let copy = s.path("sample.dll");

    // Flip bytes in the middle of the image, well away from the headers and
    // the certificate table, so the only thing that changes is content the
    // signature covers.
    let mut tampered = data.clone();
    let mid = tampered.len() / 2;
    for b in tampered[mid..mid + 64].iter_mut() {
        *b ^= 0xFF;
    }
    std::fs::write(&copy, &tampered).unwrap();

    let after = scanner::whole_file_scan_at(&tampered, "sample.dll", Some(&copy)).unwrap();
    eprintln!("  after tampering: {:?}", after.signature_status);

    assert!(
        matches!(after.signature_status, Some(TrustStatus::Tampered)),
        "editing a signed binary was not detected: {:?}",
        after.signature_status
    );
    assert!(
        after.risk_score >= 0.4,
        "a tampered signed binary scored {} and would not have been stopped",
        after.risk_score
    );
    assert!(
        after.findings
            .iter()
            .any(|f| f.title.contains("modified since it was signed")),
        "{:?}",
        after.findings
    );
}

/// Modifying a *catalog*-signed file also breaks its trust, but reports
/// differently, and the difference is worth pinning down.
///
/// A catalog signature is a list of hashes signed separately from the file, so
/// there is no embedded signature to invalidate. Editing the file simply makes
/// its hash match nothing, and the honest report is "unsigned" rather than
/// "tampered". That is a genuinely weaker signal than the embedded case — 0.2
/// instead of 0.8 — and this test exists so that stays a known property rather
/// than a surprise.
#[test]
fn tampering_with_a_catalog_signed_file_breaks_its_trust() {
    use scanner::signature::TrustStatus;

    let src = PathBuf::from("C:\\Windows\\System32\\notepad.exe");
    let Ok(data) = std::fs::read(&src) else {
        eprintln!("SKIP: not Windows");
        return;
    };

    let s = Scratch::new("cattamper");
    let copy = s.path("notepad.exe");
    std::fs::write(&copy, &data).unwrap();

    let before = scanner::whole_file_scan_at(&data, "notepad.exe", Some(&copy)).unwrap();
    if !matches!(before.signature_status, Some(TrustStatus::TrustedByCatalog { .. })) {
        eprintln!("SKIP: carrier is not catalog-signed ({:?})", before.signature_status);
        return;
    }

    let mut tampered = data.clone();
    let mid = tampered.len() / 2;
    for b in tampered[mid..mid + 64].iter_mut() {
        *b ^= 0xFF;
    }
    std::fs::write(&copy, &tampered).unwrap();

    let after = scanner::whole_file_scan_at(&tampered, "notepad.exe", Some(&copy)).unwrap();
    eprintln!("  catalog-signed after tampering: {:?}", after.signature_status);

    assert!(
        !matches!(after.signature_status, Some(TrustStatus::TrustedByCatalog { .. })),
        "a modified file still matched its catalog - the hash check is not actually running"
    );
}

/// A signature must not be able to buy down a real detection, end to end.
///
/// The unit test for `apply_trust_credit` covers the rule in isolation; this
/// checks the rule is actually reached by the pipeline, using a genuinely
/// Microsoft-signed binary as the carrier.
#[test]
fn a_valid_signature_does_not_rescue_a_disguised_file() {
    let Some((_, data)) = find_embedded_signed_binary() else {
        eprintln!("SKIP: no embedded-signed system binary available");
        return;
    };

    let s = Scratch::new("disguise");
    let disguised = s.path("invoice.pdf.exe");
    std::fs::write(&disguised, &data).unwrap();

    let res = scanner::whole_file_scan_at(&data, "invoice.pdf.exe", Some(&disguised)).unwrap();
    eprintln!(
        "  signed carrier with a double extension: risk={} status={:?}",
        res.risk_score, res.signature_status
    );

    assert!(
        res.risk_score >= 0.4,
        "a validly signed binary with a double extension scored {} - the trust credit \
         discounted a real detection, which is exactly the evasion it must not enable. \
         Signals: {:?}",
        res.risk_score,
        res.descriptions
    );
}

/// Shortcuts written by Explorer, parsed with our own reader.
///
/// The Recent folder is full of real `.lnk` files covering variations our
/// builder never produces: target ID lists, LinkInfo blocks, tracker data,
/// ANSI and Unicode strings. Every one must parse or be cleanly rejected, and
/// none of them - they are shortcuts to the user's own documents - may be
/// reported as running a system command.
#[test]
fn real_shortcuts_parse_without_false_accusations() {
    let Ok(appdata) = std::env::var("APPDATA") else {
        eprintln!("SKIP: not a Windows profile");
        return;
    };
    let recent = PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Recent");
    if !recent.is_dir() {
        eprintln!("SKIP: no Recent folder");
        return;
    }

    let mut parsed = 0usize;
    let mut seen = 0usize;
    let Ok(entries) = std::fs::read_dir(&recent) else {
        eprintln!("SKIP: Recent folder unreadable");
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("lnk") {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        seen += 1;
        if seen > 40 {
            break;
        }

        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let res = scanner::autoexec::analyse(&data, &name).unwrap();

        assert!(
            !res.findings
                .iter()
                .any(|f| f.title.contains("run a system command")),
            "a shortcut in the user's Recent folder was accused of running a system command: \
             {name:?} -> {:?}",
            res.findings
        );

        if scanner::autoexec::parse_lnk(&data).is_some() {
            parsed += 1;
        }
    }

    if seen == 0 {
        eprintln!("SKIP: no shortcuts in Recent folder");
        return;
    }
    assert!(
        parsed > 0,
        "{seen} real shortcuts examined and not one parsed - the .lnk reader does not \
         understand what Explorer actually writes"
    );
    eprintln!("parsed {parsed} of {seen} real shortcuts");
}
