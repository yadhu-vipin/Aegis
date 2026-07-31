//! Authenticode signature verification.
//!
//! "Is this signed, and by whom" is the strongest single legitimacy signal
//! available without running anything, and it is why Windows treats a
//! Microsoft-signed binary differently from an unknown one. Every other check
//! in this scanner looks for evidence of malice; this is the only one that can
//! find evidence of *provenance*.
//!
//! ## Two directions, deliberately asymmetric
//!
//! A **broken** signature is strong evidence against the file. `TRUST_E_BAD_DIGEST`
//! means the bytes changed after they were signed — someone took a signed
//! program and modified it, which has no innocent explanation.
//!
//! A **valid** signature is much weaker evidence in favour, and this is the
//! part that is easy to get wrong. Code-signing certificates are stolen and
//! abused constantly, and cheap ones are bought with fake company details.
//! A signature proves that *somebody* with a certificate signed this; it does
//! not prove they are honest. So the credit a valid signature earns is:
//!
//! * **capped** at [`MAX_TRUST_CREDIT`], and
//! * **withheld entirely** when anything worse than a Medium finding exists.
//!
//! The second rule is the important one. Without it, signing your malware
//! becomes a way to buy down a real detection — a packed dropper with a stolen
//! certificate would score lower than the same dropper unsigned, which inverts
//! the whole point. A signature can settle a *weak* case; it can never argue
//! away a strong one. See `DECISIONS.md`.
//!
//! ## No network, ever
//!
//! Verification runs with `WTD_REVOKE_NONE` and `WTD_CACHE_ONLY_URL_RETRIEVAL`.
//! Revocation checking fetches CRLs and OCSP responses over the network, which
//! in a download scanner means an unbounded stall in the middle of the user's
//! download, and a scanner that behaves differently depending on whether the
//! machine is online.
//!
//! The cost of that choice is real and worth stating plainly: **a revoked
//! certificate still verifies here.** Stolen certificates are usually dealt
//! with by revocation, so this is precisely the case we cannot see — which is
//! the third reason the trust credit is small.

use crate::scanner::finding::{Finding, Severity};
use anyhow::Result;
use std::path::Path;

/// Largest amount a valid signature may subtract from a file's risk score.
///
/// Small on purpose. It is enough to settle an ambiguous file — the difference
/// between "sandbox this" and "release it" — and nowhere near enough to rescue
/// one that tripped a real detection.
pub const MAX_TRUST_CREDIT: f32 = 0.25;

/// What Windows says about a file's signature.
#[derive(Debug, Clone, PartialEq)]
pub enum TrustStatus {
    /// Valid signature chaining to a root this machine trusts.
    Trusted { publisher: Option<String> },
    /// No embedded signature, but the file's hash appears in a signed system
    /// catalog that Windows trusts. This is how most of Windows itself is
    /// signed.
    TrustedByCatalog { catalog: Option<String> },
    /// Signed, but the chain ends somewhere Windows does not trust — a
    /// self-signed certificate, or an internal corporate CA.
    UntrustedRoot { publisher: Option<String> },
    /// Signed, but the bytes no longer match the signature.
    Tampered,
    /// Signed, but the certificate had expired and no trusted timestamp
    /// countersigned it.
    Expired { publisher: Option<String> },
    /// Explicitly distrusted — revoked by policy or blocked by Microsoft.
    Distrusted { publisher: Option<String> },
    /// No signature at all.
    Unsigned,
    /// Verification could not be performed. Not a verdict either way.
    Unavailable(String),
}

impl TrustStatus {
    pub fn publisher(&self) -> Option<&str> {
        match self {
            TrustStatus::Trusted { publisher }
            | TrustStatus::UntrustedRoot { publisher }
            | TrustStatus::Expired { publisher }
            | TrustStatus::Distrusted { publisher } => publisher.as_deref(),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SignatureResult {
    pub status: Option<TrustStatus>,
    pub flagged: bool,
    pub flags: Vec<String>,
    pub findings: Vec<Finding>,
    /// Positive risk contributed by a broken or absent signature.
    pub risk: f32,
    /// Risk to SUBTRACT for a valid signature, already capped. Applied by
    /// [`apply_trust_credit`], which enforces the withholding rule.
    pub trust_credit: f32,
}

/// Extensions Windows can carry an embedded Authenticode signature in.
///
/// Checked in addition to "the content is a PE", because a signed installer
/// script or catalog is not a PE but is still verifiable.
static SIGNABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "ocx", "msi", "msix", "appx", "cab", "cat", "ps1", "psm1", "scr", "cpl",
];

/// Verify a file's signature and turn the result into findings.
///
/// `path` is where the file actually is on disk — Windows verifies from a
/// path, not from a buffer, because the signature covers a computed hash of
/// specific parts of the PE rather than the whole byte range.
///
/// Returns an empty result for files that cannot carry a signature. Reporting
/// "this PNG is unsigned" would be noise: images are never signed, so the
/// observation carries no information.
pub fn analyse(path: Option<&Path>, is_pe: bool, filename: &str) -> Result<SignatureResult> {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_lowercase())
        .unwrap_or_default();
    let signable = is_pe || SIGNABLE_EXTENSIONS.contains(&ext.as_str());
    if !signable {
        return Ok(SignatureResult::default());
    }

    let Some(path) = path else {
        // The whole-file pass ran from a buffer with no backing file. Say so
        // rather than reporting the file as unsigned, which would be a claim
        // we did not check.
        return Ok(SignatureResult {
            status: Some(TrustStatus::Unavailable(
                "no on-disk path available to verify".to_string(),
            )),
            ..Default::default()
        });
    };

    let status = verify(path);
    Ok(build_result(status, is_pe || !ext.is_empty()))
}

fn build_result(status: TrustStatus, is_executable: bool) -> SignatureResult {
    let mut findings = Vec::new();
    let mut risk: f32 = 0.0;
    let mut trust_credit: f32 = 0.0;

    match &status {
        // --- Signed by a system catalog rather than embedded ---------------
        //
        // Earns the same credit as an embedded signature: the trust decision
        // is identical, only the place the signature is stored differs.
        TrustStatus::TrustedByCatalog { catalog } => {
            trust_credit = MAX_TRUST_CREDIT;
            findings.push(Finding::new(
                Severity::Low,
                "Signed by a trusted Windows catalog",
                match catalog {
                    Some(c) => format!(
                        "The file has no signature embedded in it, but its hash is listed in the \
                         signed system catalog {c}."
                    ),
                    None => "The file's hash is listed in a signed system catalog.".to_string(),
                },
                "Windows signs most of its own components by listing their hashes in a separate \
                 signed catalog file rather than embedding a signature in each one. Being in a \
                 trusted catalog means Windows itself vouches for these exact bytes.",
                0.0,
            ));
        }

        // --- The one case that earns credit --------------------------------
        TrustStatus::Trusted { publisher } => {
            let who = publisher.as_deref().unwrap_or("an unnamed publisher");
            trust_credit = MAX_TRUST_CREDIT;
            findings.push(Finding::new(
                Severity::Low,
                format!("Signed by {who}"),
                format!(
                    "The file carries a valid Authenticode signature from {who}, and the \
                     certificate chains to a root this machine trusts."
                ),
                "A valid signature means the file has not been altered since that publisher \
                 signed it, and that they can be identified. It is not a guarantee of safety - \
                 certificates are stolen and misused - so it counts in the file's favour without \
                 being decisive.",
                0.0,
            ));
        }

        // --- Signed, then modified: no innocent explanation ----------------
        TrustStatus::Tampered => {
            risk = 0.8;
            findings.push(Finding::new(
                Severity::Critical,
                "File has been modified since it was signed",
                "The Authenticode signature is present but does not match the file's contents \
                 (TRUST_E_BAD_DIGEST)."
                    .to_string(),
                "Someone took a signed program and changed it. The signature is the publisher's \
                 statement about exactly which bytes they produced, and these are not those \
                 bytes. Corruption in transit can cause this, but so can code being inserted \
                 into legitimate software.",
                0.8,
            ));
        }

        TrustStatus::Distrusted { publisher } => {
            risk = 0.9;
            let who = publisher.as_deref().unwrap_or("an unnamed publisher");
            findings.push(Finding::new(
                Severity::Critical,
                "File is signed by a publisher Windows explicitly distrusts",
                format!("Signed by {who}; the certificate is on an explicit distrust list."),
                "This is stronger than being unsigned. A certificate reaches this list because it \
                 was found to be issued fraudulently, stolen, or used to sign malware.",
                0.9,
            ));
        }

        // --- Signed, but the chain does not reach a trusted root -----------
        TrustStatus::UntrustedRoot { publisher } => {
            if is_executable {
                risk = 0.3;
                let who = publisher.as_deref().unwrap_or("an unidentified publisher");
                findings.push(Finding::new(
                    Severity::Medium,
                    "Signature does not identify a verifiable publisher",
                    format!(
                        "Signed by {who}, but the certificate chain does not lead to a \
                         certificate authority this machine trusts."
                    ),
                    "Anyone can generate a certificate and sign a file with it - doing so proves \
                     nothing about who they are. A signature is only meaningful when it chains \
                     back to an authority that verified the signer's identity, and this one does \
                     not.",
                    0.3,
                ));
            }
        }

        // --- Expired: common and usually innocent --------------------------
        TrustStatus::Expired { publisher } => {
            if is_executable {
                risk = 0.15;
                let who = publisher.as_deref().unwrap_or("an unnamed publisher");
                findings.push(Finding::new(
                    Severity::Low,
                    "Signature has expired",
                    format!("Signed by {who}, but the certificate is no longer within its validity period."),
                    "This is common and usually harmless: code-signing certificates expire after \
                     a few years, and older software keeps working. It only means the signature \
                     can no longer be confirmed as current, not that anything is wrong.",
                    0.15,
                ));
            }
        }

        // --- Unsigned ------------------------------------------------------
        TrustStatus::Unsigned => {
            if is_executable {
                risk = 0.2;
                findings.push(Finding::new(
                    Severity::Low,
                    "Program is not signed",
                    "The file carries no Authenticode signature.".to_string(),
                    "Nothing identifies who produced this program or confirms it has not been \
                     altered. Plenty of legitimate software is unsigned - signing costs money - \
                     so this is a weak signal on its own, but it does mean there is nothing to \
                     check against.",
                    0.2,
                ));
            }
        }

        // --- Could not check -----------------------------------------------
        //
        // Contributes no risk in either direction. An unanswered question is
        // not an answer, and pretending otherwise in either direction would be
        // worse than saying so.
        TrustStatus::Unavailable(reason) => {
            findings.push(Finding::new(
                Severity::Low,
                "Signature could not be checked",
                format!("Verification did not run: {reason}"),
                "This says nothing about the file either way. It is reported so the verdict does \
                 not silently look like a clean result on a check that never happened.",
                0.0,
            ));
        }
    }

    let flags = findings.iter().map(|f| f.one_line()).collect::<Vec<_>>();
    SignatureResult {
        // A valid signature is reported but is not an anomaly, so it must not
        // set `flagged` - that field drives "something is wrong with this file".
        flagged: risk > 0.0,
        status: Some(status),
        flags,
        findings,
        risk,
        trust_credit,
    }
}

/// Apply a signature's trust credit to an aggregate risk score.
///
/// The withholding rule lives here, in one place, because it is the part that
/// decides whether signing malware is a viable evasion:
///
/// **A valid signature may only reduce risk when nothing worse than a Medium
/// finding was found.**
///
/// Without that rule, a stolen certificate buys a fixed discount off any
/// detection, and the strongest evidence Aegis produces — a packed executable
/// that rewrites its own code, an archive carrying a disguised program — could
/// be argued down by a certificate bought for a few hundred dollars. With it,
/// a signature can settle a genuinely ambiguous file and nothing more.
pub fn apply_trust_credit(risk: f32, credit: f32, findings: &[Finding]) -> f32 {
    if credit <= 0.0 {
        return risk;
    }
    let has_serious_finding = findings
        .iter()
        .any(|f| matches!(f.severity, Severity::Critical | Severity::High));
    if has_serious_finding {
        return risk;
    }
    (risk - credit.min(MAX_TRUST_CREDIT)).max(0.0)
}

// ---------------------------------------------------------------------------
// Platform implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn verify(path: &Path) -> TrustStatus {
    windows_impl::verify(path)
}

#[cfg(not(windows))]
fn verify(_path: &Path) -> TrustStatus {
    // Authenticode is a Windows concept. On other platforms this is not a
    // failure to report, it is a check that does not apply — but it still must
    // not look like a clean result.
    TrustStatus::Unavailable("Authenticode verification requires Windows".to_string())
}

#[cfg(windows)]
mod windows_impl {
    use super::TrustStatus;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
        CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
        CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
        CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_FIND_SUBJECT_CERT, CERT_INFO,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
        CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, HCERTSTORE,
    };
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
        WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };

    // winerror.h. Compared as u32 because WinVerifyTrust returns them as a
    // sign-extended i32.
    const TRUST_E_NOSIGNATURE: u32 = 0x800B_0100;
    const TRUST_E_BAD_DIGEST: u32 = 0x8009_6010;
    const TRUST_E_EXPLICIT_DISTRUST: u32 = 0x800B_0111;
    const TRUST_E_SUBJECT_NOT_TRUSTED: u32 = 0x800B_0004;
    const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
    const CERT_E_CHAINING: u32 = 0x800B_010A;
    const CERT_E_EXPIRED: u32 = 0x800B_0101;
    const CERT_E_REVOKED: u32 = 0x800B_010C;
    const CERT_E_UNTRUSTEDTESTROOT: u32 = 0x800B_010D;
    const CRYPT_E_FILE_ERROR: u32 = 0x8009_2003;

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub fn verify(path: &Path) -> TrustStatus {
        let wpath = wide(path);

        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: PCWSTR(wpath.as_ptr()),
            hFile: HANDLE::default(),
            pgKnownSubject: std::ptr::null_mut(),
        };

        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            // No network. See the module docs: revocation checking would stall
            // the scan for as long as a remote CRL server cares to take.
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };

        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // SAFETY: `data` and `file_info` are live for the duration of both
        // calls, `action` is a static GUID, and the STATEACTION_CLOSE call
        // below releases the provider state that VERIFY allocated. Skipping
        // that second call leaks a handle per scanned file.
        let status = unsafe {
            let rc = WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut data as *mut _ as *mut core::ffi::c_void,
            );

            data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut data as *mut _ as *mut core::ffi::c_void,
            );

            rc
        };

        if status == 0 {
            return TrustStatus::Trusted {
                publisher: publisher_name(path),
            };
        }

        match status as u32 {
            TRUST_E_NOSIGNATURE => {
                // No signature *embedded in the file*. That is not the same as
                // unsigned: Windows signs most of its own binaries by listing
                // their hashes in a separate signed catalog, so notepad.exe
                // lands here while kernel32.dll does not.
                //
                // Checking only embedded signatures would report a large part
                // of Windows as unsigned, which is both wrong and exactly the
                // kind of confidently-incorrect claim that makes a security
                // tool untrustworthy.
                match catalog_signer(path) {
                    Some(catalog) => TrustStatus::TrustedByCatalog {
                        catalog: Some(catalog),
                    },
                    None => TrustStatus::Unsigned,
                }
            }
            TRUST_E_BAD_DIGEST => TrustStatus::Tampered,
            TRUST_E_EXPLICIT_DISTRUST | CERT_E_REVOKED => TrustStatus::Distrusted {
                publisher: publisher_name(path),
            },
            CERT_E_EXPIRED => TrustStatus::Expired {
                publisher: publisher_name(path),
            },
            CERT_E_UNTRUSTEDROOT
            | CERT_E_CHAINING
            | CERT_E_UNTRUSTEDTESTROOT
            | TRUST_E_SUBJECT_NOT_TRUSTED => TrustStatus::UntrustedRoot {
                publisher: publisher_name(path),
            },
            CRYPT_E_FILE_ERROR => {
                TrustStatus::Unavailable(format!("file could not be read for verification (0x{status:08X})"))
            }
            other => TrustStatus::Unavailable(format!("WinVerifyTrust returned 0x{other:08X}")),
        }
    }

    /// Find a trusted system catalog that vouches for this exact file.
    ///
    /// Returns the catalog's filename, or `None` if no catalog lists the
    /// file's hash. The sequence is: hash the file with the catalog
    /// subsystem's own algorithm, ask which catalogs contain that hash, and
    /// then verify the *catalog* — a hash appearing in a catalog proves
    /// nothing until the catalog's own signature is checked.
    ///
    /// Best-effort: any failure returns `None`, which downgrades the verdict
    /// to "unsigned" rather than claiming trust we did not establish.
    fn catalog_signer(path: &Path) -> Option<String> {
        let file = std::fs::File::open(path).ok()?;
        let handle = HANDLE(file.as_raw_handle() as _);

        let mut admin: isize = 0;
        // SAFETY: `admin` is released on every path out below. The default
        // subsystem (None) is the driver/system catalog set.
        unsafe {
            CryptCATAdminAcquireContext2(&mut admin, None, PCWSTR::null(), None, None).ok()?;
        }

        let result = (|| -> Option<String> {
            // Two-call idiom: ask for the hash length, then for the hash.
            let mut hash_len: u32 = 0;
            unsafe {
                CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut hash_len, None, None)
                    .ok()?;
            }
            if hash_len == 0 || hash_len > 128 {
                return None;
            }
            let mut hash = vec![0u8; hash_len as usize];
            unsafe {
                CryptCATAdminCalcHashFromFileHandle2(
                    admin,
                    handle,
                    &mut hash_len,
                    Some(hash.as_mut_ptr()),
                    None,
                )
                .ok()?;
            }

            let cat_info =
                unsafe { CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None) };
            if cat_info == 0 {
                return None; // no catalog lists this file
            }

            let mut info = CATALOG_INFO {
                cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
                ..Default::default()
            };
            let got = unsafe { CryptCATCatalogInfoFromContext(cat_info, &mut info, 0) }.is_ok();

            // The catalog is only meaningful if the catalog itself verifies.
            // Skipping this would accept any hash listed in any file that
            // happens to be in the catalog store.
            let verified = if got {
                verify_catalog_membership(&info.wszCatalogFile, &mut hash, path)
            } else {
                false
            };

            // SAFETY: `cat_info` came from the successful enumeration above.
            unsafe {
                let _ = CryptCATAdminReleaseCatalogContext(admin, cat_info, 0);
            }

            if !verified {
                return None;
            }

            let name: String = String::from_utf16_lossy(&info.wszCatalogFile)
                .trim_end_matches('\0')
                .to_string();
            Path::new(&name)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .filter(|f| !f.is_empty())
        })();

        // SAFETY: `admin` came from the successful acquire above.
        unsafe {
            let _ = CryptCATAdminReleaseContext(admin, 0);
        }

        result
    }

    /// Verify the catalog that claims to vouch for this file.
    ///
    /// `WTD_CHOICE_CATALOG` asks WinVerifyTrust to check the catalog's own
    /// signature and confirm the member hash is genuinely in it.
    fn verify_catalog_membership(
        catalog_file: &[u16; 260],
        hash: &mut [u8],
        member_path: &Path,
    ) -> bool {
        let member_tag: Vec<u16> = hash
            .iter()
            .flat_map(|b| format!("{b:02X}").encode_utf16().collect::<Vec<u16>>())
            .chain(std::iter::once(0))
            .collect();
        let member_file = wide(member_path);

        let mut cat_info = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: PCWSTR(catalog_file.as_ptr()),
            pcwszMemberTag: PCWSTR(member_tag.as_ptr()),
            pcwszMemberFilePath: PCWSTR(member_file.as_ptr()),
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: hash.len() as u32,
            ..Default::default()
        };

        let mut data = WINTRUST_DATA {
            cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: WTD_CHOICE_CATALOG,
            Anonymous: WINTRUST_DATA_0 {
                pCatalog: &mut cat_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        // SAFETY: every pointer in `cat_info` borrows a local that outlives
        // both calls, and STATEACTION_CLOSE releases the provider state.
        unsafe {
            let rc = WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut data as *mut _ as *mut core::ffi::c_void,
            );
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut action,
                &mut data as *mut _ as *mut core::ffi::c_void,
            );
            rc == 0
        }
    }

    /// Read the signer's display name out of the embedded PKCS#7 message.
    ///
    /// Best-effort throughout: a file can verify perfectly well while this
    /// fails, so every step returns `None` rather than changing the verdict.
    fn publisher_name(path: &Path) -> Option<String> {
        let wpath = wide(path);
        let mut store = HCERTSTORE::default();
        let mut msg: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut encoding = CERT_QUERY_ENCODING_TYPE::default();

        // SAFETY: `wpath` outlives the call; the two out-params are owned
        // handles closed on every path out of this function below.
        unsafe {
            CryptQueryObject(
                CERT_QUERY_OBJECT_FILE,
                wpath.as_ptr() as *const core::ffi::c_void,
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                CERT_QUERY_FORMAT_FLAG_BINARY,
                0,
                Some(&mut encoding),
                None,
                None,
                Some(&mut store),
                Some(&mut msg),
                None,
            )
            .ok()?;
        }

        let name = unsafe { signer_display_name(msg, store, encoding) };

        // SAFETY: both handles came from the successful CryptQueryObject above
        // and have not been closed yet.
        unsafe {
            if !msg.is_null() {
                let _ = CryptMsgClose(Some(msg));
            }
            if !store.is_invalid() {
                let _ = CertCloseStore(Some(store), 0);
            }
        }

        name
    }

    /// SAFETY: `msg` and `store` must be live handles from `CryptQueryObject`.
    unsafe fn signer_display_name(
        msg: *mut core::ffi::c_void,
        store: HCERTSTORE,
        encoding: CERT_QUERY_ENCODING_TYPE,
    ) -> Option<String> {
        if msg.is_null() || store.is_invalid() {
            return None;
        }

        // Two-call idiom: ask for the size, allocate, then ask for the data.
        // The buffer is sized from what the API reports, never from the file.
        let mut size: u32 = 0;
        unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut size).ok()? };
        if size == 0 || size as usize > 1024 * 1024 {
            return None;
        }

        let mut buf = vec![0u8; size as usize];
        unsafe {
            CryptMsgGetParam(
                msg,
                CMSG_SIGNER_INFO_PARAM,
                0,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut size,
            )
            .ok()?
        };
        if (size as usize) < std::mem::size_of::<CMSG_SIGNER_INFO>() {
            return None;
        }

        // The signer info identifies its certificate by issuer + serial. Those
        // two fields laid out as a CERT_INFO are what CERT_FIND_SUBJECT_CERT
        // matches on.
        let signer = unsafe { &*(buf.as_ptr() as *const CMSG_SIGNER_INFO) };
        let cert_info = CERT_INFO {
            Issuer: signer.Issuer,
            SerialNumber: signer.SerialNumber,
            ..Default::default()
        };

        let cert = unsafe {
            CertFindCertificateInStore(
                store,
                encoding,
                0,
                CERT_FIND_SUBJECT_CERT,
                Some(&cert_info as *const _ as *const core::ffi::c_void),
                None,
            )
        };
        if cert.is_null() {
            return None;
        }

        // Two-call idiom again: the first call returns the length in
        // characters, including the terminating NUL.
        let needed = unsafe {
            CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None)
        };
        let name = if needed > 1 && needed < 4096 {
            let mut wbuf = vec![0u16; needed as usize];
            let written = unsafe {
                CertGetNameStringW(
                    cert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    Some(wbuf.as_mut_slice()),
                )
            };
            if written > 1 {
                Some(String::from_utf16_lossy(&wbuf[..written as usize - 1]))
            } else {
                None
            }
        } else {
            None
        };

        // SAFETY: `cert` came from CertFindCertificateInStore above.
        unsafe {
            let _ = CertFreeCertificateContext(Some(cert));
        };

        name.filter(|n| !n.trim().is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(sev: Severity, risk: f32) -> Finding {
        Finding::new(sev, "t", "d", "w", risk)
    }

    // --- The withholding rule ----------------------------------------------
    //
    // These are the tests that matter. They define whether signing malware is
    // a viable way to buy down a detection.

    #[test]
    fn trust_credit_settles_an_ambiguous_file() {
        let findings = [finding(Severity::Medium, 0.45), finding(Severity::Low, 0.2)];
        let adjusted = apply_trust_credit(0.45, MAX_TRUST_CREDIT, &findings);
        assert!(
            adjusted < 0.4,
            "a signed file with only medium signals should fall below the sandbox threshold, \
             got {adjusted}"
        );
    }

    /// The evasion this rule exists to prevent: buy a certificate, sign the
    /// dropper, watch a real detection get discounted away.
    #[test]
    fn trust_credit_cannot_argue_away_a_serious_finding() {
        for sev in [Severity::Critical, Severity::High] {
            let findings = [finding(sev, 0.7)];
            assert_eq!(
                apply_trust_credit(0.7, MAX_TRUST_CREDIT, &findings),
                0.7,
                "a valid signature must not reduce risk when a {sev:?} finding is present - \
                 otherwise signing malware buys a discount off the detection"
            );
        }
    }

    #[test]
    fn trust_credit_is_capped_however_large_the_input() {
        let findings = [finding(Severity::Low, 0.1)];
        let adjusted = apply_trust_credit(0.5, 10.0, &findings);
        assert_eq!(adjusted, 0.5 - MAX_TRUST_CREDIT);
    }

    #[test]
    fn trust_credit_never_produces_a_negative_score() {
        assert_eq!(apply_trust_credit(0.1, MAX_TRUST_CREDIT, &[]), 0.0);
    }

    #[test]
    fn no_credit_leaves_the_score_untouched() {
        let findings = [finding(Severity::Medium, 0.4)];
        assert_eq!(apply_trust_credit(0.4, 0.0, &findings), 0.4);
    }

    // --- Status to findings -------------------------------------------------

    #[test]
    fn tampering_is_critical_and_earns_no_credit() {
        let res = build_result(TrustStatus::Tampered, true);
        assert!(res.flagged);
        assert_eq!(res.trust_credit, 0.0);
        assert!(res.risk >= 0.8);
        assert_eq!(res.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn explicit_distrust_outranks_being_unsigned() {
        let distrusted = build_result(
            TrustStatus::Distrusted {
                publisher: Some("Dodgy Ltd".into()),
            },
            true,
        );
        let unsigned = build_result(TrustStatus::Unsigned, true);
        assert!(distrusted.risk > unsigned.risk);
        assert!(distrusted.findings[0].detail.contains("Dodgy Ltd"));
    }

    /// Unsigned software is extremely common and must stay a weak signal, or
    /// every small utility becomes a false positive.
    #[test]
    fn unsigned_is_only_a_weak_signal() {
        let res = build_result(TrustStatus::Unsigned, true);
        assert!(res.risk < 0.3, "unsigned scored {}", res.risk);
        assert_eq!(res.findings[0].severity, Severity::Low);
    }

    /// Certificates expire and old software keeps working. This must not be
    /// treated like a broken signature.
    #[test]
    fn expiry_is_treated_as_routine_not_as_tampering() {
        let expired = build_result(
            TrustStatus::Expired {
                publisher: Some("Old Corp".into()),
            },
            true,
        );
        let tampered = build_result(TrustStatus::Tampered, true);
        assert!(expired.risk < 0.2);
        assert!(tampered.risk > expired.risk * 4.0);
        assert!(expired.findings[0].why.contains("common and usually harmless"));
    }

    #[test]
    fn a_valid_signature_is_reported_without_being_an_anomaly() {
        let res = build_result(
            TrustStatus::Trusted {
                publisher: Some("Example Corp".into()),
            },
            true,
        );
        assert!(!res.flagged, "a good signature must not read as a problem");
        assert_eq!(res.risk, 0.0);
        assert_eq!(res.trust_credit, MAX_TRUST_CREDIT);
        assert!(res.findings[0].title.contains("Example Corp"));
    }

    /// An unanswered question is not an answer. A failed check must contribute
    /// nothing in either direction, but must still be visible.
    #[test]
    fn unavailable_contributes_nothing_but_is_still_reported() {
        let res = build_result(TrustStatus::Unavailable("no provider".into()), true);
        assert_eq!(res.risk, 0.0);
        assert_eq!(res.trust_credit, 0.0);
        assert!(!res.flagged);
        assert!(!res.findings.is_empty(), "a skipped check must not be silent");
    }

    /// Images are never signed. Saying "this PNG is unsigned" is noise that
    /// would appear on almost every download.
    #[test]
    fn unsignable_formats_are_not_checked_at_all() {
        for name in ["photo.png", "notes.txt", "report.pdf", "music.mp3"] {
            let res = analyse(None, false, name).unwrap();
            assert!(res.status.is_none(), "{name} should not be checked");
            assert!(res.findings.is_empty());
            assert_eq!(res.risk, 0.0);
        }
    }

    #[test]
    fn signable_formats_without_a_path_report_that_they_were_not_checked() {
        let res = analyse(None, true, "setup.exe").unwrap();
        assert!(matches!(res.status, Some(TrustStatus::Unavailable(_))));
        assert_eq!(res.risk, 0.0);
        assert_eq!(res.trust_credit, 0.0);
    }
}
