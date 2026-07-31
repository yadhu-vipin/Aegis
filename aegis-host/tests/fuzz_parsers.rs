//! Mutation fuzzing for every parser that reads attacker-controlled bytes.
//!
//! ## Why this exists
//!
//! Aegis parses formats an attacker fully controls: PE headers, ZIP central
//! directories, LNK shortcuts, OLE compound files, and the native-messaging
//! frame that carries all of it. Every offset, length and count these parsers
//! act on is a number written by whoever made the file.
//!
//! The bug that class produces is always the same shape:
//!
//! ```ignore
//! let name_len = u16_at(data, off + 28)? as usize;
//! let name = &data[start..start + name_len];   // panics: attacker set 0xFFFF
//! ```
//!
//! **A panic here is not a normal crash.** The host dying drops the native
//! messaging port; the extension correctly reads that as "cannot verify" and
//! cancels. So a single crafted file does not infect anyone — it fails in the
//! safe direction — but it *stops every download on the machine* until the user
//! works out why. That is a denial of service triggered by one download, which
//! is why the build spec forbids panics on any path.
//!
//! Hangs count too, and are easier to miss. Each parser bounds its loops
//! (`MAX_ENTRIES`, 256 import descriptors, 4096 thunks). If any bound is wrong,
//! a crafted file spins inside it while the download sits open forever. So the
//! oracle here is "no panic **and** finished within a time budget", not just
//! "no panic".
//!
//! ## Why mutation rather than `cargo-fuzz`
//!
//! Coverage-guided fuzzing is strictly better at finding deep bugs, and it
//! needs a nightly toolchain plus libFuzzer, which is awkward on Windows/MSVC.
//! Two things decided it for this project:
//!
//! * These parsers are new. The bugs still in them are the shallow ones — a
//!   forgotten bounds check, a trusted length — and blind mutation finds those
//!   readily. Coverage guidance earns its keep on mature parsers.
//! * A `cargo-fuzz` run is an event someone has to remember to repeat. This
//!   runs on every `cargo test`, forever, and any parser added later is covered
//!   by adding one line to `TARGETS`.
//!
//! If a case ever fails, the panic message carries the seed and the exact
//! mutation, and [`replay`] turns those back into the failing input.

use std::time::{Duration, Instant};

#[path = "../src/scanner/mod.rs"]
mod scanner;

// Pulled in by path so the frame parser can be driven from a buffer. Most of
// this module writes to stdout and is unused here, hence the allow.
#[allow(dead_code)]
#[path = "../src/ipc/native_messaging.rs"]
mod native_messaging;

/// Iterations per (seed corpus entry × target). Total cases is this times the
/// corpus size times the target count — kept to a few seconds of wall clock so
/// nobody is tempted to skip the suite.
const ITERATIONS: u32 = 400;

/// A single input may not take longer than this to analyse.
///
/// Generous on purpose: this is a debug build on a loaded machine, and the
/// point is to catch a parser looping essentially forever, not to benchmark.
/// Anything that trips this is spinning, not merely slow.
const PER_INPUT_BUDGET: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Deterministic PRNG
// ---------------------------------------------------------------------------

/// xorshift64*. Deterministic and seedable, so every failure replays exactly.
///
/// Deliberately not `rand`: a fuzzer whose failures cannot be reproduced is a
/// fuzzer that reports bugs nobody can fix.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state is a fixed point for xorshift and would emit only zeros.
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }
}

// ---------------------------------------------------------------------------
// Seed corpus — valid files, so mutations start from something meaningful
// ---------------------------------------------------------------------------

/// A minimal but structurally valid PE32 with one section.
fn seed_pe() -> Vec<u8> {
    let pe_off = 0x80usize;
    let opt_size = 0xE0usize;
    let sec_table = pe_off + 4 + 20 + opt_size;
    let mut d = vec![0u8; sec_table + 40 + 0x200];

    d[0..2].copy_from_slice(b"MZ");
    d[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    d[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    d[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
    d[pe_off + 20..pe_off + 22].copy_from_slice(&(opt_size as u16).to_le_bytes());

    let opt = pe_off + 4 + 20;
    d[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32
    d[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point

    let o = sec_table;
    d[o..o + 5].copy_from_slice(b".text");
    d[o + 8..o + 12].copy_from_slice(&0x200u32.to_le_bytes()); // virtual size
    d[o + 12..o + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual addr
    d[o + 16..o + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
    d[o + 20..o + 24].copy_from_slice(&(sec_table as u32 + 40).to_le_bytes()); // raw ptr
    d[o + 36..o + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // R+X
    d
}

/// A stored ZIP with two entries, one of them nested in a directory.
fn seed_zip() -> Vec<u8> {
    zip(&[("readme.txt", b"hello world"), ("bin/tool.exe", b"MZ\x90\x00")])
}

fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();

    for (name, content) in entries {
        let local_offset = out.len() as u32;
        out.extend(b"PK\x03\x04");
        out.extend(20u16.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend([0u8; 4]);
        out.extend(0u32.to_le_bytes());
        out.extend((content.len() as u32).to_le_bytes());
        out.extend((content.len() as u32).to_le_bytes());
        out.extend((name.len() as u16).to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend(name.as_bytes());
        out.extend(*content);

        central.extend(b"PK\x01\x02");
        central.extend(20u16.to_le_bytes());
        central.extend(20u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend([0u8; 4]);
        central.extend(0u32.to_le_bytes());
        central.extend((content.len() as u32).to_le_bytes());
        central.extend((content.len() as u32).to_le_bytes());
        central.extend((name.len() as u16).to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend(0u16.to_le_bytes());
        central.extend(0u32.to_le_bytes());
        central.extend(local_offset.to_le_bytes());
        central.extend(name.as_bytes());
    }

    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend(&central);
    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]);
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend((entries.len() as u16).to_le_bytes());
    out.extend(cd_size.to_le_bytes());
    out.extend(cd_offset.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

/// An OOXML-shaped ZIP: the macro-bearing document case.
fn seed_ooxml() -> Vec<u8> {
    zip(&[
        ("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>"),
        ("word/document.xml", b"<?xml version=\"1.0\"?><document/>"),
        ("word/vbaProject.bin", b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1macro"),
    ])
}

/// A minimal Windows shortcut: the LNK header is fixed-size and self-describing.
fn seed_lnk() -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(0x0000_004Cu32.to_le_bytes()); // header size
    d.extend([
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]); // CLSID
    d.extend(0x8000_0084u32.to_le_bytes()); // link flags
    d.extend(0x0000_0020u32.to_le_bytes()); // file attributes
    d.extend([0u8; 8 * 3]); // creation / access / write times
    d.extend(0u32.to_le_bytes()); // file size
    d.extend(0u32.to_le_bytes()); // icon index
    d.extend(1u32.to_le_bytes()); // show command
    d.extend(0u16.to_le_bytes()); // hotkey
    d.extend([0u8; 10]); // reserved
    // A COMMAND_LINE_ARGUMENTS StringData block.
    let args: Vec<u16> = "/c powershell -enc ZQBjAGgAbwA="
        .encode_utf16()
        .collect();
    d.extend((args.len() as u16).to_le_bytes());
    for u in args {
        d.extend(u.to_le_bytes());
    }
    d
}

fn seed_png() -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
    v.extend(std::iter::repeat_n(0xA5u8, 256));
    v.extend(b"IEND\xAE\x42\x60\x82");
    v
}

fn seed_ole() -> Vec<u8> {
    let mut v = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec();
    v.extend(std::iter::repeat_n(0u8, 504));
    v.extend(b"V\0b\0a\0P\0r\0o\0j\0e\0c\0t\0");
    v.extend(std::iter::repeat_n(0u8, 256));
    v
}

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut c = vec![
        ("pe", seed_pe()),
        ("zip", seed_zip()),
        ("ooxml", seed_ooxml()),
        ("lnk", seed_lnk()),
        ("png", seed_png()),
        ("ole", seed_ole()),
        ("empty", Vec::new()),
        ("tiny", b"MZ".to_vec()),
    ];
    // Real samples committed to the repo, when present. These have shapes no
    // hand-built fixture thinks to produce.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("test_files"));
    if let Some(dir) = root {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                if let Ok(bytes) = std::fs::read(e.path()) {
                    if !bytes.is_empty() && bytes.len() < 2 * 1024 * 1024 {
                        c.push(("real", bytes));
                    }
                }
            }
        }
    }
    c
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mutation {
    /// Flip bits in a handful of random bytes.
    FlipBytes,
    /// Cut the input short at a random point — the single most productive
    /// mutation against parsers that read a length and then index.
    Truncate,
    /// Overwrite an aligned 2/4/8-byte window with an extreme value.
    ///
    /// This is the one that matters. Every parser here reads sizes, counts and
    /// offsets as little-endian integers, and `0xFFFF` / `0xFFFFFFFF` are
    /// exactly the values that turn `start + len` into an out-of-bounds slice
    /// or a loop that never ends.
    SlamLengthField,
    /// Splice a region from elsewhere in the same input over itself.
    Splice,
    /// Append junk, so trailing-data paths get exercised.
    Extend,
    /// Zero a run of bytes.
    Zero,
}

const MUTATIONS: &[Mutation] = &[
    Mutation::FlipBytes,
    Mutation::Truncate,
    Mutation::SlamLengthField,
    Mutation::SlamLengthField, // weighted: the highest-yield mutation
    Mutation::Splice,
    Mutation::Extend,
    Mutation::Zero,
];

/// Extreme values for `SlamLengthField`, chosen to be the ones that break
/// arithmetic rather than merely being large.
const EXTREMES: &[u64] = &[
    0,
    1,
    0x7F,
    0xFF,
    0x7FFF,
    0xFFFF,
    0x7FFF_FFFF,
    0xFFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
];

fn mutate(input: &[u8], rng: &mut Rng, how: Mutation) -> Vec<u8> {
    let mut d = input.to_vec();
    if d.is_empty() {
        d.extend_from_slice(b"MZ\x90\x00");
    }

    match how {
        Mutation::FlipBytes => {
            let n = 1 + rng.below(8);
            for _ in 0..n {
                let i = rng.below(d.len());
                d[i] ^= 1 << rng.below(8);
            }
        }
        Mutation::Truncate => {
            let at = rng.below(d.len());
            d.truncate(at);
        }
        Mutation::SlamLengthField => {
            let width = [2usize, 4, 8][rng.below(3)];
            let value = EXTREMES[rng.below(EXTREMES.len())];
            if d.len() >= width {
                let at = rng.below(d.len() - width + 1);
                let bytes = value.to_le_bytes();
                d[at..at + width].copy_from_slice(&bytes[..width]);
            }
        }
        Mutation::Splice => {
            if d.len() > 8 {
                let len = 1 + rng.below(d.len() / 2);
                let from = rng.below(d.len() - len + 1);
                let to = rng.below(d.len() - len + 1);
                let chunk: Vec<u8> = d[from..from + len].to_vec();
                d[to..to + len].copy_from_slice(&chunk);
            }
        }
        Mutation::Extend => {
            let n = 1 + rng.below(512);
            for _ in 0..n {
                d.push(rng.byte());
            }
        }
        Mutation::Zero => {
            let len = 1 + rng.below(d.len());
            let at = rng.below(d.len() - len + 1);
            for b in &mut d[at..at + len] {
                *b = 0;
            }
        }
    }
    d
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

/// Every parser that consumes untrusted bytes.
///
/// Adding a parser to Aegis means adding a line here. The filename passed is
/// deliberately varied per target, because several checks branch on the
/// claimed extension and a single name would leave those branches unfuzzed.
type Target = (&'static str, fn(&[u8], &str));

const TARGETS: &[Target] = &[
    ("pe", |d, _| {
        let _ = scanner::pe::analyse(d);
    }),
    ("archive", |d, n| {
        let _ = scanner::archive::analyse(d, n);
        let _ = scanner::archive::list_entries(d);
    }),
    ("autoexec", |d, n| {
        let _ = scanner::autoexec::analyse(d, n);
    }),
    ("structure", |d, n| {
        let _ = scanner::structure::analyse(d, n);
    }),
    ("entropy", |d, n| {
        let ext = n.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
        let _ = scanner::entropy::analyse(d, ext);
    }),
    ("magic_bytes", |d, n| {
        let _ = scanner::magic_bytes::scan_file(d, n);
    }),
    ("whole_file", |d, n| {
        let _ = scanner::whole_file_scan(d, n);
    }),
];

/// Filenames that steer extension-dependent branches.
const NAMES: &[&str] = &[
    "sample.zip",
    "invoice.pdf.exe",
    "document.docm",
    "shortcut.lnk",
    "photo.png",
    "installer.msi",
    "autorun.inf",
    "",
    ".",
    "no_extension",
];

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// Rebuild the exact input for a reported failure.
///
/// Kept public-ish and documented because it is the whole reason the PRNG is
/// deterministic: a failure message names a seed, a corpus entry and a
/// mutation, and this turns those three back into bytes.
fn replay(seed_bytes: &[u8], seed: u64, how: Mutation) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    mutate(seed_bytes, &mut rng, how)
}

#[test]
fn parsers_survive_mutated_input() {
    let corpus = corpus();
    let mut cases = 0u64;
    let mut slowest = Duration::ZERO;
    let mut slowest_desc = String::new();

    for (target_name, target) in TARGETS {
        for (corpus_name, seed_bytes) in &corpus {
            for i in 0..ITERATIONS {
                // Seed encodes everything needed to reproduce this case.
                let seed = (*target_name).len() as u64 * 1_000_003
                    + corpus_name.len() as u64 * 10_007
                    + u64::from(i) * 31
                    + seed_bytes.len() as u64;
                let mut rng = Rng::new(seed);
                let how = MUTATIONS[rng.below(MUTATIONS.len())];
                let data = replay(seed_bytes, seed, how);
                let name = NAMES[rng.below(NAMES.len())];

                let started = Instant::now();
                // A panic here fails the test with the seed in the message
                // below; there is no catch_unwind because the default panic
                // output plus this context is enough to reproduce.
                target(&data, name);
                let elapsed = started.elapsed();

                assert!(
                    elapsed < PER_INPUT_BUDGET,
                    "target {target_name:?} took {elapsed:?} on a mutated {corpus_name:?} \
                     ({} bytes, name {name:?}) — a parser this slow is looping, and a looping \
                     parser holds the download open forever. \
                     Reproduce with seed={seed} mutation={how:?}",
                    data.len()
                );

                if elapsed > slowest {
                    slowest = elapsed;
                    slowest_desc =
                        format!("{target_name}/{corpus_name} seed={seed} mutation={how:?}");
                }
                cases += 1;
            }
        }
    }

    // Not an assertion about correctness — a guard against the suite silently
    // becoming a no-op if the corpus or target list is ever emptied.
    assert!(
        cases > 10_000,
        "only {cases} fuzz cases ran; the corpus or target list has shrunk"
    );
    eprintln!("fuzzed {cases} cases; slowest {slowest:?} ({slowest_desc})");
}

/// The frame parser, fuzzed separately because it reads from a stream rather
/// than a slice.
///
/// This is the first attacker-controlled input the process ever touches, and
/// its length field decides an allocation — so `FF FF FF FF` here is a
/// four-byte request to reserve 4 GB. The ceiling in `read_frame` is what makes
/// that a rejection instead of an out-of-memory kill.
#[test]
fn frame_parser_survives_mutated_input() {
    let mut cases = 0u64;

    // Well-formed frames to mutate from.
    let seeds: Vec<Vec<u8>> = [
        serde_json::json!({ "type": "PING" }),
        serde_json::json!({ "type": "WATCH_BEGIN", "session_id": "s", "quarantine_path": "p" }),
        serde_json::json!({ "type": "CHECK_URL", "url": "https://example.invalid/x" }),
    ]
    .iter()
    .map(|v| {
        let body = serde_json::to_vec(v).unwrap();
        let mut f = (body.len() as u32).to_le_bytes().to_vec();
        f.extend(body);
        f
    })
    .collect();

    for (si, seed_frame) in seeds.iter().enumerate() {
        for i in 0..ITERATIONS * 4 {
            let seed = si as u64 * 7_919 + u64::from(i) * 131 + 17;
            let mut rng = Rng::new(seed);
            let how = MUTATIONS[rng.below(MUTATIONS.len())];
            let data = replay(seed_frame, seed, how);

            let started = Instant::now();
            let mut cursor = std::io::Cursor::new(&data);
            // Every outcome is acceptable except panicking or hanging: a
            // rejected frame is the parser working.
            let _ = native_messaging::read_frame(&mut cursor);
            let elapsed = started.elapsed();

            assert!(
                elapsed < PER_INPUT_BUDGET,
                "frame parser took {elapsed:?} on {} bytes — reproduce with seed={seed} \
                 mutation={how:?}",
                data.len()
            );
            cases += 1;
        }
    }

    eprintln!("fuzzed {cases} frame cases");
}

/// A length prefix must never cause an allocation proportional to itself.
///
/// Split out from the mutation loop because it is a specific claim worth
/// stating directly rather than hoping mutation stumbles onto it: an oversized
/// length is rejected on the strength of the header alone, without reading or
/// reserving the body.
#[test]
fn oversized_length_prefix_allocates_nothing() {
    for claimed in [
        native_messaging::MAX_MESSAGE_BYTES + 1,
        0x7FFF_FFFF,
        0xFFFF_FFFF,
    ] {
        let mut data = claimed.to_le_bytes().to_vec();
        data.extend_from_slice(b"{}"); // body nowhere near the claimed length

        let started = Instant::now();
        let mut cursor = std::io::Cursor::new(&data);
        let result = native_messaging::read_frame(&mut cursor);
        let elapsed = started.elapsed();

        assert!(
            result.is_err(),
            "a frame claiming {claimed} bytes must be rejected, not parsed"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "rejecting an oversized prefix took {elapsed:?} — the length was probably \
             used to size an allocation before being validated"
        );
    }
}

/// The boundary cases around the length field, and what each one means.
///
/// Three outcomes are possible and they are not interchangeable: `Ok(Some)` is
/// a message, `Err` is a malformed stream, and `Ok(None)` means the pipe closed
/// and the host should exit. Getting the last two confused is how a scanner
/// either exits on garbage or loops on a dead pipe.
#[test]
fn degenerate_frames_are_classified_correctly() {
    // Length 0 is malformed: a frame must carry a body.
    let mut cursor = std::io::Cursor::new(0u32.to_le_bytes().to_vec());
    assert!(
        native_messaging::read_frame(&mut cursor).is_err(),
        "a zero-length frame must be rejected"
    );

    // Header promises 100 bytes, one arrives. The stream lied.
    let mut data = 100u32.to_le_bytes().to_vec();
    data.extend_from_slice(b"{");
    let mut cursor = std::io::Cursor::new(data);
    assert!(
        native_messaging::read_frame(&mut cursor).is_err(),
        "a truncated body must be rejected"
    );

    // Empty input is a clean disconnect — Chrome closed the port.
    let mut cursor = std::io::Cursor::new(Vec::new());
    assert!(
        matches!(native_messaging::read_frame(&mut cursor), Ok(None)),
        "an empty stream is a clean shutdown, not an error"
    );

    // A PARTIAL length prefix is also reported as a disconnect, because
    // `read_exact` cannot distinguish "pipe closed mid-header" from "pipe
    // closed", and reports both as UnexpectedEof.
    //
    // That is the safe way round. `Ok(None)` makes the host exit without
    // issuing a verdict, and no verdict means the extension's fail-closed path
    // cancels the download. Treating it as `Err` would reach the same place by
    // a noisier route. What must NOT happen is a partial header being padded
    // out and parsed as a real length — which is why this is asserted rather
    // than left to chance.
    let mut cursor = std::io::Cursor::new(vec![1u8, 2]);
    assert!(
        matches!(native_messaging::read_frame(&mut cursor), Ok(None)),
        "a partial length prefix must be treated as a disconnect, never padded \
         out into a length"
    );
}

/// The mutation engine itself must be deterministic, or every failure it
/// reports is unreproducible and therefore useless.
#[test]
fn mutations_are_reproducible() {
    let seed_data = seed_zip();
    for how in MUTATIONS {
        let a = replay(&seed_data, 12345, *how);
        let b = replay(&seed_data, 12345, *how);
        assert_eq!(a, b, "mutation {how:?} is not deterministic");
    }
    // Different seeds should generally produce different output, or the
    // fuzzer is exploring a single point.
    let distinct: std::collections::HashSet<Vec<u8>> = (0..64)
        .map(|s| replay(&seed_data, s, Mutation::FlipBytes))
        .collect();
    assert!(
        distinct.len() > 32,
        "64 seeds produced only {} distinct inputs — the PRNG is not mixing",
        distinct.len()
    );
}
