/**
 * Aegis Service Worker — background.js
 *
 * Layer 2 (file triage), Phase 2 architecture.
 *
 * HOW INTERCEPTION WORKS, AND WHY IT CHANGED
 * ------------------------------------------
 * Chrome exposes no API for a download's byte stream. The previous design
 * worked around that by pausing the download and calling fetch() on the same
 * URL to get the bytes — which meant:
 *
 *   - the file was written to the user's real Downloads folder anyway
 *   - the URL was fetched TWICE (double bandwidth), and the bytes scanned were
 *     not the bytes delivered, so a server could serve benign content to the
 *     scan and malicious content to the browser
 *   - POST-initiated, one-time-token, blob:, and auth-gated downloads simply
 *     could not be re-fetched
 *   - three separate error paths called resume(), releasing files uninspected
 *
 * Instead we now use onDeterminingFilename to redirect the download into a
 * quarantine subdirectory that Aegis owns, and let Chrome perform the single
 * fetch it was always going to perform. Cookies, sessions, POST bodies and
 * one-time tokens all keep working. The native host tails the file as Chrome
 * writes it and can cancel the download mid-flight. Nothing reaches the real
 * Downloads folder unless the host moves it there after a clean verdict.
 *
 * FAIL CLOSED: every error path cancels the download. A scanner that cannot
 * scan must not wave the file through.
 */

const NATIVE_HOST_NAME = "com.aegis.sandbox";
const ML_SERVICE_URL = "http://127.0.0.1:8787/score";

/**
 * MUST match `quarantine.subdir` in aegis.toml exactly.
 *
 * These two values live in different languages and cannot share a constant, so
 * they can silently drift — and they did: this was "aegis-quarantine" (hyphen)
 * while aegis.toml said "aegis_quarantine" (underscore), which made the host
 * reject every single download as being outside the quarantine root.
 *
 * The failure is at least loud (REJECTED_MALFORMED naming both paths), and
 * `quarantine_subdir_matches_config` in tests/ipc_roundtrip.rs asserts the two
 * stay in sync. If you change one, change the other.
 */
const QUARANTINE_SUBDIR = "aegis_quarantine";

/** downloadId -> session state */
const activeSessions = new Map();

// ---------------------------------------------------------------------------
// Verdict history (for the popup)
// ---------------------------------------------------------------------------

async function saveVerdict(entry) {
  try {
    const { recentVerdicts = [] } = await chrome.storage.local.get("recentVerdicts");
    recentVerdicts.unshift({ ...entry, timestamp: new Date().toISOString() });
    if (recentVerdicts.length > 50) recentVerdicts.length = 50;
    await chrome.storage.local.set({ recentVerdicts });
  } catch (err) {
    console.error("[Aegis] Failed to persist verdict:", err);
  }
}

async function setBadge(text, color) {
  try {
    await chrome.action.setBadgeText({ text });
    if (color) await chrome.action.setBadgeBackgroundColor({ color });
  } catch { /* action API unavailable in some contexts */ }
}

// ---------------------------------------------------------------------------
// User-visible feedback
// ---------------------------------------------------------------------------
//
// A security tool that blocks silently is indistinguishable from a broken one.
// If Aegis stops a download, the user must be told what happened and why —
// otherwise the file just vanishes and they assume the download failed.

/**
 * Turn the host's technical verdict into one plain sentence.
 *
 * The host's strings are precise but dense, e.g.
 *   "Risk score 1.00 crossed block threshold 0.85 after 68 bytes.
 *    Signals: [risk=0.80] nc -e /bin/sh: Netcat reverse shell; ..."
 * The notification gets the human summary; the popup keeps the full detail.
 */
function humanReason(verdictText = "") {
  const t = verdictText.toLowerCase();

  if (t.includes("another security product") || t.includes("windows defender")) {
    return "Windows Defender identified this file as malware and removed it.";
  }
  if (t.includes("reverse shell") || t.includes("netcat")) {
    return "The file contained a reverse-shell command — a remote-access backdoor.";
  }
  if (t.includes("eicar")) {
    return "The file matched the EICAR antivirus test signature.";
  }
  if (t.includes("masquerad") || t.includes("mismatch")) {
    return "The file's real type doesn't match its extension — a program disguised as a document or image.";
  }
  if (t.includes("injection") || t.includes("createremotethread")) {
    return "The file contained process-injection code used to hijack other programs.";
  }
  if (t.includes("keylog") || t.includes("setwindowshookex")) {
    return "The file contained keylogging code.";
  }
  if (t.includes("persistence") || t.includes("autorun")) {
    return "The file tried to install itself to run automatically at startup.";
  }
  if (t.includes("sandbox analysis failed") || t.includes("sandbox verdict")) {
    return "The file behaved suspiciously when run in an isolated sandbox.";
  }
  if (t.includes("incomplete") || t.includes("truncat")) {
    return "The download ended early, so it could not be fully checked.";
  }
  if (t.includes("could not verify") || t.includes("unreachable") || t.includes("disconnected")) {
    return "Aegis couldn't finish scanning this file, so it was not saved.";
  }
  if (t.includes("too large")) {
    return "The file was too large to analyse safely.";
  }
  if (t.includes("stalled")) {
    return "The download stalled and was abandoned.";
  }
  return "Aegis found something suspicious in this file.";
}

let notificationSeq = 0;

/**
 * Raise a desktop notification. Blocks are loud; releases stay quiet so we
 * don't train the user to dismiss Aegis notifications on reflex.
 */
function notify({ blocked, filename, verdictText, earlyKill }) {
  const id = `aegis-${Date.now()}-${notificationSeq++}`;

  const title = blocked
    ? (earlyKill ? "Aegis stopped a download mid-transfer" : "Aegis blocked a download")
    : "Aegis cleared a download";

  const message = blocked
    ? `${filename}\n\n${humanReason(verdictText)}\n\nThe file was not saved to your computer.`
    : `${filename} was scanned and saved.`;

  try {
    chrome.notifications.create(id, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon128.png"),
      title,
      message,
      priority: blocked ? 2 : 0,
      requireInteraction: !!blocked
    }, () => void chrome.runtime.lastError);
  } catch (err) {
    console.warn("[Aegis] notification failed:", err);
  }
}

// ---------------------------------------------------------------------------
// Layer 1 — URL hover check (unchanged; out of scope for this phase)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "CHECK_URL") {
    handleCheckUrl(message.url).then(sendResponse).catch((err) => {
      sendResponse({ score: 0.5, label: "unscored", reason: err.message });
    });
    return true;
  }
  if (message.type === "GET_ACTIVE_SESSIONS") {
    sendResponse(Array.from(activeSessions.values()).map((s) => ({
      filename: s.originalFilename,
      state: s.state,
      bytesScanned: s.bytesScanned || 0,
      riskScore: s.riskScore || 0
    })));
    return false;
  }
});

async function handleCheckUrl(url) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 500);
  try {
    const response = await fetch(ML_SERVICE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (!response.ok) return { score: 0.5, label: "unscored", reason: `HTTP ${response.status}` };
    const data = await response.json();
    // Validate the local service's response rather than trusting it — a
    // misconfigured or compromised local service is inside the threat model.
    return {
      score: typeof data.score === "number" ? Math.min(Math.max(data.score, 0), 1) : 0.5,
      label: typeof data.label === "string" ? data.label : "unscored"
    };
  } catch {
    clearTimeout(timeoutId);
    // Layer 1 fails OPEN by design: never block browsing because a local
    // scoring service is down. This is a badge, not a gate. Layer 2 (below)
    // fails CLOSED, which is where the actual safety property lives.
    return { score: 0.5, label: "unscored", reason: "ML service unreachable" };
  }
}

// ---------------------------------------------------------------------------
// Layer 2 — download interception
// ---------------------------------------------------------------------------

function uuid() {
  return crypto.randomUUID();
}

/**
 * Redirect every download into the Aegis quarantine subdirectory.
 *
 * Chrome requires the suggested name to be RELATIVE to the default Downloads
 * directory — absolute paths and ".." are rejected outright — so quarantine is
 * necessarily a subfolder of Downloads. The host moves cleared files up into
 * Downloads proper and deletes the rest.
 */
chrome.downloads.onDeterminingFilename.addListener((downloadItem, suggest) => {
  const id = uuid();
  const quarantineRelative = `${QUARANTINE_SUBDIR}/${id}.aegispart`;

  // Remember the name the user expects to see, before we rename it away.
  const originalFilename =
    (downloadItem.filename && downloadItem.filename.split(/[\\/]/).pop()) ||
    "download.bin";

  activeSessions.set(downloadItem.id, {
    sessionId: `s-${downloadItem.id}-${Date.now()}`,
    quarantineId: id,
    originalFilename,
    url: downloadItem.url,
    state: "pending",
    port: null,
    bytesScanned: 0,
    riskScore: 0
  });

  console.log(`[Aegis] Redirecting "${originalFilename}" -> ${quarantineRelative}`);

  // "uniquify" so two concurrent downloads can never collide on one UUID.
  suggest({ filename: quarantineRelative, conflictAction: "uniquify" });
});

/**
 * Once Chrome has resolved the absolute path, start the host watching it.
 */
chrome.downloads.onChanged.addListener((delta) => {
  const session = activeSessions.get(delta.id);
  if (!session) return;

  // The absolute path becomes known shortly after onDeterminingFilename.
  if (delta.filename && delta.filename.current && session.state === "pending") {
    session.absolutePath = delta.filename.current;
    session.state = "scanning";
    beginWatch(delta.id, session);
  }

  if (delta.state && delta.state.current === "interrupted" && session.state === "scanning") {
    // Chrome gave up (network error, or our own cancel). Tear the session down.
    console.log(`[Aegis] Download ${delta.id} interrupted`);
    finishSession(delta.id);
  }
});

/**
 * Open the native port and tell the host which file to watch.
 *
 * FAIL CLOSED: if the host cannot be reached, the download is cancelled. The
 * old code called resume() here, which released files uninspected precisely
 * when the scanner was unavailable.
 */
function beginWatch(downloadId, session) {
  let port;
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  } catch (err) {
    return failClosed(downloadId, session, `native host unreachable: ${err.message}`);
  }
  session.port = port;

  port.onMessage.addListener((msg) => {
    switch (msg.type) {
      case "SCAN_PROGRESS":
        session.bytesScanned = msg.bytes_scanned;
        session.riskScore = msg.risk_score;
        break;

      case "EARLY_BLOCK":
        // The whole point of the design: kill it before it finishes arriving.
        console.warn(`[Aegis] EARLY BLOCK (risk ${msg.risk_score}): ${msg.reason}`);
        session.state = "blocked";
        session.earlyKill = true;
        chrome.downloads.cancel(downloadId, () => void chrome.runtime.lastError);
        setBadge("!", "#c0392b");
        notify({
          blocked: true,
          earlyKill: true,
          filename: session.originalFilename,
          verdictText: msg.reason
        });
        break;

      case "VERDICT":
        handleVerdict(downloadId, session, msg);
        break;

      default:
        console.debug("[Aegis] unhandled host message:", msg);
    }
  });

  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    if (session.state === "scanning") {
      // The host died mid-scan. We have no verdict, so we cannot release.
      failClosed(
        downloadId,
        session,
        `host disconnected mid-scan${err ? `: ${err.message}` : ""}`
      );
    }
  });

  port.postMessage({
    type: "WATCH_BEGIN",
    session_id: session.sessionId,
    download_id: downloadId,
    quarantine_path: session.absolutePath,
    original_filename: session.originalFilename,
    url: session.url
  });
}

function handleVerdict(downloadId, session, msg) {
  const released = msg.status === "COMPLETE";
  session.state = released ? "released" : "blocked";

  if (!released) {
    // Cancel is idempotent enough here; if the download already finished,
    // the host has deleted the quarantined file, so nothing is delivered.
    chrome.downloads.cancel(downloadId, () => void chrome.runtime.lastError);
  }

  console.log(`[Aegis] ${msg.status}: ${msg.verdict}`);

  saveVerdict({
    filename: session.originalFilename,
    url: session.url,
    status: msg.status,
    verdict: msg.verdict,
    reason: humanReason(msg.verdict),
    releasedPath: msg.released_path || null
  });

  // EARLY_BLOCK already notified; don't fire twice for the same download.
  if (!session.earlyKill) {
    notify({
      blocked: !released,
      filename: session.originalFilename,
      verdictText: msg.verdict
    });
  }

  setBadge(released ? "" : "!", released ? undefined : "#c0392b");
  finishSession(downloadId);
}

/**
 * Cancel the download and record why. Used for every failure mode.
 */
function failClosed(downloadId, session, reason) {
  console.error(`[Aegis] FAIL CLOSED — cancelling download: ${reason}`);
  session.state = "blocked";
  chrome.downloads.cancel(downloadId, () => void chrome.runtime.lastError);

  const verdict =
    `Download cancelled because Aegis could not verify it (${reason}). ` +
    `The file was not saved.`;

  saveVerdict({
    filename: session.originalFilename,
    url: session.url,
    status: "BLOCKED",
    verdict,
    reason: humanReason(verdict)
  });

  notify({ blocked: true, filename: session.originalFilename, verdictText: verdict });
  setBadge("!", "#c0392b");
  finishSession(downloadId);
}

function finishSession(downloadId) {
  const session = activeSessions.get(downloadId);
  if (session?.port) {
    try { session.port.disconnect(); } catch { /* already gone */ }
  }
  activeSessions.delete(downloadId);
}
