/**
 * Aegis Service Worker — background.js
 *
 * Responsibilities:
 * 1. Layer 1: Forward CHECK_URL hover messages to local ML service (http://127.0.0.1:8787/score)
 *    with a 500ms timeout. Fail open ("unscored") if unreachable.
 * 2. Layer 2: Intercept downloads via chrome.downloads, stream file in 256KB chunks
 *    to Rust Native Host (com.aegis.sandbox), await VERDICT, release or cancel download.
 */

const NATIVE_HOST_NAME = "com.aegis.sandbox";
const ML_SERVICE_URL = "http://127.0.0.1:8787/score";
const CHUNK_SIZE = 262144; // 256 KB

// Active download sessions tracking
const activeSessions = new Map();

// Recent verdicts storage for popup
async function saveVerdictToStorage(verdictData) {
  try {
    const { recentVerdicts = [] } = await chrome.storage.local.get("recentVerdicts");
    recentVerdicts.unshift({
      ...verdictData,
      timestamp: new Date().toISOString()
    });
    // Keep last 20
    if (recentVerdicts.length > 20) recentVerdicts.length = 20;
    await chrome.storage.local.set({ recentVerdicts });
  } catch (err) {
    console.error("[Aegis] Failed to save verdict to storage:", err);
  }
}

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CHECK_URL") {
    handleCheckUrl(message.url)
      .then(sendResponse)
      .catch((err) => {
        console.warn("[Aegis] URL check error:", err);
        sendResponse({ score: 0.5, label: "unscored", reason: err.message });
      });
    return true; // Async response
  }
});

/**
 * Layer 1: Check URL against local ML service.
 */
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

    if (!response.ok) {
      return { score: 0.5, label: "unscored", reason: `HTTP ${response.status}` };
    }

    const data = await response.json();
    return {
      score: typeof data.score === "number" ? Math.min(Math.max(data.score, 0), 1) : 0.5,
      label: data.label || "unscored"
    };
  } catch (err) {
    clearTimeout(timeoutId);
    return { score: 0.5, label: "unscored", reason: "ML service unreachable" };
  }
}

/**
 * Layer 2: Intercept browser downloads.
 */
chrome.downloads.onCreated.addListener((downloadItem) => {
  if (activeSessions.has(downloadItem.id)) return;

  console.log(`[Aegis] Download intercepted: ID=${downloadItem.id}, file=${downloadItem.filename}, url=${downloadItem.url}`);

  // Pause download in Chrome while Aegis scans
  chrome.downloads.pause(downloadItem.id);

  const sessionId = `session-${downloadItem.id}-${Date.now()}`;
  activeSessions.set(downloadItem.id, { sessionId, state: "scanning" });

  processDownloadTriage(downloadItem, sessionId);
});

/**
 * Stream file bytes to Aegis Rust host and handle verdict.
 */
async function processDownloadTriage(downloadItem, sessionId) {
  let port;
  try {
    port = chrome.runtime.connectNative(NATIVE_HOST_NAME);
  } catch (err) {
    console.error("[Aegis] Native host connection failed:", err);
    // Fail cautious / warn user, then resume download if host missing
    chrome.downloads.resume(downloadItem.id);
    saveVerdictToStorage({
      filename: downloadItem.filename,
      url: downloadItem.url,
      status: "WARNING",
      verdict: "Aegis native host unreachable. Download resumed uninspected."
    });
    activeSessions.delete(downloadItem.id);
    return;
  }

  let resolveAck = null;
  let verdictReceived = null;

  port.onMessage.addListener((msg) => {
    console.log("[Aegis Host Msg]:", msg);
    if (msg.type === "CHUNK_ACK") {
      if (resolveAck) resolveAck();
    } else if (msg.type === "VERDICT") {
      verdictReceived = msg;
      handleVerdict(downloadItem, msg);
      port.disconnect();
    }
  });

  port.onDisconnect.addListener(() => {
    if (chrome.runtime.lastError) {
      console.warn("[Aegis Port Disconnect Error]:", chrome.runtime.lastError.message);
    }
    if (!verdictReceived) {
      chrome.downloads.resume(downloadItem.id);
    }
    activeSessions.delete(downloadItem.id);
  });

  // 1. Send START_DOWNLOAD
  port.postMessage({
    type: "START_DOWNLOAD",
    session_id: sessionId,
    filename: downloadItem.filename || "download.bin",
    content_length: downloadItem.fileSize > 0 ? downloadItem.fileSize : null
  });

  // 2. Fetch download stream and forward in 256KB chunks
  try {
    const response = await fetch(downloadItem.url);
    if (!response.body) throw new Error("No response body available");

    const reader = response.body.getReader();
    let seq = 0;
    let buffer = new Uint8Array(0);

    while (true) {
      const { done, value } = await reader.read();

      if (value) {
        // Concatenate new bytes into buffer
        const newBuf = new Uint8Array(buffer.length + value.length);
        newBuf.set(buffer);
        newBuf.set(value, buffer.length);
        buffer = newBuf;
      }

      // Send 256KB chunks while buffer is large enough or stream is done
      while (buffer.length >= CHUNK_SIZE || (done && buffer.length > 0)) {
        const chunkLength = Math.min(buffer.length, CHUNK_SIZE);
        const chunkData = buffer.slice(0, chunkLength);
        buffer = buffer.slice(chunkLength);

        const isLast = done && buffer.length === 0;

        // Base64 encode chunk
        const base64Data = bytesToBase64(chunkData);

        // Send CHUNK message & await CHUNK_ACK backpressure
        const ackPromise = new Promise((res) => { resolveAck = res; });
        port.postMessage({
          type: "CHUNK",
          session_id: sessionId,
          seq: seq++,
          is_last: isLast,
          data: base64Data
        });

        await ackPromise;

        if (isLast) break;
      }

      if (done) break;
    }
  } catch (err) {
    console.error("[Aegis Stream Error]:", err);
    // If stream fetching fails, let Chrome finish normally or report error
    chrome.downloads.resume(downloadItem.id);
  }
}

/**
 * Handle verdict response from Rust host.
 */
function handleVerdict(downloadItem, msg) {
  const status = msg.status;
  const verdictMsg = msg.verdict;

  console.log(`[Aegis Verdict] Download ID=${downloadItem.id}: status=${status}, verdict=${verdictMsg}`);

  if (status === "BLOCKED" || status === "REJECTED_MALFORMED") {
    // Cancel download
    chrome.downloads.cancel(downloadItem.id);
  } else {
    // Release / Resume clean download
    chrome.downloads.resume(downloadItem.id);
  }

  saveVerdictToStorage({
    filename: downloadItem.filename,
    url: downloadItem.url,
    status: status,
    verdict: verdictMsg
  });
}

function bytesToBase64(bytes) {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
