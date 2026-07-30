/**
 * Aegis popup.
 *
 * Shows what Aegis actually did and why. A blocked download that disappears
 * without explanation is indistinguishable from a broken browser, so every
 * entry carries a plain-language reason alongside the technical detail.
 */

/** Presentation for each verdict status. */
const STATUS_STYLE = {
  COMPLETE: { cls: "ok", icon: "✓", label: "Saved" },
  BLOCKED: { cls: "blocked", icon: "⛔", label: "Blocked" },
  REJECTED_MALFORMED: { cls: "blocked", icon: "⛔", label: "Rejected" },
  REJECTED_TOO_LARGE: { cls: "blocked", icon: "⛔", label: "Too large" },
  REJECTED_INSUFFICIENT_SPACE: { cls: "warn", icon: "⚠", label: "No disk space" },
  // Aegis failed — NOT a judgement about the file. Amber, never red, and
  // never worded as though the download was found to be dangerous.
  AEGIS_ERROR: { cls: "warn", icon: "⚙", label: "Aegis error" },
  ERROR: { cls: "warn", icon: "⚙", label: "Aegis error" }
};

function styleFor(status) {
  return STATUS_STYLE[status] || { cls: "warn", icon: "•", label: status || "Unknown" };
}

function timeAgo(iso) {
  if (!iso) return "";
  const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

/**
 * Build one verdict row.
 *
 * Everything is created via textContent, never innerHTML — filenames and
 * verdict strings originate from downloaded content and the native host, so
 * treating them as markup would be an injection vector in our own UI.
 */
function renderVerdict(item) {
  const style = styleFor(item.status);

  const row = document.createElement("div");
  row.className = `verdict-item ${style.cls}`;

  const head = document.createElement("div");
  head.className = "verdict-head";

  const icon = document.createElement("span");
  icon.className = "verdict-icon";
  icon.textContent = style.icon;

  const name = document.createElement("span");
  name.className = "verdict-filename";
  name.textContent = item.filename || "Unknown file";
  name.title = item.filename || "";

  const when = document.createElement("span");
  when.className = "verdict-time";
  when.textContent = timeAgo(item.timestamp);

  head.append(icon, name, when);

  const reason = document.createElement("div");
  reason.className = "verdict-reason";
  reason.textContent = item.reason || item.verdict || style.label;

  row.append(head, reason);

  // Make it unmistakable that Aegis broke rather than the file being bad.
  if (item.infrastructure) {
    const note = document.createElement("div");
    note.className = "verdict-infra-note";
    note.textContent = "Not a verdict about this file — Aegis itself failed to run.";
    row.appendChild(note);
  }

  // Full technical detail, collapsed. Useful when explaining a decision;
  // noise the rest of the time.
  if (item.verdict && item.verdict !== item.reason) {
    const details = document.createElement("details");
    details.className = "verdict-details";

    const summary = document.createElement("summary");
    summary.textContent = "Technical detail";

    const pre = document.createElement("div");
    pre.className = "verdict-technical";
    pre.textContent = item.verdict;

    details.append(summary, pre);
    row.appendChild(details);
  }

  if (item.releasedPath) {
    const path = document.createElement("div");
    path.className = "verdict-path";
    path.textContent = `Saved to: ${item.releasedPath}`;
    row.appendChild(path);
  }

  return row;
}

function renderActiveScan(scan) {
  const row = document.createElement("div");
  row.className = "verdict-item scanning";

  const head = document.createElement("div");
  head.className = "verdict-head";

  const icon = document.createElement("span");
  icon.className = "verdict-icon spin";
  icon.textContent = "◌";

  const name = document.createElement("span");
  name.className = "verdict-filename";
  name.textContent = scan.filename || "Scanning…";

  head.append(icon, name);

  const reason = document.createElement("div");
  reason.className = "verdict-reason";
  const kb = Math.round((scan.bytesScanned || 0) / 1024);
  reason.textContent = `Scanning while it downloads — ${kb} KB checked`;

  row.append(head, reason);
  return row;
}

/**
 * Translate the browser's native-messaging error into something actionable.
 *
 * These strings have completely different fixes, and "it doesn't work" hides
 * which one you're looking at.
 */
function healthAdvice(error = "") {
  const e = error.toLowerCase();
  if (e.includes("not found")) {
    return "The scanner isn't registered with this browser. Run scripts\\install_native_host.ps1, then fully restart the browser via edge://restart.";
  }
  if (e.includes("forbidden")) {
    return "This extension's ID isn't in the scanner's allowed list. Re-run install_native_host.ps1 with the ID shown on this extension's card.";
  }
  if (e.includes("failed to start")) {
    return "The scanner is registered but won't launch. Check that aegis-host.exe exists and isn't blocked by antivirus or an app-control policy.";
  }
  if (e.includes("exited") || e.includes("without replying")) {
    return "The scanner started but quit immediately. Check aegis-host.log next to the binary.";
  }
  return "Run scripts\\verify_native_host.ps1 to diagnose.";
}

async function refreshHealth() {
  const banner = document.getElementById("health-banner");
  const title = document.getElementById("health-title");
  const detail = document.getElementById("health-detail");
  if (!banner) return;

  let h = null;
  try {
    h = await chrome.runtime.sendMessage({ type: "GET_HEALTH" });
  } catch { /* worker asleep */ }

  if (!h) {
    banner.hidden = true;
    return;
  }

  if (h.ok) {
    banner.hidden = false;
    banner.className = "health-banner ok";
    title.textContent = "Scanner connected";
    detail.textContent = `aegis-host v${h.version}`;
  } else {
    banner.hidden = false;
    banner.className = "health-banner bad";
    title.textContent = "Scanner unreachable — downloads will be blocked";
    // Both the raw error and what to do about it: the raw string is what you
    // search for, the advice is what you act on.
    detail.textContent = `${h.error}\n\n${healthAdvice(h.error)}`;
  }
}

async function refresh() {
  await refreshHealth();

  const listEl = document.getElementById("verdict-list");
  listEl.textContent = "";

  // In-flight scans first, so the user sees Aegis working in real time.
  let active = [];
  try {
    active = (await chrome.runtime.sendMessage({ type: "GET_ACTIVE_SESSIONS" })) || [];
  } catch { /* service worker asleep — no active scans */ }

  active.forEach((s) => listEl.appendChild(renderActiveScan(s)));

  const { recentVerdicts = [] } = await chrome.storage.local.get("recentVerdicts");

  if (!active.length && !recentVerdicts.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No downloads scanned yet.";
    listEl.appendChild(empty);
    return;
  }

  recentVerdicts.forEach((item) => listEl.appendChild(renderVerdict(item)));

  const blocked = recentVerdicts.filter((v) => styleFor(v.status).cls === "blocked").length;
  const countEl = document.getElementById("blocked-count");
  if (countEl) {
    countEl.textContent = blocked
      ? `${blocked} download${blocked === 1 ? "" : "s"} blocked`
      : "Nothing blocked yet";
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const toggleL1 = document.getElementById("toggle-layer1");
  const toggleL2 = document.getElementById("toggle-layer2");

  const settings = await chrome.storage.local.get(["layer1Enabled", "layer2Enabled"]);
  toggleL1.checked = settings.layer1Enabled !== false;
  toggleL2.checked = settings.layer2Enabled !== false;

  toggleL1.addEventListener("change", () =>
    chrome.storage.local.set({ layer1Enabled: toggleL1.checked })
  );
  toggleL2.addEventListener("change", () =>
    chrome.storage.local.set({ layer2Enabled: toggleL2.checked })
  );

  const retryBtn = document.getElementById("health-retry");
  if (retryBtn) {
    retryBtn.addEventListener("click", async () => {
      retryBtn.disabled = true;
      retryBtn.textContent = "Checking…";
      try {
        await chrome.runtime.sendMessage({ type: "RECHECK_HEALTH" });
      } catch { /* worker restarting */ }
      await refreshHealth();
      retryBtn.disabled = false;
      retryBtn.textContent = "Re-check";
    });
  }

  const clearBtn = document.getElementById("clear-history");
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      await chrome.storage.local.set({ recentVerdicts: [] });
      await chrome.action.setBadgeText({ text: "" });
      refresh();
    });
  }

  await refresh();
  // Keep the in-flight view live while the popup is open.
  setInterval(refresh, 1000);
});
