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
  ERROR: { cls: "warn", icon: "⚠", label: "Error" }
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

async function refresh() {
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
