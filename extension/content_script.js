/**
 * Aegis Content Script — content_script.js
 *
 * Layer 1: Hover Link Check
 * - Listens for mouseover on all <a> links (debounced 150ms)
 * - Checks background.js for URL risk score
 * - Injects inline floating risk badge near cursor
 * - Session cache with 10-minute TTL per URL
 */

const HOVER_DEBOUNCE_MS = 150;
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes

// URL cache: Map<url, {label, score, timestamp}>
const urlCache = new Map();

let hoverTimer = null;
let currentBadge = null;

document.addEventListener("mouseover", (event) => {
  const link = event.target.closest("a");
  if (!link || !link.href) {
    removeBadge();
    return;
  }

  // Ignore javascript: or anchor-only links
  if (link.href.startsWith("javascript:") || link.href.startsWith("mailto:") || link.href.startsWith("#")) {
    return;
  }

  const url = link.href;

  if (hoverTimer) clearTimeout(hoverTimer);

  hoverTimer = setTimeout(() => {
    checkAndDisplayBadge(url, event.clientX, event.clientY);
  }, HOVER_DEBOUNCE_MS);
});

document.addEventListener("mouseout", (event) => {
  const link = event.target.closest("a");
  if (link) {
    if (hoverTimer) clearTimeout(hoverTimer);
    removeBadge();
  }
});

async function checkAndDisplayBadge(url, mouseX, mouseY) {
  const cached = getFromCache(url);
  let result = cached;

  if (!result) {
    try {
      result = await chrome.runtime.sendMessage({ type: "CHECK_URL", url });
      if (result) {
        setInCache(url, result);
      }
    } catch (err) {
      console.warn("[Aegis] Failed to send CHECK_URL:", err);
      result = { score: 0.5, label: "unscored" };
    }
  }

  if (!result) return;

  renderBadge(result, mouseX, mouseY);
}

function getFromCache(url) {
  const entry = urlCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    urlCache.delete(url);
    return null;
  }
  return entry.data;
}

function setInCache(url, data) {
  urlCache.set(url, { data, timestamp: Date.now() });
}

function renderBadge(result, mouseX, mouseY) {
  removeBadge();

  const badge = document.createElement("div");
  badge.id = "aegis-link-badge";

  let bg = "#6c757d"; // default gray
  let text = "Unscored";
  let icon = "ℹ️";

  if (result.label === "safe" || (result.score < 0.3 && result.label !== "unscored")) {
    bg = "#198754"; // green
    text = "Verified Safe";
    icon = "🛡️";
  } else if (result.label === "suspicious" || (result.score >= 0.3 && result.score < 0.7)) {
    bg = "#ffc107"; // yellow
    text = "Use Caution";
    icon = "⚠️";
  } else if (result.label === "phishing" || result.score >= 0.7) {
    bg = "#dc3545"; // red
    text = "Likely Phishing";
    icon = "🚨";
  }

  const scoreText = typeof result.score === "number" ? ` (${(result.score * 100).toFixed(0)}%)` : "";

  badge.textContent = `${icon} Aegis: ${text}${scoreText}`;
  badge.title = `Aegis ML Risk Score: ${result.score !== undefined ? result.score.toFixed(3) : "N/A"}`;

  // Apply inline styles (no inline event handlers)
  Object.assign(badge.style, {
    position: "fixed",
    left: `${mouseX + 12}px`,
    top: `${mouseY + 12}px`,
    backgroundColor: bg,
    color: bg === "#ffc107" ? "#000" : "#fff",
    padding: "4px 8px",
    borderRadius: "4px",
    fontSize: "12px",
    fontWeight: "bold",
    fontFamily: "system-ui, -apple-system, sans-serif",
    boxShadow: "0 2px 6px rgba(0,0,0,0.3)",
    zIndex: "2147483647",
    pointerEvents: "none",
    transition: "opacity 0.15s ease"
  });

  document.body.appendChild(badge);
  currentBadge = badge;
}

function removeBadge() {
  if (currentBadge) {
    currentBadge.remove();
    currentBadge = null;
  }
}
