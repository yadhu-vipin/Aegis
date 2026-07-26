document.addEventListener("DOMContentLoaded", async () => {
  const toggleL1 = document.getElementById("toggle-layer1");
  const toggleL2 = document.getElementById("toggle-layer2");
  const listEl = document.getElementById("verdict-list");

  // Load toggle states
  const settings = await chrome.storage.local.get(["layer1Enabled", "layer2Enabled"]);
  toggleL1.checked = settings.layer1Enabled !== false;
  toggleL2.checked = settings.layer2Enabled !== false;

  toggleL1.addEventListener("change", () => {
    chrome.storage.local.set({ layer1Enabled: toggleL1.checked });
  });

  toggleL2.addEventListener("change", () => {
    chrome.storage.local.set({ layer2Enabled: toggleL2.checked });
  });

  // Load recent verdicts
  const { recentVerdicts = [] } = await chrome.storage.local.get("recentVerdicts");

  if (recentVerdicts.length === 0) {
    listEl.innerHTML = '<div class="empty-state">No recent download activity.</div>';
    return;
  }

  listEl.innerHTML = "";
  recentVerdicts.forEach((item) => {
    const div = document.createElement("div");
    div.className = `verdict-item ${item.status || ""}`;

    const name = document.createElement("div");
    name.className = "verdict-filename";
    name.textContent = item.filename || "Unknown file";

    const detail = document.createElement("div");
    detail.className = "verdict-detail";
    detail.textContent = item.verdict || item.status || "Completed";

    div.appendChild(name);
    div.appendChild(detail);
    listEl.appendChild(div);
  });
});
