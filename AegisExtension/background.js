// background.js

// This name must match the "name" in your future Native Host Manifest
const NATIVE_HOST_NAME = "com.aegis.sandbox";

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  // 1. Log the capture
  console.log(`[Aegis] Intercepted download: ${downloadItem.url}`);

  // 2. Kill the browser's native download immediately
  // This prevents the file from touching the 'Downloads' folder.
  chrome.downloads.cancel(downloadItem.id, () => {
    console.log("[Aegis] Native download cancelled. Redirecting to sandbox...");
  });

  // 3. Attempt to connect to the Rust Module (Module 2)
  // Note: This will fail until you build and register the Rust app,
  // but it's the correct logic for the flow.
  try {
    const port = chrome.runtime.connectNative(NATIVE_HOST_NAME);

    port.onDisconnect.addListener(() => {
      console.error(
        "[Aegis] Disconnected from Sandbox Host. Is it registered?",
      );
    });

    // 4. Stream the data manually
    const response = await fetch(downloadItem.url);
    const reader = response.body.getReader();

    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        port.postMessage({ type: "EOF" });
        break;
      }

      // Send the binary chunk as a Base64 string
      const base64Chunk = btoa(String.fromCharCode(...value));
      port.postMessage({
        type: "DATA",
        filename: downloadItem.filename, // We add this!
        payload: base64Chunk,
      });
    }
  } catch (err) {
    console.error("[Aegis] Error connecting to Native Host:", err);
  }
});
