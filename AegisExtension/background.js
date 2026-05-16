const NATIVE_HOST_NAME = "com.aegis.scanner";

chrome.downloads.onCreated.addListener((downloadItem) => {
    // 1. Kill the browser download immediately
    chrome.downloads.cancel(downloadItem.id);

    // 2. Open the pipe to Rust
    const port = chrome.runtime.connectNative(NATIVE_HOST_NAME);

    // 3. Send the "Mission Briefing"
    port.postMessage({
        type: "START_DOWNLOAD",
        url: downloadItem.url,
        filename: downloadItem.filename
    });

    // 4. Listen for the result
    port.onMessage.addListener((msg) => {
        if (msg.status === "COMPLETE") {
            console.log(`[Aegis] Scan finished. Verdict: ${msg.verdict}`);
            port.disconnect();
        }
    });
});