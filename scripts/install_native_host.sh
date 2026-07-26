#!/usr/bin/env bash
# Aegis — Linux Native Messaging Host Installer (Dev Mode)
# Registers com.aegis.sandbox Native Host for Chrome & Chromium on Linux.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

HOST_NAME="com.aegis.sandbox"
HOST_BINARY="$REPO_DIR/aegis-host/target/release/aegis-host"

if [ ! -f "$HOST_BINARY" ]; then
    echo "Release binary not found at $HOST_BINARY. Building..."
    (cd "$REPO_DIR/aegis-host" && cargo build --release)
fi

# Ensure aegis.toml is copied next to the release binary
cp "$REPO_DIR/aegis.toml" "$REPO_DIR/aegis-host/target/release/aegis.toml"

TARGET_DIR_CHROME="$HOME/.config/google-chrome/NativeMessagingHosts"
TARGET_DIR_CHROMIUM="$HOME/.config/chromium/NativeMessagingHosts"

mkdir -p "$TARGET_DIR_CHROME"
mkdir -p "$TARGET_DIR_CHROMIUM"

MANIFEST_PATH_CHROME="$TARGET_DIR_CHROME/$HOST_NAME.json"
MANIFEST_PATH_CHROMIUM="$TARGET_DIR_CHROMIUM/$HOST_NAME.json"

echo "Creating native messaging host manifest..."

cat <<EOF > "$MANIFEST_PATH_CHROME"
{
  "name": "$HOST_NAME",
  "description": "Aegis Host Sandbox Native Messaging Host",
  "path": "$HOST_BINARY",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://aegisdownloadguardextensionid/"
  ]
}
EOF

cp "$MANIFEST_PATH_CHROME" "$MANIFEST_PATH_CHROMIUM"

echo "Native host manifest installed to:"
echo "  - $MANIFEST_PATH_CHROME"
echo "  - $MANIFEST_PATH_CHROMIUM"
echo "Binary path: $HOST_BINARY"
echo "✅ Installation complete."
