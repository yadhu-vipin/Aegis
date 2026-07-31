#!/usr/bin/env python3
"""
Local HTTP server for end-to-end Aegis testing.

Aegis can only be tested properly through a real browser: it hooks
`downloads.onDeterminingFilename`, so a download has to actually originate in
Chromium for any of the pipeline to run. This serves `test_files/` so you can
click a link and watch the real thing happen.

    python scripts/serve_test_downloads.py

Then open the printed URL in the browser where the extension is loaded, click a
file, and check `aegis-host/target/debug/aegis-host.log`.

Binds to 127.0.0.1 only. A directory of deliberately malicious-looking test
files should not be reachable from the rest of the network.
"""

import http.server
import os
import socketserver

PORT = 8000
HOST = "127.0.0.1"
DIRECTORY = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "test_files")
)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def log_message(self, fmt, *args):
        # One line per request, so the browser's side of the exchange is
        # visible next to the host log without the usual noise.
        print(f"  <- {fmt % args}")


def main():
    if not os.path.isdir(DIRECTORY):
        raise SystemExit(f"test_files directory not found at {DIRECTORY}")

    files = sorted(
        f for f in os.listdir(DIRECTORY)
        if os.path.isfile(os.path.join(DIRECTORY, f))
    )

    with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
        print(f"Serving {DIRECTORY}")
        print(f"  http://{HOST}:{PORT}/\n")
        if files:
            print("Available:")
            for f in files:
                print(f"  http://{HOST}:{PORT}/{f}")
        else:
            print("(no files in test_files/)")
        print("\nCtrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
