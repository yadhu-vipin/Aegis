#!/usr/bin/env python3
"""
Simple local HTTP server to serve test files for Aegis download testing.

Usage: python3 serve_test_downloads.py
Serves http://localhost:8000/test_trojan.jpg
"""

import http.server
import socketserver
import os

PORT = 8000
DIRECTORY = os.path.join(os.path.dirname(__file__), "..", "test_files")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"🚀 Serving test downloads at http://localhost:{PORT}/")
        print(f"   Test file 1 (Mismatched Trojan .jpg): http://localhost:{PORT}/test_trojan.jpg")
        print("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped server.")
