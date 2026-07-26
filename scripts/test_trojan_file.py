#!/usr/bin/env python3
"""
Direct terminal test for test_trojan.jpg against aegis-host.
Simulates Chrome passing the file to the native messaging host.
"""

import json
import struct
import subprocess
import base64
import os
import sys

BINARY = os.path.join(os.path.dirname(__file__), "..", "aegis-host", "target", "debug", "aegis-host")
DEFAULT_FILE = os.path.join(os.path.dirname(__file__), "..", "test_files", "test_trojan.jpg")
AEGIS_TOML = os.path.join(os.path.dirname(__file__), "..", "aegis.toml")

TEST_FILE = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FILE

def encode(data):
    b = json.dumps(data).encode('utf-8')
    return struct.pack('<I', len(b)) + b

def decode(stream):
    len_bytes = stream.read(4)
    if not len_bytes: return None
    length = struct.unpack('<I', len_bytes)[0]
    return json.loads(stream.read(length).decode('utf-8'))

def run():
    print("=" * 60)
    print("Testing test_trojan.jpg against Aegis Rust Host")
    print("=" * 60)

    # Ensure aegis.toml is copied
    import shutil
    shutil.copy2(AEGIS_TOML, os.path.join(os.path.dirname(BINARY), "aegis.toml"))

    with open(TEST_FILE, "rb") as f:
        file_bytes = f.read()

    chunk_b64 = base64.b64encode(file_bytes).decode('ascii')
    session_id = "test-trojan-session"

    filename = os.path.basename(TEST_FILE)
    messages = [
        {"type": "START_DOWNLOAD", "session_id": session_id, "filename": filename, "content_length": len(file_bytes)},
        {"type": "CHUNK", "session_id": session_id, "seq": 0, "is_last": True, "data": chunk_b64}
    ]

    input_bytes = b"".join(encode(m) for m in messages)

    proc = subprocess.run([BINARY], input=input_bytes, capture_output=True)

    print("\n--- Stderr Log (Aegis Host Output) ---")
    print(proc.stderr.decode('utf-8', errors='replace'))

    print("--- Native Host JSON Responses ---")
    import io
    stream = io.BytesIO(proc.stdout)
    while stream.tell() < len(proc.stdout):
        msg = decode(stream)
        if msg:
            print(json.dumps(msg, indent=2))

if __name__ == "__main__":
    run()
