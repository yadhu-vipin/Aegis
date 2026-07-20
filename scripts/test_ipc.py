#!/usr/bin/env python3
"""
Phase 1 Verification Script — Test 1: Native Messaging IPC
Sends a fake START_DOWNLOAD + one CHUNK message to the aegis-host binary
over stdin (using the Chrome native messaging framing) and confirms we get
a well-formed JSON reply on stdout.

Usage: python3 test_ipc.py
"""

import json
import struct
import subprocess
import base64
import sys
import os

# Path to the compiled binary
BINARY = os.path.join(os.path.dirname(__file__), "..", "aegis-host", "target", "debug", "aegis-host")
AEGIS_TOML = os.path.join(os.path.dirname(__file__), "..", "aegis.toml")


def encode_message(data: dict) -> bytes:
    """Encode a dict as a Chrome native-messaging frame."""
    json_bytes = json.dumps(data).encode("utf-8")
    length = struct.pack("<I", len(json_bytes))
    return length + json_bytes


def decode_message(stream) -> dict:
    """Read one Chrome native-messaging frame from a byte stream."""
    length_bytes = stream.read(4)
    if len(length_bytes) < 4:
        raise EOFError("Stream closed before length header")
    length = struct.unpack("<I", length_bytes)[0]
    if length > 1_048_576:
        raise ValueError(f"Message length {length} exceeds 1MB — malformed")
    json_bytes = stream.read(length)
    return json.loads(json_bytes.decode("utf-8"))


def run_test():
    print("=" * 60)
    print("Phase 1 IPC Test: Sending fake download session to aegis-host")
    print("=" * 60)

    if not os.path.exists(BINARY):
        print(f"ERROR: Binary not found at {BINARY}")
        print("Run: cd aegis-host && cargo build")
        sys.exit(1)

    # Build a synthetic 1KB "PNG" file (real PNG magic bytes + padding)
    png_magic = b"\x89PNG\r\n\x1a\n" + b"\x00" * 1016  # 1024 bytes total
    chunk_b64 = base64.b64encode(png_magic).decode("ascii")

    session_id = "test-session-001"

    # Messages to send
    messages = [
        {
            "type": "START_DOWNLOAD",
            "session_id": session_id,
            "filename": "test_image.png",
            "content_length": len(png_magic),
        },
        {
            "type": "CHUNK",
            "session_id": session_id,
            "seq": 0,
            "is_last": True,
            "data": chunk_b64,
        },
    ]

    input_bytes = b"".join(encode_message(m) for m in messages)

    # Copy aegis.toml to the binary's directory for config loading
    import shutil
    target_dir = os.path.join(os.path.dirname(__file__), "..", "aegis-host", "target", "debug")
    shutil.copy2(AEGIS_TOML, os.path.join(target_dir, "aegis.toml"))

    proc = subprocess.run(
        [BINARY],
        input=input_bytes,
        capture_output=True,
        timeout=30,
    )

    print(f"\nExit code: {proc.returncode}")
    print(f"Stderr (tracing): {proc.stderr.decode('utf-8', errors='replace')[:2000]}")

    # Parse responses from stdout
    import io
    stdout_stream = io.BytesIO(proc.stdout)
    responses = []
    while stdout_stream.tell() < len(proc.stdout):
        try:
            msg = decode_message(stdout_stream)
            responses.append(msg)
        except EOFError:
            break

    print(f"\nReceived {len(responses)} response(s):")
    for i, resp in enumerate(responses):
        print(f"  [{i}] {json.dumps(resp, indent=2)}")

    # Assertions
    assert len(responses) >= 1, "Expected at least one response (CHUNK_ACK or VERDICT)"

    # Find the VERDICT response
    verdicts = [r for r in responses if r.get("type") == "VERDICT"]
    chunk_acks = [r for r in responses if r.get("type") == "CHUNK_ACK"]

    assert len(chunk_acks) >= 1, f"Expected at least one CHUNK_ACK, got: {responses}"
    assert len(verdicts) >= 1, f"Expected at least one VERDICT, got: {responses}"

    verdict = verdicts[0]
    assert "status" in verdict, f"VERDICT missing 'status': {verdict}"
    assert "verdict" in verdict, f"VERDICT missing 'verdict': {verdict}"
    assert verdict.get("session_id") == session_id, \
        f"VERDICT session_id mismatch: {verdict}"

    print(f"\n✅ PASS: Received valid VERDICT: status={verdict['status']}")
    print(f"   Verdict message: {verdict['verdict'][:120]}")


if __name__ == "__main__":
    run_test()
