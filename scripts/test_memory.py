#!/usr/bin/env python3
"""
Phase 1 Verification Script — Test 2: Memory Flatness (Chunking Pipeline)
Streams a synthetic large file (configurable size) through the aegis-host
binary in 256KB chunks and confirms host RSS stays flat (bounded by ring buffer,
not file size).

Usage: python3 test_memory.py [--size-mb 500]
"""

import json
import struct
import subprocess
import base64
import sys
import os
import time
import threading
import argparse

BINARY = os.path.join(os.path.dirname(__file__), "..", "aegis-host", "target", "debug", "aegis-host")
AEGIS_TOML = os.path.join(os.path.dirname(__file__), "..", "aegis.toml")

CHUNK_SIZE = 262_144  # 256 KB


def encode_message(data: dict) -> bytes:
    json_bytes = json.dumps(data).encode("utf-8")
    return struct.pack("<I", len(json_bytes)) + json_bytes


def decode_message_from(data: bytes, offset: int):
    if offset + 4 > len(data):
        return None, offset
    length = struct.unpack_from("<I", data, offset)[0]
    if offset + 4 + length > len(data):
        return None, offset
    msg = json.loads(data[offset + 4: offset + 4 + length])
    return msg, offset + 4 + length


def get_rss_kb(pid: int) -> int:
    """Read RSS from /proc/<pid>/status (Linux only)."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (FileNotFoundError, ProcessLookupError):
        pass
    return 0


def run_test(size_mb: int):
    print("=" * 60)
    print(f"Phase 1 Memory Test: Streaming {size_mb}MB through aegis-host")
    print("=" * 60)

    if not os.path.exists(BINARY):
        print(f"ERROR: Binary not found at {BINARY}")
        sys.exit(1)

    # Copy aegis.toml to binary dir
    import shutil
    target_dir = os.path.dirname(BINARY)
    shutil.copy2(AEGIS_TOML, os.path.join(target_dir, "aegis.toml"))

    total_bytes = size_mb * 1024 * 1024
    num_chunks = (total_bytes + CHUNK_SIZE - 1) // CHUNK_SIZE

    print(f"Total size: {total_bytes:,} bytes, {num_chunks} chunks of {CHUNK_SIZE:,} bytes each")

    session_id = "memory-test-session"

    # A repeating pattern chunk (benign — no red flags, PNG magic bytes)
    png_chunk = b"\x89PNG\r\n\x1a\n" + b"\xAB" * (CHUNK_SIZE - 8)

    proc = subprocess.Popen(
        [BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    rss_samples = []
    stop_sampling = threading.Event()

    def sample_rss():
        while not stop_sampling.is_set():
            rss = get_rss_kb(proc.pid)
            if rss > 0:
                rss_samples.append(rss)
            time.sleep(0.1)

    rss_thread = threading.Thread(target=sample_rss, daemon=True)
    rss_thread.start()

    # Send START_DOWNLOAD
    start_msg = encode_message({
        "type": "START_DOWNLOAD",
        "session_id": session_id,
        "filename": "large_test_file.png",
        "content_length": total_bytes,
    })
    proc.stdin.write(start_msg)
    proc.stdin.flush()

    # Stream chunks with backpressure (wait for ACK before sending next)
    received_buf = b""

    t_start = time.monotonic()
    for i in range(num_chunks):
        is_last = (i == num_chunks - 1)
        chunk_b64 = base64.b64encode(png_chunk[:CHUNK_SIZE if not is_last
                                               else total_bytes - i * CHUNK_SIZE]).decode("ascii")
        chunk_msg = encode_message({
            "type": "CHUNK",
            "session_id": session_id,
            "seq": i,
            "is_last": is_last,
            "data": chunk_b64,
        })

        proc.stdin.write(chunk_msg)
        proc.stdin.flush()

        # Wait for CHUNK_ACK before sending next chunk (backpressure)
        while True:
            data = proc.stdout.read(4)
            if len(data) < 4:
                break
            length = struct.unpack("<I", data)[0]
            body = proc.stdout.read(length)
            msg = json.loads(body)
            if msg.get("type") == "CHUNK_ACK":
                break
            elif msg.get("type") == "VERDICT":
                print(f"  Early verdict at chunk {i}: {msg}")
                break

        if i % 10 == 0:
            rss = get_rss_kb(proc.pid)
            elapsed = time.monotonic() - t_start
            pct = (i + 1) / num_chunks * 100
            print(f"  Chunk {i+1}/{num_chunks} ({pct:.0f}%) | RSS: {rss} KB | {elapsed:.1f}s")

    proc.stdin.close()
    stdout_data, stderr_data = proc.communicate(timeout=30)
    stop_sampling.set()

    t_elapsed = time.monotonic() - t_start
    print(f"\nCompleted in {t_elapsed:.1f}s")
    print(f"Stderr tail:\n{stderr_data.decode('utf-8', errors='replace')[-500:]}")

    if not rss_samples:
        print("WARNING: No RSS samples collected (is this Linux?)")
    else:
        min_rss = min(rss_samples)
        max_rss = max(rss_samples)
        print(f"\nRSS stats: min={min_rss} KB, max={max_rss} KB, range={max_rss - min_rss} KB")

        # Ring buffer = 4 chunks × 256 KB = 1 MB = 1024 KB overhead
        # Allow generous 50 MB total for the process (overhead + stack + etc.)
        max_allowed_kb = 51_200  # 50 MB
        if max_rss > max_allowed_kb:
            print(f"❌ FAIL: Peak RSS {max_rss} KB exceeds {max_allowed_kb} KB — memory not bounded!")
            sys.exit(1)
        else:
            print(f"✅ PASS: Peak RSS {max_rss} KB stays within {max_allowed_kb} KB limit")
            print(f"   Range variation: {max_rss - min_rss} KB (expected ~ring-buffer size ~{4*256} KB)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-mb", type=int, default=256,
                        help="Size of synthetic test file in MB (default: 256)")
    args = parser.parse_args()
    run_test(args.size_mb)
