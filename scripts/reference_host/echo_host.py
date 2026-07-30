#!/usr/bin/env python3
"""
Minimal reference native messaging host — diagnostic only, not part of Aegis.

Purpose: determine whether Microsoft Edge can launch ANY native messaging host
on this machine, or whether the failure is specific to the Aegis host.

Aegis's host has never been launched by Edge: it writes its log as the very
first statement in main(), and no log has ever appeared in any location. Edge
reports "Can't find manifest" for a manifest that demonstrably exists at a path
the registry demonstrably points to. That is only possible if Edge is not
consulting the registry location we wrote, so the question becomes whether
native messaging works here at all.

This host is deliberately different from Aegis in every respect that could
matter:

  * Python, not Rust
  * launched through a .bat wrapper (so Edge goes via cmd.exe), not a direct
    .exe invocation
  * a different host name (com.aegis.echo), so it gets its own registry key
  * no config file, no dependencies, nothing that can fail at startup

The FIRST thing it does is append to a log. If that file appears, Edge launched
it — which tells us native messaging works and the fault is in the Aegis
registration. If it never appears, native messaging is broken for this Edge
install and nothing in Aegis is at fault.
"""

import json
import os
import struct
import sys
import datetime

LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "echo-host.log")


def log(msg):
    """Append to the log, flushing immediately.

    Written before anything else can fail, and never allowed to raise: if the
    log is unwritable we still want the host to speak the protocol correctly,
    because "ran but could not log" and "never ran" are different diagnoses.
    """
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now().isoformat()} {msg}\n")
            f.flush()
    except Exception:
        pass


def read_message():
    """Read one Chrome native-messaging frame: 4-byte LE length + JSON."""
    raw = sys.stdin.buffer.read(4)
    if len(raw) < 4:
        return None
    length = struct.unpack("<I", raw)[0]
    if length == 0 or length > 1024 * 1024:
        log(f"rejecting absurd frame length {length}")
        return None
    body = sys.stdin.buffer.read(length)
    return json.loads(body.decode("utf-8"))


def write_message(obj):
    data = json.dumps(obj).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(data)))
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def main():
    # Capture the environment Edge gives us. This is the information we have
    # never been able to obtain for the Aegis host, because it has never run.
    log("=== echo host STARTED — Edge successfully launched a native host ===")
    log(f"  pid  = {os.getpid()}")
    log(f"  exe  = {sys.executable}")
    log(f"  cwd  = {os.getcwd()}")
    log(f"  argv = {sys.argv}")
    log(f"  user = {os.environ.get('USERNAME')}")

    try:
        while True:
            msg = read_message()
            if msg is None:
                log("stdin closed — exiting cleanly")
                break
            log(f"received: {msg}")
            write_message({
                "type": "ECHO_PONG",
                "received": msg,
                "pid": os.getpid(),
                "python": sys.version.split()[0],
            })
            log("replied ECHO_PONG")
    except Exception as e:
        log(f"ERROR: {e!r}")
        raise


if __name__ == "__main__":
    main()
