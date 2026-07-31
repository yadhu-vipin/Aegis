#!/usr/bin/env python3
"""
Generate the sample files used for end-to-end testing.

These are the six cases in HANDOVER.md section 6. They are generated rather
than committed because several are deliberately malicious-looking, and a
repository full of things that trip antivirus scanners is its own problem.

    python scripts/make_test_files.py

Nothing here is actually malicious. The "executable" payloads are an `MZ`
header followed by zeros: enough for a scanner to identify the type, not
enough to do anything. There is deliberately no EICAR - on a machine with
Defender running, EICAR measures Defender rather than Aegis.
"""

import os
import struct
import zipfile

OUT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "test_files")
)

# An MZ header and nothing else. Identifiable as a Windows executable, inert.
FAKE_EXE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 512


def write(name, data):
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {name}  ({len(data)} bytes)")


def benign_pdf():
    """A real, minimal, valid PDF. Must be RELEASED."""
    body = (
        b"%PDF-1.4\n"
        b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
        b"trailer<</Root 1 0 R>>\n"
        b"%%EOF\n"
    )
    write("benign_document.pdf", body)


def zip_with_disguised_exe():
    """The archive case. Must be BLOCKED, naming the entry."""
    path = os.path.join(OUT, "invoice_archive.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("invoice.pdf.exe", FAKE_EXE)
        z.writestr("readme.txt", b"Please open the invoice.")
    print(f"  invoice_archive.zip  ({os.path.getsize(path)} bytes)")


def ordinary_source_zip():
    """The false-positive check. Must be RELEASED."""
    path = os.path.join(OUT, "ordinary_project.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("project/README.md", b"# A perfectly ordinary project\n")
        z.writestr("project/src/main.py", b"print('hello')\n")
        z.writestr("project/src/util.py", b"def add(a, b):\n    return a + b\n")
        z.writestr("project/docs/guide.txt", b"Documentation goes here.\n")
        z.writestr("project/LICENSE", b"MIT\n")
    print(f"  ordinary_project.zip  ({os.path.getsize(path)} bytes)")


def encrypted_zip():
    """
    A ZIP whose entries claim to be encrypted.

    Python's zipfile cannot write encrypted archives, so this sets general
    purpose bit 0 by hand in both the local header and the central directory.
    That is exactly what Aegis reads - it never decrypts anything, it reports
    that it cannot - so a flag-only archive exercises the real path.
    """
    path = os.path.join(OUT, "protected_documents.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        z.writestr("statement.pdf", b"%PDF-1.4\n" + b"x" * 200)
        z.writestr("details.docx", b"PK\x03\x04" + b"y" * 200)

    with open(path, "rb") as f:
        data = bytearray(f.read())

    # Local file headers: flags at offset +6. Central directory: offset +8.
    for sig, flag_off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = 0
        while True:
            pos = data.find(sig, pos)
            if pos < 0:
                break
            at = pos + flag_off
            flags = struct.unpack_from("<H", data, at)[0]
            struct.pack_into("<H", data, at, flags | 1)
            pos += 4

    with open(path, "wb") as f:
        f.write(bytes(data))
    print(f"  protected_documents.zip  ({len(data)} bytes)")


def macro_document():
    """
    A .docx carrying vbaProject.bin.

    Deliberately .docx rather than .docm: that format is macro-free by
    definition, so a macro stream inside one is a mismatch nobody creates by
    accident. A .docm would be reported and not condemned.
    """
    path = os.path.join(OUT, "quarterly_report.docx")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types/>')
        z.writestr("_rels/.rels", '<?xml version="1.0"?><Relationships/>')
        z.writestr("word/document.xml", '<?xml version="1.0"?><document/>')
        # OLE compound-file header, which is what a real vbaProject.bin is.
        z.writestr(
            "word/vbaProject.bin",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 500,
        )
    print(f"  quarterly_report.docx  ({os.path.getsize(path)} bytes)")


def signed_binary():
    """
    A genuinely signed executable, copied from Windows itself.

    Most Windows binaries carry no embedded signature - they are covered by a
    signed system catalogue - so this exercises the catalogue path, which is
    the one an embedded-only check gets wrong.
    """
    for candidate in (
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\calc.exe",
        r"C:\Windows\System32\where.exe",
    ):
        if os.path.exists(candidate):
            with open(candidate, "rb") as f:
                data = f.read()
            write("signed_windows_binary.exe", data)
            return
    print("  (no Windows binary available to copy - skipping signed sample)")


def main():
    os.makedirs(OUT, exist_ok=True)
    print(f"Writing to {OUT}")
    benign_pdf()
    zip_with_disguised_exe()
    ordinary_source_zip()
    encrypted_zip()
    macro_document()
    signed_binary()
    print("\nServe them with:  python scripts/serve_test_downloads.py")


if __name__ == "__main__":
    main()
