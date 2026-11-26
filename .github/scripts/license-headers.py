#!/usr/bin/env python3
# Copyright Seaionl Inc. and CertPing contributors
# SPDX-License-Identifier: Apache-2.0
"""Checks, or with --fix adds, the copyright and license header on CertPing's own source files.

Every tracked source file starts with (in the file's comment style):

    Copyright Seaionl Inc. and CertPing contributors
    SPDX-License-Identifier: Apache-2.0

A shebang, a Dockerfile "# syntax=" line, a "#cloud-config" line, an XML declaration or a Jest pragma
docblock stays first, with the header after it. Not covered: Flyway migrations (a changed migration
fails its checksum on upgrade), third-party license texts, lock files, JSON, Markdown, email
templates (sent to recipients as they are), images, and files that cannot hold a comment (.nvmrc,
PEM files, Mockito's MockMaker).

Usage: .github/scripts/license-headers.py          exit 1 and list files without the header
       .github/scripts/license-headers.py --fix    add the header where it is missing
"""
import os
import re
import subprocess
import sys

COPYRIGHT = "Copyright Seaionl Inc. and CertPing contributors"
LICENSE = "SPDX-License-Identifier: Apache-2.0"

SLASH = ("//", "")
HASH = ("#", "")
DASH = ("--", "")
XML = ("<!--", "-->")
HELM = ("{{- /*", "*/ -}}")
STYLES = {
    ".java": SLASH, ".ts": SLASH, ".tsx": SLASH, ".js": SLASH, ".mjs": SLASH, ".cjs": SLASH,
    ".proto": SLASH, ".tf": HASH, ".sh": HASH, ".py": HASH, ".yaml": HASH, ".yml": HASH,
    ".toml": HASH, ".properties": HASH, ".conf": HASH, ".tftpl": HASH, ".sql": DASH,
    ".xml": XML, ".tpl": HELM, ".css": ("/*", " */"),
}
NAMED = {"Dockerfile": HASH, "Caddyfile": HASH, "Corefile": HASH,
         "Makefile": HASH, "pre-commit": HASH, "certping-admin": HASH, "lombok.config": HASH,
         ".gitignore": HASH, ".gitattributes": HASH, ".dockerignore": HASH, ".prettierignore": HASH,
         ".env.example": HASH}

EXCLUDED_PARTS = ("/db/migration/", "/licenses/", "/node_modules/", "/target/", "/.next/")
EXCLUDED_NAMES = {"pnpm-lock.yaml", "next-env.d.ts", ".terraform.lock.hcl"}
# The first line of these must stay first.
KEEP_FIRST = ("#!", "# syntax=", "#cloud-config", "<?xml")


def style_for(path):
    name = os.path.basename(path)
    if name in EXCLUDED_NAMES or any(part in "/" + path for part in EXCLUDED_PARTS):
        return None
    if name in NAMED or name.endswith(".Dockerfile"):
        return NAMED.get(name, HASH)
    return STYLES.get(os.path.splitext(name)[1])


def header_lines(style):
    start, end = style
    if style in (XML, HELM):  # one comment over two lines
        return [f"{start} {COPYRIGHT}", f"{' ' * len(start)} {LICENSE} {end}"]
    if end:  # a block comment, as in CSS
        return [f"{start} {COPYRIGHT}", f" * {LICENSE}", end]
    return [f"{start} {COPYRIGHT}", f"{start} {LICENSE}"]


def has_header(text):
    head = text[:600]
    return COPYRIGHT in head and LICENSE in head


def add_header(text, style):
    lines = text.split("\n")
    keep = [lines.pop(0)] if lines and lines[0].startswith(KEEP_FIRST) else []
    # Jest reads its pragmas (@jest-environment) only from the docblock that opens the file.
    pragma = re.match(r"/\*\*.*?\*/\n", text, re.S)
    if not keep and pragma and "@jest-" in pragma.group(0):
        keep = pragma.group(0).rstrip("\n").split("\n") + [""]
        lines = text[pragma.end():].lstrip("\n").split("\n")
    block = header_lines(style)
    if lines and lines[0].strip():
        block.append("")
    return "\n".join(keep + block + lines)


def main():
    fix = "--fix" in sys.argv[1:]
    root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    os.chdir(root)
    files = subprocess.check_output(["git", "ls-files", "-z"], text=True).split("\0")
    missing = []
    for path in files:
        if not path or not os.path.isfile(path):
            continue
        style = style_for(path)
        if style is None:
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        if has_header(text):
            continue
        if fix:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(add_header(text, style))
        missing.append(path)
    if fix:
        print(f"Added the header to {len(missing)} files.")
        return 0
    if missing:
        print("These files have no copyright and license header:")
        print("\n".join(f"  {path}" for path in missing))
        print("Run .github/scripts/license-headers.py --fix and commit the result.")
        return 1
    print("Every source file has the copyright and license header.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
