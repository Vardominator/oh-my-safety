#!/usr/bin/env python3
"""Small, dependency-free documentation gate used by CI."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parent.parent
DOCS = [
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    *sorted((ROOT / "docs").rglob("*.md")),
]
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*]\(([^)\s]+)(?:\s+['\"][^)]*['\"])?\)")
HTML_SOURCE = re.compile(r"""(?:src|href)=["']([^"']+)["']""")
EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "tel:")


def check_link(source: Path, raw_target: str) -> str | None:
    target = raw_target.strip("<>")
    if not target or target.startswith(("#", *EXTERNAL_PREFIXES)):
        return None

    path_text = unquote(target.split("#", 1)[0].split("?", 1)[0])
    if not path_text:
        return None

    destination = Path(path_text)
    if not destination.is_absolute():
        destination = source.parent / destination
    if not destination.exists():
        return f"{source.relative_to(ROOT)}: missing link target {raw_target}"
    return None


def main() -> int:
    failures: list[str] = []
    for document in DOCS:
        if not document.is_file():
            failures.append(f"missing required documentation file: {document.relative_to(ROOT)}")
            continue
        text = document.read_text(encoding="utf-8")
        targets = MARKDOWN_LINK.findall(text) + HTML_SOURCE.findall(text)
        failures.extend(
            failure
            for target in targets
            if (failure := check_link(document, target)) is not None
        )

    formula = (ROOT / "Formula/oh-my-safety.rb").read_text(encoding="utf-8")
    if "REPLACE_WITH_RELEASE_SHA256" in formula:
        failures.append("Formula/oh-my-safety.rb: release checksum placeholder is forbidden")
    if not re.search(r'^\s*sha256 "[0-9a-f]{64}"$', formula, re.MULTILINE):
        failures.append("Formula/oh-my-safety.rb: stable sha256 must be 64 lowercase hex characters")

    if failures:
        print("\n".join(f"ERROR: {failure}" for failure in failures), file=sys.stderr)
        return 1

    print(f"Documentation gate passed ({len(DOCS)} Markdown files checked).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
