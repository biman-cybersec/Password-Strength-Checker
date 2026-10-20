"""Rebuild common-passwords.js from common_passwords.txt (run this after editing the .txt)."""
import json
from pathlib import Path

here = Path(__file__).parent
words = sorted({w.strip().lower() for w in (here / "common_passwords.txt").read_text(encoding="utf-8").splitlines() if w.strip()})
(here / "common-passwords.js").write_text(
    "// Generated from common_passwords.txt. Do not edit by hand; run build_common_js.py.\n"
    "window.COMMON_PASSWORDS = " + json.dumps(words, separators=(",", ":")) + ";\n",
    encoding="utf-8",
)
print(f"Wrote common-passwords.js with {len(words)} passwords")
