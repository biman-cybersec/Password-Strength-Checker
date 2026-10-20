"""Password Strength Checker.

Scores a password out of 6 and classifies it as Low, Medium, Moderate or Strong.

Usage:
    python password_checker.py passwords.txt
"""

import re
import csv
import sys
from pathlib import Path

def _load_common_passwords():
    """Read common_passwords.txt (next to this file). Falls back to a short built-in list."""
    fallback = {"password", "123456", "12345678", "qwerty", "abc123", "letmein", "admin", "welcome"}
    try:
        text = Path(__file__).with_name("common_passwords.txt").read_text(encoding="utf-8")
    except OSError:
        return fallback
    return {line.strip().lower() for line in text.splitlines() if line.strip()} or fallback


COMMON_PASSWORDS = _load_common_passwords()

LEET = {"@": "a", "4": "a", "0": "o", "3": "e", "$": "s", "5": "s", "7": "t", "!": "i"}

def leet_variants(password: str) -> set:
    """Undo common look-alike swaps (p@ssw0rd -> password). '1' may be l, i or a real 1;
    trailing ! ? . are also tried as plain punctuation (Password! -> password)."""
    lower = password.lower()
    out = set()
    for source in (lower, re.sub(r"[!?.]+$", "", lower)):
        for one in ("l", "i", "1"):
            out.add("".join(one if c == "1" else LEET.get(c, c) for c in source))
    return out


def is_common(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS or any(v in COMMON_PASSWORDS for v in leet_variants(password))

SEQUENCES = [
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]


def has_sequence(password: str, n: int = 4) -> bool:
    """True if the password contains n characters in a row from a common
    sequence (abcd, 1234, qwer ...), forwards or backwards."""
    p = password.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - n + 1):
                if s[i:i + n] in p:
                    return True
    return False


def has_repeat(password: str, n: int = 3) -> bool:
    """True if the same character appears n or more times in a row."""
    return re.search(r"(.)\1{%d,}" % (n - 1), password) is not None


def label_for(score: int) -> str:
    if score <= 1:
        return "Low"
    if score <= 3:
        return "Medium"
    if score == 4:
        return "Moderate"
    return "Strong"


def check_password(password: str) -> dict:
    """Return {'score': 0-6, 'label': str, 'feedback': [str]}."""
    if not password:
        return {"score": 0, "label": label_for(0), "feedback": ["Enter a password."]}

    if password.lower() in COMMON_PASSWORDS:
        return {
            "score": 0,
            "label": label_for(0),
            "feedback": ["This is a very common password. Pick something unique."],
        }
    if is_common(password):
        return {
            "score": 0,
            "label": label_for(0),
            "feedback": ["This is a common password with look-alike swaps (like p@ssw0rd). Pick something unique."],
        }
        
    feedback = []
    score = 0

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Use 12 or more characters.")

    if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Mix uppercase and lowercase letters.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add a number.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        feedback.append("Add a symbol (e.g. ! @ # $).")

    if has_sequence(password):
        feedback.append("Avoid sequences like abcd, 1234 or qwer.")
    elif has_repeat(password):
        feedback.append("Avoid repeating the same character 3+ times.")
    else:
        score += 1

    return {"score": score, "label": label_for(score), "feedback": feedback}


def check_file(path: str) -> list:
    """Check every non-empty line of a file. Returns a list of result dicts."""
    results = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        pw = line.strip()
        if not pw:
            continue
        result = check_password(pw)
        result["password"] = pw
        results.append(result)
    return results


def main(argv):
    path = argv[1] if len(argv) == 2 else str(Path(__file__).with_name("passwords.txt"))
    
    results = check_file(path)
    print(f"{'Password':<35} {'Score':<7} Strength")
    print("-" * 55)
    for r in results:
        print(f"{r['password']:<35} {r['score']}/6     {r['label']}")

    print("\nSummary:")
    for label in ("Low", "Medium", "Moderate", "Strong"):
        count = sum(1 for r in results if r["label"] == label)
        print(f"  {label:<9} {count}")
    
    # Save the report files next to the password file.
    print(f"\nCSV report saved: {save_csv_report(results, Path(path).with_name('password_report.csv'))}")
    try:
        print(f"Chart saved:      {save_chart(results, Path(path).with_name('strength_chart.png'))}")
    except ImportError:
        print("Chart skipped. Install matplotlib with: pip install matplotlib")
    return 0

def _safe(value) -> str:
    """Stop spreadsheet apps from treating a password like a formula."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def save_csv_report(results: list, path="password_report.csv"):
    """Write the results to a CSV file and return its path."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Password", "Score", "Strength"])
        for r in results:
            writer.writerow([_safe(r["password"]), r["score"], r["label"]])
    return path


def save_chart(results: list, path="strength_chart.png"):
    """Save a bar chart of how many passwords fall in each level."""
    import matplotlib
    matplotlib.use("Agg")                      # draw to a file, no window needed
    import matplotlib.pyplot as plt
    from matplotlib.ticker import MaxNLocator

    labels = ["Low", "Medium", "Moderate", "Strong"]
    counts = [sum(1 for r in results if r["label"] == l) for l in labels]

    plt.figure(figsize=(6, 4))
    bars = plt.bar(labels, counts, color=["#ef4444", "#f97316", "#eab308", "#22c55e"])
    plt.bar_label(bars)
    plt.title("Password strength")
    plt.ylabel("Number of passwords")
    plt.gca().yaxis.set_major_locator(MaxNLocator(integer=True))   # whole numbers only
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    return path


if __name__ == "__main__":
    sys.exit(main(sys.argv))
