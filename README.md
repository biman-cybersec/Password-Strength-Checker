# Password Strength Checker

A cyber security learning project by **BIMAN SHIL**. It rates a password out of 6 (**Low, Medium, Moderate, Strong**) and explains what to improve. It comes in three forms that share the same scoring rules:

- a **command-line script** (`password_checker.py`)
- a **website** (`index.html`) that also works as an installable, offline app
- a small **Flask server** (`app.py`) that serves the website and a JSON API

> **Experiment only.** This tool is for learning. It does not guarantee the security of any password. Please do not enter your real passwords.

## Features

**Checking**
- Score out of 6, strength label, live requirements checklist and tips
- Crack-time estimate and entropy (in bits) that account for patterns, not just length
- Attack simulator: dictionary list, online guessing (100/s), offline GPU (10 billion/s)
- Weak parts of the password highlighted in red
- Common-password list (about 1,650 entries) with leetspeak detection (`p@ssw0rd` is treated as `password`)
- "Words to avoid" box (name, pet, year); matches lower the score
- Strength presets: Standard, Wi-Fi, Email, Bank
- Leak check using Have I Been Pwned (only the first 5 characters of a SHA-1 hash are sent, never the password); a leaked password scores 0

**Tools**
- Random password generator and passphrase generator (uses `crypto.getRandomValues`)
- Copy button that clears the clipboard after 30 seconds
- Bulk check of a `.txt` file (one password per line) with a table, bar chart, CSV download and PNG chart download
- PDF report of the result (never contains the password)

**Experience**
- Light and dark theme, animated background, rainbow cursor trail
- Keyboard shortcuts: `/` password box, `Alt+G` generate, `Alt+P` passphrase, `Alt+T` theme, `Esc` close notice
- Accessible: ARIA meter, screen-reader announcements, skip link, visible focus, readable contrast
- Installable app (PWA) that keeps working when the server is stopped

## Scoring rules

One point each, total 6:

1. 8 or more characters
2. 12 or more characters
3. Upper and lower case letters
4. A number
5. A symbol (anything that is not a letter or number)
6. No sequence (4+ characters in a row such as `abcd`, `1234`, `qwer`, forwards or backwards) and no character repeated 3+ times

Special cases: an empty password scores 0; a common password (or one that is common after undoing look-alike swaps) scores 0.

| Score | Label |
|---|---|
| 0-1 | Low |
| 2-3 | Medium |
| 4 | Moderate |
| 5-6 | Strong |

Presets (website only) add rules such as a longer minimum length or a required symbol. A missing requirement caps the result at Medium.

## How the crack-time estimate works

The website estimates how many guesses an attacker would need. It finds the cheapest way to "explain" the password out of: random characters, sequences, repeated characters, years, dictionary words (with extra cost for capital letters and look-alike swaps) and your avoid-words. It then assumes 10 billion guesses per second and an average of half the possibilities. So `Summer2024` (a word and a year) is cracked almost instantly, while a long random password takes billions of years.

## Run it

You need Python 3.9 or newer.

**1. Command line**
```
python password_checker.py                 # checks passwords.txt
python password_checker.py my_list.txt     # checks your own file
```
Prints a table and a summary, and saves `password_report.csv` and `strength_chart.png` next to the file. The chart needs `pip install matplotlib` (it is skipped with a note if missing).

**2. Website with the Flask server** (recommended)
```
pip install flask
python app.py
```
Open http://127.0.0.1:5000. Bulk checks run on the Python side; if the server is not running, the page falls back to checking in the browser.

**3. Website only**
Open `index.html` in a browser. Everything works except the installable-app features, which need `http://` (use option 2).

**Install as an app:** open the site through the server, then use the install icon in Chrome's address bar. The app keeps working offline (except the leak check). To remove it completely, uninstall it and tick "Also clear data from Chrome".

## API

| Method and path | Body | Result |
|---|---|---|
| `POST /api/check` | `{"password": "..."}` | `{"score", "label", "feedback"}` |
| `POST /api/bulk` | `{"passwords": ["...", "..."]}` | `{"results": [{"password", "score", "label"}]}` |

Errors: `400` if a value is not text, `413` if more than 100,000 passwords are sent. The server only serves a fixed list of website files, so `.py` and `.txt` files are never exposed.

## Tests

```
pip install pytest flask
pytest
```
- `test_password_checker.py`: scoring rules, sequences, repeats, labels, file reading
- `test_checker_extra.py`: common list, leetspeak, CSV report safety
- `test_app.py`: every API route, error cases, and that private files return 404

## Project structure

| File | Purpose |
|---|---|
| `password_checker.py` | Scoring logic and command-line tool |
| `app.py` | Flask server and API |
| `passwords.txt` | Sample passwords |
| `common_passwords.txt` | Common-password list used by Python |
| `build_common_js.py` | Builds `common-passwords.js` from the list |
| `make_wordlist.py` | Builds `wordlist.js` for the passphrase generator |
| `index.html`, `style.css`, `script.js` | The website |
| `common-passwords.js`, `wordlist.js` | Word lists for the website |
| `extras.js` | PDF report and service-worker registration |
| `sw.js`, `manifest.webmanifest`, `icon-*.png` | Installable offline app |
| `test_*.py` | Tests |

## Limitations

- The common-password list was written for this project; it is **not** a real leaked dataset. For real use, replace `common_passwords.txt` with a list such as SecLists' top 10,000 and run `python build_common_js.py`.
- The crack-time is an estimate with a simple attacker model, not a guarantee. Passphrases are still over-estimated, because their separator and number are counted as random characters.
- The "avoid words", presets, leak check, entropy and attack simulator exist only in the website. The Python script uses the basic 6-point rules.
- The leak check needs an internet connection and sends a partial hash to a third party (Have I Been Pwned).
- This is a learning project. Use a password manager for real accounts.

---
&copy; Made by **BIMAN SHIL**.
