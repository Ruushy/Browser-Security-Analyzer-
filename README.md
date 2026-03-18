# 🔒 Browser Security Analyzer v1.0

A Python CLI tool that scans local browser settings, detects insecure configurations,
and provides actionable security recommendations.

> ⚠️ **ETHICS NOTICE**: This tool is for ethical and educational purposes only.
> Only scan your own browsers.

---

## 📦 Installation

```bash
# Required (standard library only — no pip needed for basic run)
python3 browser_security_analyzer.py

# Optional: install rich for coloured tables + progress bar
pip install rich

# Optional: install tqdm for fallback progress bar
pip install tqdm
```

---

## 🚀 Usage

```bash
# Basic scan (all detected browsers)
python3 browser_security_analyzer.py

# Scan a specific browser only
python3 browser_security_analyzer.py --browser Chrome
python3 browser_security_analyzer.py --browser Firefox
python3 browser_security_analyzer.py --browser Edge

# Export results
python3 browser_security_analyzer.py --export-json results.json
python3 browser_security_analyzer.py --export-txt  results.txt

# Combine flags
python3 browser_security_analyzer.py --browser Chrome --export-json chrome_report.json

# Suppress banner
python3 browser_security_analyzer.py --no-banner
```

---

## 🖥️ Example CLI Output

```
  ____  ____   ___  _    _ ____  _____ ____     ____  _____ ____ _   _ ____  ___ _______   __
 | __ )|  _ \ / _ \| |  | / ___|| ____|  _ \   / ___|| ____/ ___| | | |  _ \|_ _|_   _\ \ / /
 |  _ \| |_) | | | | |  | \___ \|  _| | |_) |  \___ \|  _|| |   | | | | |_) || |  | |  \ V /
 | |_) |  _ <| |_| | |/\| |___) | |___|  _ <    ___) | |__| |___| |_| |  _ < | |  | |   | |
 |____/|_| \_\\___/ |__/\__|____/|_____|_| \_\  |____/|_____\____|\___/|_| \_\___| |_|   |_|

    ANALYZER  v1.0         🔒  Detect Insecure Browser Configurations

⚠  ETHICS NOTICE: This tool is for ethical and educational purposes only.
   Only scan your own browsers.

✔ Detected browsers: Chrome, Firefox, Edge

  Scanning Chrome... ████████████ 100%

╭──────────────────────────────────────────────────────────────────────────────────────╮
│                         🔍 Browser Security Summary                                  │
├──────────────┬──────────────────────────────┬──────────────────────┬────────────────┤
│ Browser      │ HTTPS-Only                   │ Pwd Saving           │ Autofill       │ Extensions │ Risky Exts │
├──────────────┼──────────────────────────────┼──────────────────────┼────────────────┤
│ Chrome       │ Not Detected / Disabled ✘    │ Password Saving ON ✘ │ Autofill ON ✘  │     12     │     2      │
│ Firefox      │ HTTPS-Only Mode Enabled ✔    │ Password Saving ON ✘ │ Autofill ON ✘  │      5     │     0      │
│ Edge         │ Not Detected / Disabled ✘    │ Password Saving ON ✘ │ Autofill ON ✘  │      8     │     1      │
╰──────────────┴──────────────────────────────┴──────────────────────┴────────────────╯

  🧩 Chrome Extensions (12 found)
  ┃ Name                              ┃ Version   ┃ Risk   ┃
  ┃ uBlock Origin                     ┃ 1.56.0    ┃ OK     ┃
  ┃ Dark Reader                       ┃ 4.9.61    ┃ OK     ┃
  ┃ Honey                             ┃ 14.1.0    ┃ ⚠ RISKY┃
  ┃ Touch VPN                         ┃ 5.2.1     ┃ ⚠ RISKY┃
  ┃ LastPass                          ┃ 4.119.0   ┃ OK     ┃
  ...

━━━━━━━━━━━━━━━━━━━━━━━ 📋 Security Recommendations ━━━━━━━━━━━━━━━━━━━━━━━

  1. [Chrome] Enable HTTPS-Only Mode: Settings → Privacy and Security → Security
             → Always use secure connections.
  2. [Chrome] Disable built-in password saving and use a dedicated password manager
             (e.g., Bitwarden, 1Password). Built-in managers can be accessed by anyone
             with OS access.
  3. [Chrome] Disable Autofill for forms and payment info:
             Settings → Autofill → turn off addresses and payment methods.
  4. [Chrome] Review or remove potentially risky extensions: Honey, Touch VPN.
             Extensions have broad access to your browsing data.
  5. [Firefox] Disable built-in password saving and use a dedicated password manager.
  6. [Firefox] Disable Autofill for forms and payment info.
  7. [Edge] Enable HTTPS-Only Mode in Edge settings.
  8. [Edge] Review or remove potentially risky extensions: Browsec VPN.

──────────────────────────────────────────────────────────────────────────────
  Scan complete — stay secure! 🔐
──────────────────────────────────────────────────────────────────────────────
```

---

## 🔎 What Gets Checked

| Check              | Chrome / Edge                          | Firefox                                    |
|--------------------|----------------------------------------|--------------------------------------------|
| **HTTPS-Only**     | `profile.https_only_mode_enabled`      | `dom.security.https_only_mode`             |
| **Password Saving**| `credentials_enable_service`           | `signon.rememberSignons`                   |
| **Autofill**       | `autofill.enabled`, `credit_card_enabled` | `extensions.formautofill.addresses.enabled` |
| **Extensions**     | Reads `/Extensions/*/manifest.json`    | Reads `extensions.json`                    |

---

## 🗂️ Project Structure

```
browser_security_analyzer.py   ← Single-file tool, no external deps required
```



## ⚖️ Disclaimer

This tool reads **only local files on your own machine** — no network requests are made.
It does not decrypt passwords, read browsing history, or transmit any data.
Use responsibly and only on systems you own or have explicit authorization to scan.
