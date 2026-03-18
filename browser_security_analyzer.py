#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           🔒 BROWSER SECURITY ANALYZER v1.0                  ║
║         Detect insecure browser configurations               ║
╠══════════════════════════════════════════════════════════════╣
║  ⚠️  ETHICS NOTICE:                                          ║
║  This tool is for ethical and educational purposes only.     ║
║  Only scan your own browsers.                                ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import sqlite3
import shutil
import platform
import tempfile
import argparse
from pathlib import Path
from datetime import datetime

# ── Optional rich library for nice output ──────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ── Optional tqdm for progress bar fallback ────────────────────────────────────
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

console = Console() if RICH_AVAILABLE else None

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

# Extensions considered risky / potentially unwanted
RISKY_EXTENSION_KEYWORDS = [
    "vpn", "proxy", "ad inject", "coupon", "honey",
    "grammarly",  # high data access - not always risky but flagged for review
    "superfish", "conduit", "searchqu", "mywebsearch",
    "astrill", "hola", "touch vpn", "browsec",
    "web of trust", "wot",  # privacy concerns historically
    "savefrom", "helper", "downloader",
]

PLATFORM = platform.system()  # 'Windows', 'Darwin', 'Linux'


# ══════════════════════════════════════════════════════════════════════════════
#  BROWSER PATH DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def get_browser_paths() -> dict:
    """
    Return known profile directory paths for Chrome, Firefox, and Edge
    based on the current OS platform.
    """
    home = Path.home()
    paths = {}

    if PLATFORM == "Windows":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roaming = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        paths = {
            "Chrome": local / "Google" / "Chrome" / "User Data" / "Default",
            "Edge":   local / "Microsoft" / "Edge" / "User Data" / "Default",
            "Firefox": roaming / "Mozilla" / "Firefox" / "Profiles",
        }

    elif PLATFORM == "Darwin":  # macOS
        paths = {
            "Chrome":  home / "Library" / "Application Support" / "Google" / "Chrome" / "Default",
            "Edge":    home / "Library" / "Application Support" / "Microsoft Edge" / "Default",
            "Firefox": home / "Library" / "Application Support" / "Firefox" / "Profiles",
        }

    else:  # Linux
        paths = {
            "Chrome":  home / ".config" / "google-chrome" / "Default",
            "Edge":    home / ".config" / "microsoft-edge" / "Default",
            "Firefox": home / ".mozilla" / "firefox",
        }

    return paths


def detect_installed_browsers(paths: dict) -> list:
    """
    Return a list of browsers that have a detectable profile directory.
    """
    detected = []
    for browser, path in paths.items():
        if path.exists():
            detected.append(browser)
    return detected


# ══════════════════════════════════════════════════════════════════════════════
#  CHROMIUM-BASED CHECKS (Chrome / Edge)
# ══════════════════════════════════════════════════════════════════════════════

def read_chromium_preferences(profile_path: Path) -> dict:
    """
    Read and parse the Preferences JSON file for a Chromium-based browser.
    Returns an empty dict on failure.
    """
    prefs_file = profile_path / "Preferences"
    if not prefs_file.exists():
        return {}
    try:
        with open(prefs_file, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        _warn(f"Could not read Preferences at {prefs_file}: {e}")
        return {}


def check_chromium_https_only(prefs: dict) -> tuple:
    """
    Check whether HTTPS-Upgrading (HTTPS-only mode) is enabled in Chrome/Edge.
    Returns (status_bool, label_string).
    Chrome stores this under profile.https_only_mode_enabled or
    profile.content_settings.exceptions.http_allowed.
    """
    # Direct key (Chrome 94+)
    https_only = prefs.get("profile", {}).get("https_only_mode_enabled", None)
    if https_only is True:
        return True, "Enabled ✔"
    if https_only is False:
        return False, "Disabled ✘"

    # Fallback: check https_upgrading_enabled
    https_upgrade = prefs.get("https_upgrades_enabled", None)
    if https_upgrade is True:
        return True, "HTTPS Upgrading Enabled ✔"

    return False, "Not Detected / Disabled ✘"


def check_chromium_password_saving(prefs: dict) -> tuple:
    """Check if the built-in password manager is enabled."""
    enabled = prefs.get("credentials_enable_service", True)
    if enabled:
        return False, "Password Saving ON ✘"  # False = not-secure
    return True, "Password Saving OFF ✔"


def check_chromium_autofill(prefs: dict) -> tuple:
    """Check if autofill for addresses/forms is enabled."""
    autofill_enabled = prefs.get("autofill", {}).get("enabled", True)
    payment_enabled  = prefs.get("autofill", {}).get("credit_card_enabled", True)
    if autofill_enabled or payment_enabled:
        return False, f"Autofill ON (forms={autofill_enabled}, payments={payment_enabled}) ✘"
    return True, "Autofill OFF ✔"


def get_chromium_extensions(profile_path: Path) -> list:
    """
    Return a list of dicts with extension name, id, version, and a risky flag.
    Reads from the Extensions directory metadata.
    """
    extensions = []
    ext_dir = profile_path / "Extensions"
    if not ext_dir.exists():
        return extensions

    for ext_id in ext_dir.iterdir():
        if not ext_id.is_dir():
            continue
        # Each extension id folder contains version sub-folders
        for version_dir in ext_id.iterdir():
            manifest_path = version_dir / "manifest.json"
            if not manifest_path.exists():
                continue
            try:
                with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
                    manifest = json.load(f)
                name    = manifest.get("name", "Unknown")
                version = manifest.get("version", "?")
                # Resolve _locales name if it's a placeholder like __MSG_appName__
                if name.startswith("__MSG_"):
                    name = _resolve_extension_name(version_dir, name)
                risky = _is_risky_extension(name)
                extensions.append({
                    "id": ext_id.name,
                    "name": name,
                    "version": version,
                    "risky": risky,
                })
                break  # only need the latest version folder
            except (json.JSONDecodeError, OSError):
                continue

    return extensions


def _resolve_extension_name(version_dir: Path, msg_key: str) -> str:
    """Try to resolve __MSG_xxx__ placeholder from _locales/en/messages.json."""
    key = msg_key.strip("__MSG_").rstrip("__").lower()
    messages_file = version_dir / "_locales" / "en" / "messages.json"
    if not messages_file.exists():
        messages_file = version_dir / "_locales" / "en_US" / "messages.json"
    if messages_file.exists():
        try:
            with open(messages_file, "r", encoding="utf-8", errors="replace") as f:
                messages = json.load(f)
            for k, v in messages.items():
                if k.lower() == key:
                    return v.get("message", msg_key)
        except (json.JSONDecodeError, OSError):
            pass
    return msg_key


def _is_risky_extension(name: str) -> bool:
    """Return True if the extension name matches any risky keyword."""
    name_lower = name.lower()
    return any(kw in name_lower for kw in RISKY_EXTENSION_KEYWORDS)


# ══════════════════════════════════════════════════════════════════════════════
#  FIREFOX CHECKS
# ══════════════════════════════════════════════════════════════════════════════

def get_firefox_default_profile(profiles_path: Path) -> Path | None:
    """
    Locate the default Firefox profile directory.
    Looks for profiles.ini and returns the default profile path.
    """
    profiles_ini = profiles_path.parent / "profiles.ini"
    if not profiles_ini.exists():
        # Try to find any profile folder directly
        for entry in profiles_path.iterdir():
            if entry.is_dir() and (".default" in entry.name or "default-release" in entry.name):
                return entry
        # Last resort: return first profile folder
        for entry in profiles_path.iterdir():
            if entry.is_dir():
                return entry
        return None

    # Parse profiles.ini manually (avoid configparser encoding issues)
    try:
        content = profiles_ini.read_text(encoding="utf-8", errors="replace")
        current_path = None
        is_relative = True
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("path="):
                current_path = line.split("=", 1)[1]
            elif line.lower().startswith("isrelative="):
                is_relative = line.split("=", 1)[1].strip() == "1"
            elif line.lower().startswith("default=1") or (line == "" and current_path):
                if current_path:
                    if is_relative:
                        return profiles_path.parent / current_path
                    else:
                        return Path(current_path)
        # Fallback: return first path found
        current_path = None
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith("path="):
                current_path = line.split("=", 1)[1]
                break
        if current_path:
            return profiles_path.parent / current_path
    except OSError:
        pass
    return None


def read_firefox_prefs(profile_path: Path) -> dict:
    """
    Parse Firefox's user.js or prefs.js into a key→value dict.
    """
    prefs = {}
    for filename in ("user.js", "prefs.js"):
        prefs_file = profile_path / filename
        if not prefs_file.exists():
            continue
        try:
            content = prefs_file.read_text(encoding="utf-8", errors="replace")
            for line in content.splitlines():
                line = line.strip()
                if not line.startswith("user_pref("):
                    continue
                # e.g.  user_pref("security.OCSP.enabled", 1);
                inner = line[len("user_pref("):-2]  # strip leading/trailing
                parts = inner.rsplit(",", 1)
                if len(parts) != 2:
                    continue
                key   = parts[0].strip().strip('"')
                value = parts[1].strip()
                # Convert value types
                if value == "true":
                    value = True
                elif value == "false":
                    value = False
                elif value.lstrip("-").isdigit():
                    value = int(value)
                elif value.startswith('"'):
                    value = value.strip('"')
                prefs[key] = value
        except OSError as e:
            _warn(f"Could not read {filename}: {e}")
    return prefs


def check_firefox_https_only(prefs: dict) -> tuple:
    """
    dom.security.https_only_mode = true  → enabled
    """
    enabled = prefs.get("dom.security.https_only_mode", False)
    if enabled is True:
        return True, "HTTPS-Only Mode Enabled ✔"
    return False, "HTTPS-Only Mode Disabled ✘"


def check_firefox_password_saving(prefs: dict) -> tuple:
    """signon.rememberSignons = false → secure"""
    enabled = prefs.get("signon.rememberSignons", True)
    if not enabled:
        return True, "Password Saving OFF ✔"
    return False, "Password Saving ON ✘"


def check_firefox_autofill(prefs: dict) -> tuple:
    """extensions.formautofill.addresses.enabled = false → secure"""
    addr    = prefs.get("extensions.formautofill.addresses.enabled", True)
    payment = prefs.get("extensions.formautofill.creditCards.enabled", True)
    if not addr and not payment:
        return True, "Autofill OFF ✔"
    return False, f"Autofill ON (addresses={addr}, payments={payment}) ✘"


def get_firefox_extensions(profile_path: Path) -> list:
    """
    Read extensions.json from the Firefox profile to list installed add-ons.
    """
    extensions = []
    ext_file = profile_path / "extensions.json"
    if not ext_file.exists():
        return extensions
    try:
        with open(ext_file, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        addons = data.get("addons", [])
        for addon in addons:
            name    = addon.get("defaultLocale", {}).get("name", addon.get("id", "Unknown"))
            version = addon.get("version", "?")
            active  = addon.get("active", True)
            risky   = _is_risky_extension(name)
            extensions.append({
                "id":      addon.get("id", ""),
                "name":    name,
                "version": version,
                "active":  active,
                "risky":   risky,
            })
    except (json.JSONDecodeError, OSError) as e:
        _warn(f"Could not read Firefox extensions.json: {e}")
    return extensions


# ══════════════════════════════════════════════════════════════════════════════
#  SCAN ORCHESTRATION
# ══════════════════════════════════════════════════════════════════════════════

def scan_browser(browser: str, profile_path: Path) -> dict:
    """
    Run all security checks for a given browser and return a results dict.
    """
    result = {
        "browser":    browser,
        "path":       str(profile_path),
        "https_only": {},
        "passwords":  {},
        "autofill":   {},
        "extensions": [],
        "errors":     [],
    }

    if browser in ("Chrome", "Edge"):
        prefs = read_chromium_preferences(profile_path)
        if not prefs:
            result["errors"].append("Could not read Preferences file.")
            return result

        ok, label = check_chromium_https_only(prefs)
        result["https_only"] = {"secure": ok, "label": label}

        ok, label = check_chromium_password_saving(prefs)
        result["passwords"] = {"secure": ok, "label": label}

        ok, label = check_chromium_autofill(prefs)
        result["autofill"] = {"secure": ok, "label": label}

        result["extensions"] = get_chromium_extensions(profile_path)

    elif browser == "Firefox":
        ff_profile = get_firefox_default_profile(profile_path)
        if not ff_profile:
            result["errors"].append("Could not locate Firefox profile directory.")
            return result
        result["path"] = str(ff_profile)

        prefs = read_firefox_prefs(ff_profile)

        ok, label = check_firefox_https_only(prefs)
        result["https_only"] = {"secure": ok, "label": label}

        ok, label = check_firefox_password_saving(prefs)
        result["passwords"] = {"secure": ok, "label": label}

        ok, label = check_firefox_autofill(prefs)
        result["autofill"] = {"secure": ok, "label": label}

        result["extensions"] = get_firefox_extensions(ff_profile)

    return result


def generate_recommendations(scan_result: dict) -> list:
    """
    Produce a list of actionable recommendation strings from a scan result.
    """
    recommendations = []
    browser = scan_result["browser"]

    if not scan_result["https_only"].get("secure"):
        if browser == "Firefox":
            recommendations.append(
                f"[{browser}] Enable HTTPS-Only Mode: "
                "Settings → Privacy & Security → HTTPS-Only Mode → Enable in all windows."
            )
        else:
            recommendations.append(
                f"[{browser}] Enable HTTPS-Only Mode: "
                "Settings → Privacy and Security → Security → Always use secure connections."
            )

    if not scan_result["passwords"].get("secure"):
        recommendations.append(
            f"[{browser}] Disable built-in password saving and use a dedicated password manager "
            "(e.g., Bitwarden, 1Password). Built-in managers can be accessed by anyone with OS access."
        )

    if not scan_result["autofill"].get("secure"):
        recommendations.append(
            f"[{browser}] Disable Autofill for forms and payment info: "
            "Settings → Autofill → turn off addresses and payment methods."
        )

    risky_exts = [e for e in scan_result["extensions"] if e.get("risky")]
    if risky_exts:
        names = ", ".join(e["name"] for e in risky_exts)
        recommendations.append(
            f"[{browser}] Review or remove potentially risky extensions: {names}. "
            "Extensions have broad access to your browsing data."
        )

    if not recommendations:
        recommendations.append(f"[{browser}] ✅ No critical issues detected. Keep browser and extensions updated.")

    return recommendations


# ══════════════════════════════════════════════════════════════════════════════
#  OUTPUT — CLI TABLES
# ══════════════════════════════════════════════════════════════════════════════

def _warn(msg: str):
    """Print a warning to stderr."""
    print(f"[WARN] {msg}", file=sys.stderr)


def _color(text: str, secure: bool) -> str:
    """ANSI colour-wrap: green for secure, red for insecure (plain fallback)."""
    if RICH_AVAILABLE:
        return text  # Rich handles colours via markup
    GREEN = "\033[92m"
    RED   = "\033[91m"
    RESET = "\033[0m"
    return f"{GREEN if secure else RED}{text}{RESET}"


def print_banner():
    banner = r"""
  ____  ____   ___  _    _ ____  _____ ____     ____  _____ ____ _   _ ____  ___ _______   __
 | __ )|  _ \ / _ \| |  | / ___|| ____|  _ \   / ___|| ____/ ___| | | |  _ \|_ _|_   _\ \ / /
 |  _ \| |_) | | | | |  | \___ \|  _| | |_) |  \___ \|  _|| |   | | | | |_) || |  | |  \ V / 
 | |_) |  _ <| |_| | |/\| |___) | |___|  _ <    ___) | |__| |___| |_| |  _ < | |  | |   | |  
 |____/|_| \_\\___/ |__/\__|____/|_____|_| \_\  |____/|_____\____|\___/|_| \_\___| |_|   |_|  
                                                                                                
    ANALYZER  v1.0         🔒  Detect Insecure Browser Configurations
    """
    if RICH_AVAILABLE:
        console.print(Panel(banner, style="bold cyan", border_style="bright_blue"))
        console.print(
            "[bold yellow]⚠  ETHICS NOTICE:[/bold yellow] "
            "This tool is for [bold]ethical and educational purposes only[/bold]. "
            "Only scan [underline]your own browsers[/underline].\n"
        )
    else:
        print(banner)
        print("⚠  ETHICS NOTICE: This tool is for ethical and educational purposes only.")
        print("   Only scan your own browsers.\n")


def print_summary_table(all_results: list):
    """Print a summary table of all browser checks."""
    if RICH_AVAILABLE:
        table = Table(
            title="🔍 Browser Security Summary",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta",
            border_style="bright_blue",
        )
        table.add_column("Browser",     style="bold cyan",   no_wrap=True)
        table.add_column("HTTPS-Only",  justify="center")
        table.add_column("Pwd Saving",  justify="center")
        table.add_column("Autofill",    justify="center")
        table.add_column("Extensions",  justify="center")
        table.add_column("Risky Exts",  justify="center")

        for r in all_results:
            def cell(d): 
                secure = d.get("secure", False)
                label  = d.get("label", "N/A")
                color  = "green" if secure else "red"
                return Text(label, style=color)

            n_ext   = len(r["extensions"])
            n_risky = len([e for e in r["extensions"] if e.get("risky")])
            risky_cell = Text(str(n_risky), style="red bold" if n_risky else "green")

            table.add_row(
                r["browser"],
                cell(r["https_only"]),
                cell(r["passwords"]),
                cell(r["autofill"]),
                str(n_ext),
                risky_cell,
            )
        console.print(table)
    else:
        # Plain text table
        header = f"{'Browser':<10} {'HTTPS-Only':<35} {'Pwd Saving':<30} {'Autofill':<45} {'Exts':<6} {'Risky'}"
        print("\n" + "=" * len(header))
        print("  BROWSER SECURITY SUMMARY")
        print("=" * len(header))
        print(header)
        print("-" * len(header))
        for r in all_results:
            n_risky = len([e for e in r["extensions"] if e.get("risky")])
            print(
                f"{r['browser']:<10} "
                f"{_color(r['https_only'].get('label','N/A'), r['https_only'].get('secure',False)):<45} "
                f"{_color(r['passwords'].get('label','N/A'), r['passwords'].get('secure',False)):<40} "
                f"{_color(r['autofill'].get('label','N/A'), r['autofill'].get('secure',False)):<55} "
                f"{len(r['extensions']):<6} "
                f"{_color(str(n_risky), n_risky == 0)}"
            )
        print("=" * len(header) + "\n")


def print_extensions_table(browser: str, extensions: list):
    """Print a detailed extensions table for a single browser."""
    if not extensions:
        return

    if RICH_AVAILABLE:
        table = Table(
            title=f"🧩 {browser} Extensions ({len(extensions)} found)",
            box=box.SIMPLE_HEAVY,
            header_style="bold blue",
        )
        table.add_column("Name",    style="white",   max_width=40)
        table.add_column("Version", style="dim",     justify="right")
        table.add_column("Risk",    justify="center")

        for ext in extensions:
            risk_text = Text("⚠ RISKY", style="bold red") if ext.get("risky") else Text("OK", style="green")
            table.add_row(ext.get("name", "?"), ext.get("version", "?"), risk_text)

        console.print(table)
    else:
        print(f"\n  {browser} Extensions ({len(extensions)} found):")
        print(f"  {'Name':<40} {'Version':<12} {'Risk'}")
        print("  " + "-" * 60)
        for ext in extensions:
            risk = _color("RISKY", False) if ext.get("risky") else _color("OK", True)
            print(f"  {ext.get('name','?'):<40} {ext.get('version','?'):<12} {risk}")


def print_recommendations(all_recommendations: list):
    """Print consolidated recommendations."""
    if RICH_AVAILABLE:
        console.print("\n")
        console.rule("[bold yellow]📋 Security Recommendations[/bold yellow]")
        for i, rec in enumerate(all_recommendations, 1):
            style = "green" if "✅" in rec else "yellow"
            console.print(f"  [bold]{i}.[/bold] [{style}]{rec}[/{style}]")
        console.print("")
    else:
        print("\n" + "=" * 70)
        print("  SECURITY RECOMMENDATIONS")
        print("=" * 70)
        for i, rec in enumerate(all_recommendations, 1):
            print(f"  {i}. {rec}")
        print("")


# ══════════════════════════════════════════════════════════════════════════════
#  EXPORT
# ══════════════════════════════════════════════════════════════════════════════

def export_json(all_results: list, all_recs: list, path: str):
    """Export results and recommendations to a JSON file."""
    payload = {
        "scan_time": datetime.now().isoformat(),
        "platform":  PLATFORM,
        "results":   all_results,
        "recommendations": all_recs,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    _print_ok(f"Results exported to JSON: {path}")


def export_txt(all_results: list, all_recs: list, path: str):
    """Export results and recommendations to a plain-text file."""
    lines = [
        "BROWSER SECURITY ANALYZER — REPORT",
        f"Scan Time : {datetime.now().isoformat()}",
        f"Platform  : {PLATFORM}",
        "=" * 60,
        "",
    ]
    for r in all_results:
        lines += [
            f"Browser   : {r['browser']}",
            f"  HTTPS-Only : {r['https_only'].get('label','N/A')}",
            f"  Passwords  : {r['passwords'].get('label','N/A')}",
            f"  Autofill   : {r['autofill'].get('label','N/A')}",
            f"  Extensions : {len(r['extensions'])} installed",
        ]
        for ext in r["extensions"]:
            flag = " [RISKY]" if ext.get("risky") else ""
            lines.append(f"    - {ext.get('name','?')} v{ext.get('version','?')}{flag}")
        lines.append("")

    lines += ["", "RECOMMENDATIONS", "-" * 60]
    for i, rec in enumerate(all_recs, 1):
        lines.append(f"{i}. {rec}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    _print_ok(f"Results exported to TXT: {path}")


def _print_ok(msg: str):
    if RICH_AVAILABLE:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        print(f"✅ {msg}")


# ══════════════════════════════════════════════════════════════════════════════
#  PROGRESS WRAPPER
# ══════════════════════════════════════════════════════════════════════════════

def scan_with_progress(browsers: list, paths: dict) -> list:
    """Scan all browsers with a progress indicator."""
    results = []

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning browsers...", total=len(browsers))
            for browser in browsers:
                progress.update(task, description=f"Scanning [bold cyan]{browser}[/bold cyan]...")
                result = scan_browser(browser, paths[browser])
                results.append(result)
                progress.advance(task)
    else:
        for browser in browsers:
            print(f"  → Scanning {browser}...")
            result = scan_browser(browser, paths[browser])
            results.append(result)

    return results


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="Browser Security Analyzer — Detect insecure browser configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--export-json", metavar="FILE",
        help="Export results to a JSON file (e.g. results.json)"
    )
    parser.add_argument(
        "--export-txt", metavar="FILE",
        help="Export results to a plain-text file (e.g. results.txt)"
    )
    parser.add_argument(
        "--browser", metavar="NAME",
        choices=["Chrome", "Firefox", "Edge"],
        help="Scan only a specific browser"
    )
    parser.add_argument(
        "--no-banner", action="store_true",
        help="Suppress the ASCII banner"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # ── Banner ────────────────────────────────────────────────────────────────
    if not args.no_banner:
        print_banner()

    # ── Detect browsers ───────────────────────────────────────────────────────
    paths    = get_browser_paths()
    detected = detect_installed_browsers(paths)

    if args.browser:
        if args.browser in detected:
            detected = [args.browser]
        else:
            msg = f"Browser '{args.browser}' not found on this system."
            if RICH_AVAILABLE:
                console.print(f"[bold red]❌ {msg}[/bold red]")
            else:
                print(f"❌ {msg}")
            sys.exit(1)

    if not detected:
        msg = "No supported browsers detected on this system."
        if RICH_AVAILABLE:
            console.print(f"[bold red]❌ {msg}[/bold red]")
        else:
            print(f"❌ {msg}")
        sys.exit(0)

    if RICH_AVAILABLE:
        console.print(f"[bold green]✔ Detected browsers:[/bold green] {', '.join(detected)}\n")
    else:
        print(f"✔ Detected browsers: {', '.join(detected)}\n")

    # ── Scan ──────────────────────────────────────────────────────────────────
    all_results = scan_with_progress(detected, paths)

    # ── Print summary ─────────────────────────────────────────────────────────
    print_summary_table(all_results)

    # ── Print extension details ───────────────────────────────────────────────
    for r in all_results:
        print_extensions_table(r["browser"], r["extensions"])

    # ── Recommendations ───────────────────────────────────────────────────────
    all_recs = []
    for r in all_results:
        all_recs.extend(generate_recommendations(r))

    print_recommendations(all_recs)

    # ── Export ────────────────────────────────────────────────────────────────
    if args.export_json:
        export_json(all_results, all_recs, args.export_json)
    if args.export_txt:
        export_txt(all_results, all_recs, args.export_txt)

    # ── Footer ────────────────────────────────────────────────────────────────
    if RICH_AVAILABLE:
        console.rule("[dim]Scan complete — stay secure! 🔐[/dim]")
    else:
        print("─" * 60)
        print("  Scan complete — stay secure! 🔐")
        print("─" * 60)


if __name__ == "__main__":
    main()
