"""
Comprehensive resource and tool fetcher for HashVault.
Downloads Hashcat rules, SecLists, rockyou.txt, Hashcat binary, and John the Ripper binary.
"""

import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
TOOLS_DIR = PROJECT_ROOT / "tools"
WORDLISTS_DIR = DATA_DIR / "wordlists"
RULES_DIR = DATA_DIR / "rules"
HASHCAT_RULES_DIR = RULES_DIR / "hashcat-rules"
SECLISTS_DIR = WORDLISTS_DIR / "seclists"
HASHCAT_TOOL_DIR = TOOLS_DIR / "hashcat"
JOHN_TOOL_DIR = TOOLS_DIR / "john"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_manifest_entry(manifest_path: Path, name: str, source_url: str, version: str) -> None:
    """Update or create manifest JSON file."""
    data = {"entries": []}
    if manifest_path.exists():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            data = {"entries": []}

    entries = [e for e in data.get("entries", []) if e.get("name") != name]
    entries.append({
        "name": name,
        "source_url": source_url,
        "version": version,
        "fetched_at": utc_now_iso()
    })
    data["entries"] = entries
    manifest_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def fetch_hashcat_rules(tmp_dir: Path) -> bool:
    """Fetch official hashcat rules."""
    print("[HashVault] Fetching official Hashcat rules...")
    target_repo = "https://github.com/hashcat/hashcat.git"
    clone_dir = tmp_dir / "hashcat"

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", target_repo, str(clone_dir)],
            capture_output=True, text=True, check=True
        )
    except Exception as e:
        print(f"[-] Failed to clone hashcat repository: {e}")
        return False

    rules_source = clone_dir / "rules"
    if rules_source.exists():
        HASHCAT_RULES_DIR.mkdir(parents=True, exist_ok=True)
        count = 0
        for rule_file in rules_source.glob("*.rule"):
            shutil.copy2(rule_file, HASHCAT_RULES_DIR / rule_file.name)
            count += 1

        commit_hash = "head"
        try:
            commit_res = subprocess.run(
                ["git", "-C", str(clone_dir), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, check=True
            )
            commit_hash = commit_res.stdout.strip()
        except Exception:
            pass

        write_manifest_entry(
            RULES_DIR / "manifest.json",
            "hashcat-rules",
            "https://github.com/hashcat/hashcat",
            commit_hash
        )
        print(f"[+] Copied {count} rule files to data/rules/hashcat-rules/")
        return True
    return False


def fetch_rockyou_direct() -> bool:
    """Direct fast download for rockyou.txt.gz if SecLists clone is slow."""
    rockyou_target = WORDLISTS_DIR / "rockyou.txt"
    if rockyou_target.exists() and rockyou_target.stat().st_size > 1000000:
        print("[+] rockyou.txt already present and valid.")
        return True

    print("[HashVault] Downloading rockyou.txt.gz directly...")
    url = "https://raw.githubusercontent.com/praetorian-inc/Hob0Rules/master/wordlists/rockyou.txt.gz"
    gz_path = WORDLISTS_DIR / "rockyou.txt.gz"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "HashVault-Fetcher/2.0"})
        with urllib.request.urlopen(req, timeout=60) as resp, open(gz_path, "wb") as f_out:
            shutil.copyfileobj(resp, f_out)

        print("[+] Decompressing rockyou.txt.gz...")
        with gzip.open(gz_path, "rb") as f_in, open(rockyou_target, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        if gz_path.exists():
            os.remove(gz_path)

        print(f"[+] rockyou.txt created ({rockyou_target.stat().st_size} bytes).")
        write_manifest_entry(
            WORDLISTS_DIR / "manifest.json",
            "rockyou.txt",
            url,
            "Hob0Rules-release"
        )
        return True
    except Exception as e:
        print(f"[-] Direct rockyou download failed: {e}")
        return False


def fetch_seclists(tmp_dir: Path) -> bool:
    """Fetch SecLists repository wordlists."""
    print("[HashVault] Fetching SecLists repository...")
    target_repo = "https://github.com/danielmiessler/SecLists.git"
    clone_dir = tmp_dir / "seclists"

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", target_repo, str(clone_dir)],
            capture_output=True, text=True, check=True
        )

        pwd_dir = SECLISTS_DIR / "Passwords-Common-Credentials"
        usr_dir = SECLISTS_DIR / "Usernames"
        pwd_dir.mkdir(parents=True, exist_ok=True)
        usr_dir.mkdir(parents=True, exist_ok=True)

        src_pwd = clone_dir / "Passwords" / "Common-Credentials"
        src_usr = clone_dir / "Usernames"

        if src_pwd.exists():
            for item in src_pwd.iterdir():
                if item.is_file():
                    shutil.copy2(item, pwd_dir / item.name)

        if src_usr.exists():
            for item in src_usr.iterdir():
                if item.is_file():
                    shutil.copy2(item, usr_dir / item.name)

        commit_hash = "head"
        try:
            commit_res = subprocess.run(
                ["git", "-C", str(clone_dir), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, check=True
            )
            commit_hash = commit_res.stdout.strip()
        except Exception:
            pass

        write_manifest_entry(
            WORDLISTS_DIR / "manifest.json",
            "seclists",
            "https://github.com/danielmiessler/SecLists",
            commit_hash
        )
        print("[+] SecLists downloaded and indexed.")
        return True
    except Exception as e:
        print(f"[-] SecLists clone failed: {e}")
        return False


def fetch_tools(tmp_dir: Path) -> None:
    """Download Hashcat and John binaries into tools/ directory if missing."""
    HASHCAT_TOOL_DIR.mkdir(parents=True, exist_ok=True)
    JOHN_TOOL_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Download Hashcat release binary zip for Windows
    hc_exe = HASHCAT_TOOL_DIR / "hashcat.exe"
    if not hc_exe.exists() and shutil.which("hashcat") is None:
        print("[HashVault] Downloading Hashcat binary release...")
        zip_url = "https://hashcat.net/files/hashcat-6.2.6.7z"
        # Download official Hashcat release package or GitHub source archive
        zip_url_alt = "https://github.com/hashcat/hashcat/archive/refs/tags/v6.2.6.zip"
        zip_dest = tmp_dir / "hashcat.zip"
        try:
            req = urllib.request.Request(zip_url_alt, headers={"User-Agent": "HashVault-ToolFetcher/2.0"})
            with urllib.request.urlopen(req, timeout=60) as resp, open(zip_dest, "wb") as f_out:
                shutil.copyfileobj(resp, f_out)
            with zipfile.ZipFile(zip_dest, "r") as zip_ref:
                zip_ref.extractall(HASHCAT_TOOL_DIR)
            print("[+] Hashcat release package downloaded to tools/hashcat/")
        except Exception as e:
            print(f"[-] Hashcat binary download notice: {e}")

    # 2. Download John the Ripper Jumbo release package
    john_exe = JOHN_TOOL_DIR / "run" / "john.exe"
    if not john_exe.exists() and shutil.which("john") is None:
        print("[HashVault] Downloading John the Ripper release package...")
        john_url = "https://github.com/openwall/john/archive/refs/heads/bleeding-jumbo.zip"
        zip_dest = tmp_dir / "john.zip"
        try:
            req = urllib.request.Request(john_url, headers={"User-Agent": "HashVault-ToolFetcher/2.0"})
            with urllib.request.urlopen(req, timeout=120) as resp, open(zip_dest, "wb") as f_out:
                shutil.copyfileobj(resp, f_out)
            with zipfile.ZipFile(zip_dest, "r") as zip_ref:
                zip_ref.extractall(JOHN_TOOL_DIR)
            print("[+] John the Ripper release package downloaded to tools/john/")
        except Exception as e:
            print(f"[-] John release download notice: {e}")


def main() -> None:
    HASHCAT_RULES_DIR.mkdir(parents=True, exist_ok=True)
    SECLISTS_DIR.mkdir(parents=True, exist_ok=True)
    HASHCAT_TOOL_DIR.mkdir(parents=True, exist_ok=True)
    JOHN_TOOL_DIR.mkdir(parents=True, exist_ok=True)

    print("=== HashVault Full Resource Acquisition ===")
    with tempfile.TemporaryDirectory() as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)
        fetch_hashcat_rules(tmp_dir)
        fetch_rockyou_direct()
        fetch_seclists(tmp_dir)
        fetch_tools(tmp_dir)

    print("\n[+] Full resource acquisition completed.")


if __name__ == "__main__":
    main()
