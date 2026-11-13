#!/usr/bin/env python3
"""
Git Audit Patrol
Zero-dependency pre-commit hook & repository auditor for secrets and private keys.
Author: Rahul Buriya (rny0007)
License: MIT
"""

import sys
import os
import re
import argparse
import subprocess
from typing import List, Dict, Tuple

# Patterns to scan for sensitive data
SECRET_PATTERNS = [
    ("Private Key Header", re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----")),
    ("GitHub Personal Access Token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key Assignment", re.compile(r"""(?i)aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]""")),
    ("Generic Bearer/JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Slack/Discord Webhook URL", re.compile(r"https://(?:hooks\.slack\.com/services|discord\.com/api/webhooks)/[A-Za-z0-9/_-]+")),
    ("Hardcoded Database Password", re.compile(r"""(?i)(?:db_password|database_password|dbpass)\s*[:=]\s*['"][^'"]{8,}['"]""")),
]

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".zip", ".tar", ".gz", ".7z", ".pdf", ".pyc", ".lock"
}

IGNORE_DIRECTORIES = {
    ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build"
}


def scan_content(text: str, filename: str) -> List[Tuple[str, int, str]]:
    """Scan string content for secrets and return (pattern_name, line_no, masked_line)."""
    findings = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        for name, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                # Mask sensitive portion for safe display
                val = match.group(0)
                masked_val = val[:4] + "*" * min(12, max(4, len(val) - 8)) + val[-4:] if len(val) > 8 else "***"
                display_line = line[:match.start()] + masked_val + line[match.end():]
                findings.append((name, idx, display_line.strip()))
                break
    return findings


def scan_file(filepath: str) -> List[Tuple[str, int, str]]:
    """Scan a single file safely."""
    # Check if file matches forbidden raw files like .env or .key
    basename = os.path.basename(filepath)
    if basename == ".env" or (basename.startswith(".env.") and not basename.endswith(".example")):
        return [("Unencrypted Dotenv File", 1, f"Found production environment file: {basename}")]

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(500_000)  # Max 500KB per file
            return scan_content(content, filepath)
    except Exception as exc:
        return []


def scan_directory(target_dir: str) -> Dict[str, List[Tuple[str, int, str]]]:
    """Recursively scan a directory."""
    all_findings = {}
    for root, dirs, files in os.walk(target_dir):
        # Exclude hidden and vendor dirs
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRECTORIES]
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in IGNORE_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            relpath = os.path.relpath(fpath, target_dir)
            findings = scan_file(fpath)
            if findings:
                all_findings[relpath] = findings
    return all_findings


def scan_git_staged() -> Dict[str, List[Tuple[str, int, str]]]:
    """Scan staged files in git repository for pre-commit hook."""
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        return {}
    staged_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
    all_findings = {}
    for f in staged_files:
        if os.path.exists(f):
            findings = scan_file(f)
            if findings:
                all_findings[f] = findings
    return all_findings


def install_pre_commit_hook():
    """Install git pre-commit hook into current repository."""
    hook_path = os.path.join(".git", "hooks", "pre-commit")
    if not os.path.isdir(os.path.join(".git", "hooks")):
        print("Error: Not a git repository or .git/hooks directory not found.")
        sys.exit(1)

    hook_content = (
        "#!/bin/sh\n"
        "# Git Audit Patrol automated pre-commit hook\n"
        "python audit_patrol.py --pre-commit\n"
    )
    with open(hook_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(hook_content)

    try:
        os.chmod(hook_path, 0o755)
    except Exception:
        pass
    print("✅ Git Audit Patrol pre-commit hook successfully installed at .git/hooks/pre-commit")


def main():
    parser = argparse.ArgumentParser(description="Git Audit Patrol: Secrets & Key Scanner")
    parser.add_argument("path", nargs="?", default=".", help="Directory path to scan")
    parser.add_argument("--pre-commit", action="store_true", help="Run in git pre-commit mode")
    parser.add_argument("--install-hook", action="store_true", help="Install pre-commit hook into .git/hooks")
    args = parser.parse_args()

    if args.install_hook:
        install_pre_commit_hook()
        return

    if args.pre_commit:
        findings = scan_git_staged()
        header = "🛡️  GIT AUDIT PATROL - PRE-COMMIT STAGED SCAN"
    else:
        findings = scan_directory(args.path)
        header = f"🛡️  GIT AUDIT PATROL - DIRECTORY AUDIT ({os.path.abspath(args.path)})"

    print("=" * 65)
    print(header)
    print("=" * 65)

    if not findings:
        print("✅ Clean: No exposed credentials, keys, or unencrypted dotenv files detected.")
        print("=" * 65)
        sys.exit(0)

    total_violations = sum(len(f) for f in findings.values())
    print(f"❌ FAILED: Detected {total_violations} potential secret exposure(s) across {len(findings)} file(s):\n")

    for fpath, issues in findings.items():
        print(f"📄 {fpath}:")
        for name, lineno, line in issues:
            print(f"   [Line {lineno}] {name}: {line}")
        print()

    print("=" * 65)
    print("Action Required: Remove secrets before committing or use environment variables.")
    sys.exit(1)


if __name__ == "__main__":
    main()
