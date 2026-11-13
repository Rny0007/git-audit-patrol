# Git Audit Patrol 🛡️

A zero-dependency command-line utility and Git pre-commit hook that prevents accidental leakage of API keys, tokens, private keys, and unencrypted environment files.

---

## Why Git Audit Patrol?

Committing secrets to public or shared repositories can lead to compromised infrastructure and data leaks. Git Audit Patrol acts as a lightweight security gate that scans staged code or entire directories before code is committed or pushed.

---

## Features

- **Sensitive Pattern Detection**:
  - RSA, OpenSSH, and EC private key headers
  - GitHub Personal Access Tokens (`ghp_`, `gho_`, etc.)
  - AWS Access Key IDs and secret assignment strings
  - Bearer and JWT token patterns
  - Webhook URLs (Slack, Discord)
  - Hardcoded database passwords
  - Unencrypted `.env` files committed without an `.example` suffix
- **Zero External Dependencies**: Pure Python 3 using standard library modules.
- **Git Hook Integration**: Can be installed as a `.git/hooks/pre-commit` hook with a single command.
- **Safe Output**: Masks sensitive values in terminal output to avoid displaying plaintext secrets in logs.

---

## Installation & Usage

### 1. Run as a Standalone Directory Scanner
```sh
# Clone the repository
git clone https://github.com/Rny0007/git-audit-patrol.git
cd git-audit-patrol

# Scan current directory
python audit_patrol.py .

# Scan another folder
python audit_patrol.py /path/to/project
```

### 2. Install as a Git Pre-Commit Hook
Run inside any Git repository to install the hook:
```sh
python /path/to/git-audit-patrol/audit_patrol.py --install-hook
```
Whenever `git commit` is executed, Git Audit Patrol will scan all staged files and abort the commit if secrets are discovered.

---

## Running Tests

```sh
python -m unittest test_audit_patrol.py
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

Developed by **Rahul Buriya ([@rny0007](https://github.com/rny0007))**.
