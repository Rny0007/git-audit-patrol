"""
Unit tests for Git Audit Patrol scanner.
"""

import unittest
from audit_patrol import scan_content


class TestGitAuditPatrol(unittest.TestCase):
    def test_clean_content(self):
        code = (
            "import os\n"
            "DB_PORT = 5432\n"
            "HOST = '127.0.0.1'\n"
            "USER = os.getenv('DB_USER')\n"
        )
        findings = scan_content(code, "config.py")
        self.assertEqual(len(findings), 0)

    def test_detect_private_key_header(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA..."
        findings = scan_content(text, "server.key")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "Private Key Header")

    def test_detect_aws_key(self):
        code = "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        findings = scan_content(code, "deploy.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "AWS Access Key ID")

    def test_detect_github_token(self):
        code = "TOKEN = 'ghp_1234567890abcdefghijklmnopqrstuvwxyza'"
        findings = scan_content(code, "script.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], "GitHub Personal Access Token")


if __name__ == "__main__":
    unittest.main()
