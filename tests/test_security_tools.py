import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import security_tools
from backend.sanitize import sanitize_body, sanitize_headers, sanitize_url


class SanitizationTests(unittest.TestCase):
    def test_url_credentials_and_secret_query_are_removed(self):
        safe = sanitize_url("https://alice:password@example.test/items?api_token=abc&view=full")
        self.assertNotIn("alice", safe)
        self.assertNotIn("password", safe)
        self.assertNotIn("abc", safe)
        self.assertIn("REDACTED", safe)
        self.assertIn("view=full", safe)

    def test_set_cookie_value_is_redacted_but_flags_remain(self):
        headers = sanitize_headers([("Set-Cookie", "sessionid=supersecret; Path=/; Secure; HttpOnly; SameSite=Lax")])
        value = headers[0][1]
        self.assertIn("sessionid=[REDACTED]", value)
        self.assertNotIn("supersecret", value)
        self.assertIn("Secure", value)
        self.assertIn("HttpOnly", value)
        self.assertIn("SameSite=Lax", value)

    def test_json_secret_values_are_redacted(self):
        safe = sanitize_body('{"username":"sam","access_token":"do-not-store"}', "application/json")
        self.assertIn("[REDACTED]", safe)
        self.assertNotIn("do-not-store", safe)
        self.assertIn("sam", safe)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.scope_patch = patch.object(security_tools, "SCOPE_PATH", self.directory / "scope.json")
        self.data_patch = patch.object(security_tools, "DATA_DIR", self.directory)
        self.scope_patch.start()
        self.data_patch.start()

    def tearDown(self):
        self.scope_patch.stop()
        self.data_patch.stop()
        self.temp.cleanup()

    def test_hosts_are_normalized_and_deduplicated(self):
        self.assertEqual(security_tools.add_scope_host(" LOCALHOST "), ["localhost"])
        self.assertEqual(security_tools.add_scope_host("localhost"), ["localhost"])
        self.assertTrue(security_tools.host_in_scope("localhost"))
        self.assertFalse(security_tools.host_in_scope("127.0.0.1"))
        self.assertEqual(security_tools.remove_scope_host("localhost"), [])
        self.assertFalse(security_tools.host_in_scope("localhost"))

    def test_wildcards_and_urls_are_rejected(self):
        for value in ("*.example.com", "https://example.com", "example.com/path", "user@example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                security_tools.normalize_host(value)


class PassiveScannerTests(unittest.TestCase):
    def test_detects_missing_html_headers_and_cookie_flags_without_leaking_cookie(self):
        rows = [{
            "id": "flow-1",
            "scheme": "https",
            "host": "lab.example.test",
            "path": "/",
            "response_status": 200,
            "content_type": "text/html; charset=utf-8",
            "response_headers": json.dumps([
                ["Set-Cookie", "sid=private-value; Path=/"],
                ["Server", "example-server/1.0"],
            ]),
        }]
        findings = security_tools.analyze_history(rows)
        rules = {finding["rule"] for finding in findings}
        self.assertIn("missing-hsts", rules)
        self.assertIn("missing-csp", rules)
        self.assertIn("cookie-no-secure", rules)
        self.assertIn("cookie-no-httponly", rules)
        self.assertIn("cookie-no-samesite", rules)
        self.assertNotIn("private-value", json.dumps(findings))


if __name__ == "__main__":
    unittest.main()
