import importlib.util
import http.server
import pathlib
import sys
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("php_critical_scan", ROOT / "php_critical_scan.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class VersionAssessmentTests(unittest.TestCase):
    def test_fixed_thresholds(self):
        cases = {
            "8.2.34": "AFFECTED",
            "8.2.35": "PATCHED",
            "8.3.35": "AFFECTED",
            "8.3.36": "PATCHED",
            "8.4.26": "AFFECTED",
            "8.4.27": "PATCHED",
            "8.5.11": "AFFECTED",
            "8.5.12": "PATCHED",
        }
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(MODULE.assess_version(version).status, expected)

    def test_eol_requires_vendor_verification(self):
        result = MODULE.assess_version("PHP 8.1.33")
        self.assertEqual(result.status, "LIKELY_AFFECTED")
        self.assertTrue(result.vendor_backport_possible)

    def test_php_86_release_candidates(self):
        self.assertEqual(MODULE.assess_version("8.6.0beta3").status, "AFFECTED")
        self.assertEqual(MODULE.assess_version("8.6.0RC3").status, "AFFECTED")
        self.assertEqual(MODULE.assess_version("8.6.0RC4").status, "PATCHED")

    def test_unparseable_version(self):
        self.assertEqual(MODULE.assess_version("PHP version hidden").status, "UNKNOWN")


class FingerprintTests(unittest.TestCase):
    def test_header_version(self):
        version, evidence = MODULE.fingerprint_php([("X-Powered-By", "PHP/8.4.26")], b"")
        self.assertEqual(version, "8.4.26")
        self.assertTrue(evidence)

    def test_cookie_without_value_disclosure(self):
        version, evidence = MODULE.fingerprint_php([("Set-Cookie", "PHPSESSID=secret; Secure")], b"")
        self.assertIsNone(version)
        self.assertIn("A PHPSESSID cookie was observed (value omitted).", evidence)
        self.assertNotIn("secret", " ".join(evidence))

    def test_no_evidence_is_inconclusive(self):
        version, evidence = MODULE.fingerprint_php([("Server", "nginx")], b"hello")
        self.assertIsNone(version)
        self.assertEqual(evidence, [])


class MitigationTests(unittest.TestCase):
    def test_official_partial_mitigations(self):
        ini = {
            "memory_limit": "-1",
            "post_max_size": "32M",
            "upload_max_filesize": "8M",
            "session.upload_progress.enabled": "0",
            "fatal_error_backtraces": "0",
        }
        checks = MODULE.evaluate_mitigations("8.5.11", ini)
        for name, result in checks.items():
            if name != "notice":
                self.assertTrue(result["present"], name)


class UrlIntegrationTests(unittest.TestCase):
    def test_safe_get_detects_vulnerable_header(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Powered-By", "PHP/8.4.26")
                self.send_header("Set-Cookie", "PHPSESSID=do-not-report; HttpOnly")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = f"http://127.0.0.1:{server.server_port}/"
            result = MODULE.scan_url(target, 2.0, False, None, {})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result.status, "AFFECTED")
        self.assertEqual(result.version, "8.4.26")
        self.assertNotIn("do-not-report", " ".join(result.evidence))


if __name__ == "__main__":
    unittest.main()
