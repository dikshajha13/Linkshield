"""Run from the project folder:  python -m unittest discover -s tests -v"""
import os, sys, tempfile, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import analyzer
from app import create_app


def ids(result):
    return {i["id"] for i in result["indicators"]}


class AnalyzerTests(unittest.TestCase):
    def test_empty_and_whitespace(self):
        for bad in ("", "   ", None, 123):
            with self.assertRaises(analyzer.ValidationError):
                analyzer.analyze_url(bad)

    def test_malformed(self):
        for bad in ("hello world", "example.com", "ftp://example.com", "javascript:alert(1)",
                    "http://", "http://localhost", "http://exa..mple.com", "http://example.com:99999",
                    "https://exa mple.com", "http://[::1", "http://-bad-.com", "http://example.123"):
            with self.subTest(bad=bad), self.assertRaises(analyzer.ValidationError):
                analyzer.analyze_url(bad)

    def test_normal_https_is_low_and_clean(self):
        r = analyzer.analyze_url("https://example.com")
        self.assertEqual((r["score"], r["level"], r["indicators"]), (0, "low", []))
        self.assertTrue(r["positives"])

    def test_http_alone_is_low(self):
        r = analyzer.analyze_url("http://example.com/about")
        self.assertEqual(ids(r), {"no_https"})
        self.assertEqual(r["level"], "low")

    def test_ip_url(self):
        r = analyzer.analyze_url("http://192.168.4.20/verify")
        self.assertIn("ip_host", ids(r))
        self.assertEqual(r["level"], "medium")

    def test_obfuscated_ip(self):
        self.assertIn("obfuscated_ip", ids(analyzer.analyze_url("http://3232235777/")))

    def test_excessive_subdomains(self):
        self.assertIn("subdomains_many", ids(analyzer.analyze_url("https://a.b.c.d.example.com")))
        self.assertNotIn("subdomains_many", ids(analyzer.analyze_url("https://www.bbc.co.uk")))

    def test_at_symbol(self):
        r = analyzer.analyze_url("https://paypal.com@example.net/signin")
        self.assertIn("userinfo_at", ids(r))
        self.assertEqual(r["host"], "example.net")

    def test_punycode(self):
        self.assertIn("punycode", ids(analyzer.analyze_url("https://xn--pple-43d.example.com")))
        self.assertIn("punycode", ids(analyzer.analyze_url("https://аррӏе.com")))  # real unicode

    def test_very_long_url(self):
        r = analyzer.analyze_url("https://example.com/" + "a" * 250)
        self.assertIn("very_long_url", ids(r))
        with self.assertRaises(analyzer.ValidationError):
            analyzer.analyze_url("https://example.com/" + "a" * 3000)

    def test_encoded_patterns(self):
        r = analyzer.analyze_url("https://example.com/go?next=%252e%252e%2F%3Cscript%3E")
        self.assertTrue({"encoding_double", "encoding_dangerous"} <= ids(r))

    def test_brand_and_lookalike(self):
        self.assertIn("brand_impersonation", ids(analyzer.analyze_url("https://paypal.secure-login.example.com")))
        self.assertIn("lookalike", ids(analyzer.analyze_url("https://paypa1.com")))
        self.assertEqual(analyzer.analyze_url("https://www.google.com")["indicators"], [])
        self.assertNotIn("brand_impersonation", ids(analyzer.analyze_url("https://s3.amazonaws.com")))

    def test_shortener_port_redirect(self):
        self.assertIn("shortener", ids(analyzer.analyze_url("https://bit.ly/x")))
        self.assertIn("unusual_port", ids(analyzer.analyze_url("https://example.com:8081/")))
        self.assertIn("redirect_param", ids(analyzer.analyze_url("https://example.com/r?url=https://other.com")))

    def test_single_weak_signal_never_high_and_stacking_is_high(self):
        for u in ("http://example.com", "https://example.com:9000", "https://example.xyz/" + "a" * 120):
            self.assertNotEqual(analyzer.analyze_url(u)["level"], "high")
        r = analyzer.analyze_url("http://paypal.com@192.168.1.5:8080/login")
        self.assertEqual(r["level"], "high")
        self.assertLessEqual(r["score"], 100)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "t.db")
        self.client = create_app(self.db).test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def scan(self, url):
        return self.client.post("/api/scan", json={"url": url})

    def test_pages_render(self):
        for path in ("/", "/history"):
            self.assertEqual(self.client.get(path).status_code, 200)

    def test_bad_requests(self):
        self.assertEqual(self.scan("").status_code, 400)
        self.assertEqual(self.scan("not a url").status_code, 400)
        self.assertEqual(self.client.post("/api/scan", data="x", content_type="text/plain").status_code, 400)
        self.assertEqual(self.client.post("/api/scan", json=["a"]).status_code, 400)
        self.assertEqual(self.client.post("/api/scan", json={"url": "a" * 20000}).status_code, 413)
        body = self.scan("").get_json()
        self.assertFalse(body["ok"]); self.assertIn("error", body)

    def test_multiple_scans_history_view_clear(self):
        for u in ("https://example.com", "http://192.168.1.1/x", "https://a.b.c.d.example.com"):
            self.assertEqual(self.scan(u).status_code, 200)
        scans = self.client.get("/api/history").get_json()["scans"]
        self.assertEqual([s["url"] for s in scans][0], "https://a.b.c.d.example.com")  # newest first
        self.assertEqual(len(scans), 3)
        one = self.client.get(f"/api/history/{scans[1]['id']}").get_json()
        self.assertEqual(one["scan"]["result"]["url"], "http://192.168.1.1/x")
        self.assertEqual(self.client.get("/api/history/9999").status_code, 404)
        self.assertEqual(self.client.delete("/api/history").get_json()["deleted"], 3)
        self.assertEqual(self.client.get("/api/history").get_json()["scans"], [])

    def test_history_persists_after_restart(self):
        self.scan("https://example.com/persist")
        fresh_client = create_app(self.db).test_client()  # new app object = "restarted server"
        urls = [s["url"] for s in fresh_client.get("/api/history").get_json()["scans"]]
        self.assertEqual(urls, ["https://example.com/persist"])

    def test_sql_injection_text_is_stored_safely(self):
        self.assertEqual(self.scan("https://example.com/?q=1');DROP/**/TABLE/**/scans;--").status_code, 200)
        self.assertEqual(len(self.client.get("/api/history").get_json()["scans"]), 1)


if __name__ == "__main__":
    unittest.main()
