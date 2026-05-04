from pathlib import Path
import tempfile
import unittest

from codeflow.analyzer import analyze_paths


SAMPLE_CODE = """
@app.post("/partners/decision")
def route_partner(partner, payload):
    if partner == "stripe" and payload["status"] == "active":
        validate_customer(payload)
        db.execute("SELECT * FROM customers WHERE partner = 'stripe'")
        requests.post("https://api.stripe.com/v1/charges", json=payload)
        return approve_limit(payload)
    elif partner == "adyen":
        if payload.get("kyc_verified"):
            db.execute("UPDATE payouts SET status = 'queued' WHERE partner = 'adyen'")
            fetch("https://checkout.adyen.com/payments")
            return "accepted"
    return "rejected"
"""


class AnalyzerTests(unittest.TestCase):
    def test_detects_partners_checks_and_apis(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            sample = Path(temp_dir) / "sample.py"
            sample.write_text(SAMPLE_CODE, encoding="utf-8")
            report = analyze_paths([sample]).to_dict()

        self.assertEqual(report["overview"]["files_scanned"], 1)
        self.assertEqual(report["overview"]["partners_found"], 2)
        partner_keys = list(report["partners"].keys())
        self.assertTrue(any("stripe" in k for k in partner_keys))
        self.assertTrue(any("adyen" in k for k in partner_keys))
        self.assertIn("status", report["files"][0]["checks"])
        self.assertIn("kyc", report["files"][0]["checks"])
        self.assertGreaterEqual(len(report["files"][0]["flow_points"]), 3)
        self.assertEqual(report["overview"]["inbound_apis"], 1)
        self.assertEqual(report["overview"]["outbound_apis"], 2)
        self.assertEqual(report["overview"]["database_tables"], 2)
        self.assertEqual(report["overview"]["functions_analyzed"], 1)
        self.assertEqual(report["files"][0]["inbound_apis"][0]["label"], "POST /partners/decision")
        self.assertIn("requests.post", report["files"][0]["outbound_apis"][0]["label"].lower())
        self.assertEqual(report["files"][0]["database_tables"][0]["table"], "customers")
        self.assertEqual(report["files"][0]["functions"][0]["name"], "route_partner")
        self.assertGreaterEqual(len(report["files"][0]["functions"][0]["ordered_steps"]), 5)


if __name__ == "__main__":
    unittest.main()
