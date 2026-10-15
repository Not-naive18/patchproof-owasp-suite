"""
PatchProof AI Regression Test Suite - Python
Verifies that functional behavior remains intact while confirming vulnerability remediation.
Supports both unittest (built-in) and pytest.
"""
import unittest
import json
import base64
from app_patched import app as patched_app
from app_vulnerable import app as vulnerable_app

class TestPatchProofRegression(unittest.TestCase):

    def setUp(self):
        patched_app.config["TESTING"] = True
        vulnerable_app.config["TESTING"] = True
        self.patched = patched_app.test_client()
        self.vulnerable = vulnerable_app.test_client()

    # -------------------------------------------------------------
    # Regression Test 1: Product Search Functionality Preservation
    # -------------------------------------------------------------
    def test_product_search_functional_integrity(self):
        """
        Ensure normal search queries continue to return legitimate data with exact response schema.
        """
        res = self.patched.get("/api/products/search?category=hardware")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["count"], 2)
        names = [p["name"] for p in data["products"]]
        self.assertIn("Secure Laptop", names)
        self.assertIn("Encrypted USB", names)

    # -------------------------------------------------------------
    # Regression Test 2: SQL Injection Remediation Proof
    # -------------------------------------------------------------
    def test_sqli_attack_mitigated(self):
        """
        Demonstrate that SQL injection payload fails on patched endpoint, but leaked all data in vulnerable version.
        """
        sqli_payload = "' OR '1'='1"

        # Vulnerable leaks all 3 products regardless of category
        vuln_res = self.vulnerable.get(f"/api/products/search?category={sqli_payload}")
        self.assertEqual(vuln_res.status_code, 200)
        vuln_data = vuln_res.get_json()
        self.assertEqual(vuln_data["count"], 3)  # Exploit succeeded in vulnerable version!

        # Patched returns 0 products because literal string is queried
        patch_res = self.patched.get(f"/api/products/search?category={sqli_payload}")
        self.assertEqual(patch_res.status_code, 200)
        patch_data = patch_res.get_json()
        self.assertEqual(patch_data["count"], 0)  # Exploit neutralized!

    # -------------------------------------------------------------
    # Regression Test 3: Access Control Enforcement
    # -------------------------------------------------------------
    def test_access_control_protected(self):
        # Unauthenticated request must be rejected
        unauth_res = self.patched.get("/admin/users")
        self.assertEqual(unauth_res.status_code, 403)

        # Authorized request succeeds
        auth_res = self.patched.get("/admin/users", headers={"Authorization": "Bearer admin-secret-token"})
        self.assertEqual(auth_res.status_code, 200)
        data = auth_res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["users"]), 2)

    # -------------------------------------------------------------
    # Regression Test 4: Safe Session Token Deserialization
    # -------------------------------------------------------------
    def test_session_loading_integrity(self):
        valid_payload = {"user_id": 42, "role": "member"}
        b64 = base64.b64encode(json.dumps(valid_payload).encode()).decode()

        res = self.patched.post("/api/session/load", json={"session_token": b64})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["session"]["user_id"], 42)

if __name__ == "__main__":
    unittest.main()
