import tempfile
import unittest
from pathlib import Path

from app import create_app


class FirewallAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "RULES_PATH": Path(self.temp_dir.name) / "rules.json"})
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_evaluate_reports_matching_and_default_deny(self):
        response = self.client.post("/api/evaluate", json={"ip": "192.168.1.42"})
        data = response.get_json()
        decisions = {(row["port"], row["protocol"]): row["action"] for row in data["results"]}
        self.assertEqual(response.status_code, 200)
        self.assertEqual(decisions[(443, "TCP")], "ALLOW")
        self.assertEqual(decisions[(5432, "TCP")], "DENY")
        self.assertEqual(decisions[(8080, "TCP")], "DENY")
        self.assertEqual(data["summary"], {"allowed": 3, "denied": 5})

    def test_invalid_ip_is_rejected(self):
        response = self.client.post("/api/evaluate", json={"ip": "not-an-ip"})
        self.assertEqual(response.status_code, 400)

    def test_new_rule_takes_priority_and_can_be_deleted(self):
        created = self.client.post("/api/rules", json={
            "source": "192.168.1.42", "port": 443, "protocol": "TCP", "action": "DENY",
        })
        rule_id = created.get_json()["rule"]["id"]
        decision = self.client.post("/api/evaluate", json={"ip": "192.168.1.42"}).get_json()
        https = next(row for row in decision["results"] if row["port"] == 443)
        self.assertEqual(created.status_code, 201)
        self.assertEqual(https["action"], "DENY")
        self.assertEqual(https["rule_id"], rule_id)
        self.assertEqual(self.client.delete(f"/api/rules/{rule_id}").status_code, 200)

    def test_invalid_rule_is_rejected(self):
        response = self.client.post("/api/rules", json={
            "source": "10.0.0.1", "port": 70000, "protocol": "TCP", "action": "ALLOW",
        })
        self.assertEqual(response.status_code, 400)

    def test_custom_rule_port_is_included_in_inspection(self):
        self.client.post("/api/rules", json={
            "source": "198.51.100.0/24", "port": 9443, "protocol": "TCP", "action": "ALLOW",
            "description": "Custom secure service",
        })
        data = self.client.post("/api/evaluate", json={"ip": "198.51.100.8"}).get_json()
        custom_service = next(row for row in data["results"] if row["port"] == 9443)

        self.assertEqual(custom_service["name"], "Custom service")
        self.assertEqual(custom_service["action"], "ALLOW")


if __name__ == "__main__":
    unittest.main()