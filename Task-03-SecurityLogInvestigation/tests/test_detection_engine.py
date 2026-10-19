"""
Automated Test Suite for Detection Engine & Forensic Pipeline
Task 03 - EdVyro Cybersecurity Internship
"""

import os
import sys
import unittest

# Ensure src/ is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from normalizer import normalize_record, classify_ip, normalize_log_file
from detection_engine import DetectionEngine
from timeline_builder import build_forensic_timeline


class TestSecurityLogInvestigation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.raw_csv = os.path.join(cls.base_dir, "data", "raw_authentication_log.csv")
        cls.normalized_records = normalize_log_file(cls.raw_csv)
        cls.engine = DetectionEngine()

    def test_record_count_and_fields(self):
        """Verifies that all 12 events are properly loaded and normalized with required fields."""
        self.assertEqual(len(self.normalized_records), 12)
        required_keys = [
            "timestamp_iso", "timestamp_epoch", "user_id", "source_ip",
            "subnet", "network_label", "network_zone", "trust_level",
            "event_raw", "event_category", "result_normalized", "device_raw"
        ]
        for r in self.normalized_records:
            for k in required_keys:
                self.assertIn(k, r, f"Missing key {k} in record {r}")

    def test_rfc5737_network_classification(self):
        """Verifies proper mapping of RFC 5737 documentation subnets."""
        ip1 = classify_ip("192.0.2.18")
        self.assertEqual(ip1["network_label"], "TEST-NET-1")
        self.assertEqual(ip1["trust_level"], "Trusted")

        ip2 = classify_ip("198.51.100.27")
        self.assertEqual(ip2["network_label"], "TEST-NET-2")
        self.assertIn("External", ip2["network_zone"])

        ip3 = classify_ip("203.0.113.42")
        self.assertEqual(ip3["network_label"], "TEST-NET-3")
        self.assertEqual(ip3["trust_level"], "Hostile / Suspect")

    def test_rule01_brute_force_detection(self):
        """Verifies Rule 01 accurately detects targeted brute force on stu-117."""
        alerts = self.engine.detect_targeted_brute_force(self.normalized_records)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "RULE-01-BRUTE-FORCE")
        self.assertIn("stu-117", alert.target_accounts)
        self.assertIn("198.51.100.27", alert.source_ips)
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(len(alert.evidence), 3)

    def test_rule02_password_spraying_detection(self):
        """Verifies Rule 02 detects horizontal password spraying from 203.0.113.42."""
        alerts = self.engine.detect_password_spraying(self.normalized_records)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "RULE-02-PASSWORD-SPRAY")
        self.assertIn("203.0.113.42", alert.source_ips)
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(len(alert.target_accounts), 4)
        for expected_user in ["stu-209", "stu-311", "stu-415", "stu-502"]:
            self.assertIn(expected_user, alert.target_accounts)

    def test_rule03_unusual_access_detection(self):
        """Verifies Rule 03 detects anomalous successful login for sprayed user stu-311."""
        spray_alerts = self.engine.detect_password_spraying(self.normalized_records)
        alerts = self.engine.detect_unusual_access(self.normalized_records, spray_alerts)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "RULE-03-UNUSUAL-ACCESS")
        self.assertIn("stu-311", alert.target_accounts)
        self.assertIn("192.0.2.99", alert.source_ips)

    def test_benign_traffic_no_false_positives(self):
        """Ensures benign user stu-104 does not trigger brute force or spraying alerts."""
        all_alerts = self.engine.run_all_detections(self.normalized_records)
        for alert in all_alerts:
            self.assertNotIn("stu-104", alert.target_accounts)
            self.assertNotIn("192.0.2.18", alert.source_ips)

    def test_timeline_evidence_vs_assumptions_structure(self):
        """Verifies that all 12 timeline items separate empirical evidence from assumptions."""
        timeline = build_forensic_timeline(self.normalized_records)
        self.assertEqual(len(timeline), 12)
        for item in timeline:
            self.assertTrue(len(item["empirical_evidence"]) > 0)
            self.assertTrue(len(item["analytical_assumptions"]) > 0)
            self.assertTrue(len(item["defensive_outcome"]) > 0)


if __name__ == "__main__":
    unittest.main()
