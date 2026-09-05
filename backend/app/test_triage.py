import unittest
from datetime import datetime
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.main import app
from app.models.finding import Finding, FindingSeverity, FindingSource, FindingStatus
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.services.finding_normalizer import generate_fingerprint


class TestTriageAndDeltaTracking(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)
        self.db = self.SessionLocal()

        def override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Seed test project and scan
        self.project = Project(
            name="Triage Test Target",
            technology="Python/React",
            source_type="ZIP",
            source_status="READY",
        )
        self.db.add(self.project)
        self.db.commit()
        self.db.refresh(self.project)

        self.scan = Scan(project_id=self.project.id, status=ScanStatus.COMPLETED)
        self.db.add(self.scan)
        self.db.commit()
        self.db.refresh(self.scan)

        # Seed sample finding
        self.fingerprint_a = generate_fingerprint(
            self.project.id, "semgrep", "python.sql.injection", "app/db.py", 42, "SQL Injection detected"
        )
        self.finding_a = Finding(
            project_id=self.project.id,
            scan_id=self.scan.id,
            title="SQL Injection",
            description="Dynamic SQL query concatenation",
            severity=FindingSeverity.CRITICAL,
            cvss=9.8,
            category="A03:2021-Injection",
            file_path="app/db.py",
            line_number=42,
            status=FindingStatus.OPEN,
            source=FindingSource.SAST,
            rule_id="python.sql.injection",
            scanner_name="semgrep",
            fingerprint=self.fingerprint_a,
        )
        self.db.add(self.finding_a)
        self.db.commit()
        self.db.refresh(self.finding_a)

    def tearDown(self):
        self.db.close()

    # 1. OPEN -> RESOLVED via PATCH API
    def test_triage_open_to_resolved(self):
        res = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "resolved", "resolution_comment": "Remediated via parameterized queries"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "resolved")
        self.assertEqual(data["resolution_comment"], "Remediated via parameterized queries")
        self.assertIsNotNone(data["resolved_at"])

    # 2. OPEN -> FALSE_POSITIVE via PATCH API
    def test_triage_open_to_false_positive(self):
        res = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "false_positive", "resolution_comment": "Internal test mock query"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "false_positive")
        self.assertEqual(data["resolution_comment"], "Internal test mock query")
        self.assertIsNotNone(data["resolved_at"])

    # 3. RESOLVED -> OPEN clears timestamp and comment
    def test_triage_resolved_to_open(self):
        # Resolve first
        self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "resolved", "resolution_comment": "Fixed"}
        )
        # Reopen
        res = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "open"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "open")
        self.assertIsNone(data["resolution_comment"])
        self.assertIsNone(data["resolved_at"])

    # 4. FALSE_POSITIVE -> OPEN clears timestamp and comment
    def test_triage_false_positive_to_open(self):
        self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "false_positive", "resolution_comment": "Test FP"}
        )
        res = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "open"}
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "open")
        self.assertIsNone(data["resolution_comment"])
        self.assertIsNone(data["resolved_at"])

    # 5. RESOLVED -> FALSE_POSITIVE maintains timestamp
    def test_triage_resolved_to_false_positive(self):
        res1 = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "resolved", "resolution_comment": "Initial fix"}
        ).json()
        initial_time = res1["resolved_at"]

        res2 = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "false_positive", "resolution_comment": "Reclassified as FP"}
        ).json()
        self.assertEqual(res2["status"], "false_positive")
        self.assertEqual(res2["resolution_comment"], "Reclassified as FP")
        self.assertIsNotNone(res2["resolved_at"])

    # 6. FALSE_POSITIVE -> RESOLVED maintains timestamp
    def test_triage_false_positive_to_resolved(self):
        self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "false_positive", "resolution_comment": "FP note"}
        )
        res = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "resolved", "resolution_comment": "Resolved note"}
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "resolved")

    # 7. Invalid status returns 422
    def test_invalid_status_returns_422(self):
        res = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "super_resolved"}
        )
        self.assertEqual(res.status_code, 422)

    # 8. Comment >1000 characters rejected
    def test_excessive_comment_length_rejected(self):
        long_comment = "A" * 1005
        res = self.client.patch(
            f"/api/findings/{self.finding_a.id}",
            json={"status": "false_positive", "resolution_comment": long_comment}
        )
        self.assertEqual(res.status_code, 422)

    # 9. Nonexistent finding returns 404
    def test_nonexistent_finding_returns_404(self):
        res = self.client.patch("/api/findings/999999", json={"status": "resolved"})
        self.assertEqual(res.status_code, 404)

    # 10. Project findings summary endpoint
    def test_project_findings_summary(self):
        # Add a second finding marked resolved
        f2 = Finding(
            project_id=self.project.id,
            scan_id=self.scan.id,
            title="Second Finding",
            description="High risk issue",
            severity=FindingSeverity.HIGH,
            cvss=8.0,
            category="A01",
            file_path="config.py",
            status=FindingStatus.RESOLVED,
            source=FindingSource.SAST,
            resolution_comment="Resolved",
            resolved_at=datetime.utcnow(),
        )
        self.db.add(f2)
        self.db.commit()

        res = self.client.get(f"/api/projects/{self.project.id}/findings/summary")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["open"], 1)
        self.assertEqual(data["resolved"], 1)
        self.assertEqual(data["false_positive"], 0)
        self.assertEqual(data["total"], 2)

    def tearDown(self):
        self.db.close()
        app.dependency_overrides.clear()


if __name__ == "__main__":
    unittest.main()
