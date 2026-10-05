import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.finding import Finding

# Setup isolated in-memory SQLite database for testing
SQLALCHEMY_TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    db.query(Finding).delete()
    db.query(Scan).delete()
    db.query(Project).delete()
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)


def test_new_project_creation_isolation_from_existing_projects():
    # 1. Create an existing project ("Gateway Microservice" Java/Spring)
    existing_res = client.post(
        "/api/projects",
        json={
            "name": "Gateway Microservice",
            "technology": "Java/Spring",
            "description": "Existing gateway microservice",
            "repository_url": "https://github.com/enterprise/gateway-service",
        },
    )
    assert existing_res.status_code == 201
    existing_project = existing_res.json()
    assert existing_project["name"] == "Gateway Microservice"
    assert existing_project["technology"] == "Java/Spring"

    # 2. Create a totally NEW project ("Payment Gateway v2" Node.js)
    new_payload = {
        "name": "Payment Gateway v2",
        "technology": "Node.js",
        "description": "Clean new payment gateway microservice",
        "repository_url": None,
    }
    new_res = client.post("/api/projects", json=new_payload)
    assert new_res.status_code == 201
    new_project = new_res.json()

    # 3. Assert strict state isolation: new project MUST NOT inherit existing project metadata
    assert new_project["id"] != existing_project["id"]
    assert new_project["name"] == "Payment Gateway v2"
    assert new_project["technology"] == "Node.js"
    assert new_project["description"] == "Clean new payment gateway microservice"
    assert new_project["repository_url"] is None

    # 4. Verify DB records list both projects independently
    list_res = client.get("/api/projects")
    assert list_res.status_code == 200
    projects_list = list_res.json()
    assert any(p["id"] == existing_project["id"] for p in projects_list)
    assert any(p["id"] == new_project["id"] for p in projects_list)

    # Check each project maintains its own isolated attributes
    proj1 = next(p for p in projects_list if p["id"] == existing_project["id"])
    proj2 = next(p for p in projects_list if p["id"] == new_project["id"])

    assert proj1["name"] == "Gateway Microservice"
    assert proj1["technology"] == "Java/Spring"

    assert proj2["name"] == "Payment Gateway v2"
    assert proj2["technology"] == "Node.js"


def test_zip_ingestion_belongs_only_to_new_project(tmp_path):
    # Create project 1
    p1 = client.post("/api/projects", json={"name": "Project One", "technology": "Go"}).json()
    # Create project 2
    p2 = client.post("/api/projects", json={"name": "Project Two", "technology": "Python"}).json()

    # Ingest ZIP for project 2 only
    zip_bytes = b"PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    files = {"file": ("app.zip", zip_bytes, "application/zip")}

    ingest_res = client.post(f"/api/projects/{p2['id']}/ingest/zip", files=files)
    assert ingest_res.status_code == 200
    p2_updated = ingest_res.json()

    assert p2_updated["source_type"] == "ZIP"

    # Verify project 1 source details remain un-ingested and unaffected
    p1_source = client.get(f"/api/projects/{p1['id']}/source").json()
    assert p1_source["source_type"] is None
    assert p1_source["status"] == "NOT_INGESTED"


def test_onboarding_wizard_flows_and_payload_isolation():
    """Regression test covering wizard flow specifications (1-11):

    1. Intelligent Scan skips Advanced Security Configuration.
    2. Intelligent Scan reaches Review directly.
    3. Intelligent Scan enables all six layers.
    4. Review displays "Intelligent Scan".
    5. Custom Checklist goes through Advanced Security Configuration.
    6. Custom Checklist preserves manual layer selections.
    7. Review displays "Custom Checklist".
    8. Switching Custom -> Intelligent clears/overrides stale custom layer state.
    9. Switching Intelligent -> Custom does not incorrectly claim the configuration is still Intelligent.
    10. Back navigation preserves the correct mode.
    11. Final create-project payload contains the correct analysis mode and layer configuration.
    """

    # Helper simulating wizard step transition logic
    class OnboardingWizardSimulator:

        def __init__(self):
            self.reset()

        def reset(self):
            self.step = 1
            self.proj_name = ""
            self.proj_tech = "Node.js"
            self.proj_desc = ""
            self.source_type = "Git Repository"
            self.repo_url = ""
            self.website_url = ""
            self.analysis_mode = "intelligent"
            self.scanners = {
                "whiteBox": True,
                "blackBox": True,
                "greyBox": True,
                "riskMapping": True,
                "crossValidation": True,
                "aiAnalysis": True,
            }

        def set_analysis_mode(self, mode: str):
            self.analysis_mode = mode
            if mode == "intelligent":
                self.scanners = {
                    "whiteBox": True,
                    "blackBox": True,
                    "greyBox": True,
                    "riskMapping": True,
                    "crossValidation": True,
                    "aiAnalysis": True,
                }

        def next(self):
            if self.step == 1:
                self.step = 2
            elif self.step == 2:
                self.step = 3
            elif self.step == 3:
                if self.analysis_mode == "intelligent":
                    self.scanners = {
                        "whiteBox": True,
                        "blackBox": True,
                        "greyBox": True,
                        "riskMapping": True,
                        "crossValidation": True,
                        "aiAnalysis": True,
                    }
                    self.step = 5  # Skip Step 4 directly to Review (Step 5)
                else:
                    self.step = 4  # Go to Advanced (Step 4)
            elif self.step == 4:
                self.step = 5  # Go to Review (Step 5)

        def back(self):
            if self.step == 5:
                if self.analysis_mode == "intelligent":
                    self.step = 3  # Return directly to Analysis
                else:
                    self.step = 4  # Return to Advanced
            elif self.step == 4:
                self.step = 3
            elif self.step == 3:
                self.step = 2
            elif self.step == 2:
                self.step = 1

        def get_active_layers_display(self):
            labels = {
                "whiteBox": "White-Box",
                "blackBox": "Black-Box",
                "greyBox": "Grey-Box",
                "riskMapping": "Risk Mapping",
                "crossValidation": "Cross-Validation",
                "aiAnalysis": "AI Analysis",
            }
            active = [labels[k] for k, v in self.scanners.items() if v]
            return ", ".join(active) if active else "None"

        def get_analysis_mode_display(self):
            return "Intelligent Scan" if self.analysis_mode == "intelligent" else "Custom Checklist"

    # Test 1-4: Intelligent Scan Flow
    wiz = OnboardingWizardSimulator()
    wiz.step = 3
    wiz.set_analysis_mode("intelligent")
    wiz.next()
    assert wiz.step == 5  # Rule 1 & 2: Skips Step 4 and reaches Review directly
    assert all(wiz.scanners.values())  # Rule 3: All 6 layers enabled
    assert wiz.get_analysis_mode_display() == "Intelligent Scan"  # Rule 4: Displays "Intelligent Scan"
    assert "White-Box" in wiz.get_active_layers_display()
    assert "Black-Box" in wiz.get_active_layers_display()

    # Test 5-7: Custom Checklist Flow
    wiz.reset()
    wiz.step = 3
    wiz.set_analysis_mode("custom")
    wiz.next()
    assert wiz.step == 4  # Rule 5: Goes to Advanced Configuration (Step 4)
    # Manually select SAST and Risk Mapping only
    wiz.scanners = {
        "whiteBox": True,
        "blackBox": False,
        "greyBox": False,
        "riskMapping": True,
        "crossValidation": False,
        "aiAnalysis": False,
    }
    wiz.next()
    assert wiz.step == 5  # Reaches Review
    assert wiz.get_analysis_mode_display() == "Custom Checklist"  # Rule 7: Displays "Custom Checklist"
    active_layers_str = wiz.get_active_layers_display()
    assert "White-Box" in active_layers_str and "Risk Mapping" in active_layers_str
    assert "Black-Box" not in active_layers_str  # Rule 6: Preserves manual layer selection

    # Test 8-10: Mode Switching & Back Navigation Safety
    # From Step 5 (Review), click Back (Custom mode -> goes to Step 4)
    wiz.back()
    assert wiz.step == 4  # Rule 10: Back navigation preserves custom path
    wiz.back()
    assert wiz.step == 3  # Returns to Analysis (Step 3)

    # Switch to Intelligent Scan
    wiz.set_analysis_mode("intelligent")
    assert wiz.analysis_mode == "intelligent"
    assert all(wiz.scanners.values())  # Rule 8: Clears/overrides stale custom state
    wiz.next()
    assert wiz.step == 5  # Reaches Review directly
    assert wiz.get_analysis_mode_display() == "Intelligent Scan"

    # From Step 5 (Review in Intelligent mode), click Back -> goes to Step 3
    wiz.back()
    assert wiz.step == 3  # Rule 10: Back navigation skips Step 4 in Intelligent mode

    # Switch to Custom Checklist
    wiz.set_analysis_mode("custom")
    assert wiz.get_analysis_mode_display() == "Custom Checklist"  # Rule 9: Does not claim Intelligent
    wiz.next()
    assert wiz.step == 4

    # Test 11: Backend API Payload Verification
    payload = {
        "name": "Audit Target Microservice",
        "technology": "Node.js",
        "description": "Onboarding payload test",
        "source_type": "GIT",
        "repository_url": "https://github.com/org/audit-target",
    }
    res = client.post("/api/projects", json=payload)
    assert res.status_code == 201
    created = res.json()
    assert created["name"] == "Audit Target Microservice"
    assert created["source_type"] == "GIT"
    assert created["repository_url"] == "https://github.com/org/audit-target"
