import unittest
import io
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.main import app
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.api_endpoint import ApiEndpoint
from app.models.finding import Finding, FindingSource
from app.services.api_spec_parser import OpenApiSpecParser, resolve_local_ref

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"


class TestApiSecurity(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            SQLALCHEMY_DATABASE_URL,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
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


        # Create dummy test project
        self.project = Project(name="API Test Project", technology="Python/FastAPI")
        self.db.add(self.project)
        self.db.commit()
        self.db.refresh(self.project)

    def tearDown(self):
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=self.engine)
        self.db.close()

    def test_openapi_spec_parser_json(self):
        spec_json = """{
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/api/users": {
                    "get": {
                        "summary": "List Users",
                        "responses": {
                            "200": {
                                "description": "Success",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "user_id": {"type": "string"},
                                                "password_hash": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"""
        parser = OpenApiSpecParser(spec_json)
        self.assertEqual(parser.get_version(), "OpenAPI 3.0.0")
        endpoints = parser.extract_endpoints()
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["path"], "/api/users")
        self.assertEqual(endpoints[0]["method"], "GET")

    def test_openapi_spec_parser_yaml(self):
        spec_yaml = """
openapi: 3.0.0
info:
  title: Test YAML API
  version: 1.0.0
paths:
  /api/admin/reset:
    post:
      summary: Reset Admin Password
      security: []
      responses:
        '200':
          description: Password reset link
"""
        parser = OpenApiSpecParser(spec_yaml)
        endpoints = parser.extract_endpoints()
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["path"], "/api/admin/reset")
        self.assertEqual(endpoints[0]["method"], "POST")
        self.assertEqual(endpoints[0]["op_security"], [])

    def test_malformed_openapi_rejection(self):
        with self.assertRaises(ValueError):
            OpenApiSpecParser("INVALID NON JSON OR YAML CONTENT {{[")

        with self.assertRaises(ValueError):
            OpenApiSpecParser('{"info": "missing paths and openapi version"}')

    def test_local_ref_resolution(self):
        spec = {
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {"id": {"type": "integer"}}
                    }
                }
            }
        }
        resolved = resolve_local_ref(spec, "#/components/schemas/User")
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["type"], "object")

    def test_remote_ref_rejection(self):
        spec = {}
        # Remote refs must be rejected safely
        resolved = resolve_local_ref(spec, "https://evil.example.com/schema.json")
        self.assertIsNone(resolved)

    def test_ingest_openapi_endpoint(self):
        valid_spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {
                        "summary": "Get users",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        response = self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(valid_spec.encode("utf-8")), "application/json")}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "READY")
        self.assertEqual(data["endpoints_count"], 1)

    def test_ingest_openapi_nonexistent_project(self):
        response = self.client.post(
            "/api/projects/9999/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(b"{}"), "application/json")}
        )
        self.assertEqual(response.status_code, 404)

    def test_run_analysis_and_summary(self):
        spec_content = """{
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "BearerAuth": {"type": "http", "scheme": "bearer"}
                }
            },
            "security": [{"BearerAuth": []}],
            "paths": {
                "/admin/credentials": {
                    "post": {
                        "summary": "Expose Admin Token",
                        "security": [],
                        "responses": {
                            "200": {
                                "description": "Exposes token",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "access_token": {"type": "string"},
                                                "password": {"type": "string"}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"""
        # First ingest
        ingest_res = self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec_content.encode("utf-8")), "application/json")}
        )
        self.assertEqual(ingest_res.status_code, 200)

        # Run analysis
        analyze_res = self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")
        self.assertEqual(analyze_res.status_code, 200)
        scan_data = analyze_res.json()
        self.assertEqual(scan_data["status"], "completed")

        # Check endpoints list
        endpoints_res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints")
        self.assertEqual(endpoints_res.status_code, 200)
        endpoints = endpoints_res.json()
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["path"], "/admin/credentials")
        self.assertEqual(endpoints[0]["auth_status"], "UNAUTHENTICATED")
        self.assertGreaterEqual(endpoints[0]["risk_score"], 50)
        self.assertIn("access_token", endpoints[0]["sensitive_data_fields"])

        # Check summary
        summary_res = self.client.get(f"/api/projects/{self.project.id}/api-security/summary")
        self.assertEqual(summary_res.status_code, 200)
        summary = summary_res.json()
        self.assertEqual(summary["total_endpoints"], 1)
        self.assertEqual(summary["unauthenticated_endpoints"], 1)
        self.assertEqual(summary["sensitive_data_endpoints"], 1)
        self.assertGreaterEqual(summary["total_api_findings"], 1)

    # -------------------------------------------------------------------------
    # Milestone 2 Tests: BOLA / Broken Object Level Authorization (OWASP API1:2023)
    # -------------------------------------------------------------------------
    def test_bola_detection_users_id(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/users/{id}": {
                    "get": {
                        "summary": "Get User Profile",
                        "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")

        ep_res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints")
        ep_data = ep_res.json()
        self.assertEqual(len(ep_data), 1)
        self.assertEqual(ep_data[0]["path"], "/users/{id}")
        self.assertEqual(ep_data[0]["bola_status"], "POTENTIAL_BOLA")

    def test_bola_detection_orders_order_id(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/orders/{order_id}": {
                    "get": {
                        "summary": "Get Order Details",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")

        ep_res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints")
        ep_data = ep_res.json()
        self.assertEqual(ep_data[0]["bola_status"], "POTENTIAL_BOLA")

    def test_bola_non_object_param(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/search": {
                    "get": {
                        "summary": "Search items",
                        "parameters": [{"name": "query", "in": "query", "schema": {"type": "string"}}],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")

        ep_res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints")
        ep_data = ep_res.json()
        self.assertEqual(ep_data[0]["bola_status"], "NONE")

    def test_bola_owasp_mapping(self):
        from app.services.api_security_scanner import ApiSecurityScanner
        ep_info = {
            "path": "/documents/{document_id}",
            "method": "GET",
            "summary": "Fetch document",
            "parameters": [{"name": "document_id", "in": "path"}],
            "response_schemas": {"200": {}}
        }
        scanner = ApiSecurityScanner(project_id=self.project.id, scan_id=1)
        _, findings = scanner.analyze_endpoint(ep_info)
        bola_findings = [f for f in findings if "BOLA" in f.title or "API1" in f.owasp]
        self.assertGreaterEqual(len(bola_findings), 1)
        self.assertEqual(bola_findings[0].owasp, "API1:2023 Broken Object Level Authorization")

    def test_bola_deterministic_finding_generation(self):
        from app.services.api_security_scanner import ApiSecurityScanner
        ep_info = {
            "path": "/accounts/{accountId}",
            "method": "GET",
            "summary": "Fetch Account",
            "parameters": [{"name": "accountId", "in": "path"}],
            "response_schemas": {"200": {}}
        }
        scanner1 = ApiSecurityScanner(project_id=self.project.id, scan_id=1)
        _, findings1 = scanner1.analyze_endpoint(ep_info)

        scanner2 = ApiSecurityScanner(project_id=self.project.id, scan_id=2)
        _, findings2 = scanner2.analyze_endpoint(ep_info)

        fp1 = [f.fingerprint for f in findings1 if "API-BOLA" in f.rule_id]
        fp2 = [f.fingerprint for f in findings2 if "API-BOLA" in f.rule_id]
        self.assertEqual(fp1, fp2)

    def test_bola_duplicate_prevention(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/profiles/{profileId}": {
                    "get": {
                        "summary": "Get Profile",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        res1 = self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")
        scan1_id = res1.json()["id"]

        res2 = self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")
        scan2_id = res2.json()["id"]

        findings_scan1 = self.db.query(Finding).filter(Finding.project_id == self.project.id, Finding.scan_id == scan1_id).all()
        bola_fps_scan1 = [f.fingerprint for f in findings_scan1 if f.rule_id == "API-BOLA-POTENTIAL-EXPOSURE"]

        findings_scan2 = self.db.query(Finding).filter(Finding.project_id == self.project.id, Finding.scan_id == scan2_id).all()
        bola_fps_scan2 = [f.fingerprint for f in findings_scan2 if f.rule_id == "API-BOLA-POTENTIAL-EXPOSURE"]

        self.assertEqual(len(bola_fps_scan2), 1)
        self.assertEqual(bola_fps_scan1, bola_fps_scan2)

    # -------------------------------------------------------------------------
    # Milestone 2 Tests: Mass Assignment / Unsafe Property Binding (OWASP API6:2023)
    # -------------------------------------------------------------------------
    def test_mass_assignment_is_admin(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "post": {
                        "summary": "Create User",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "is_admin": {"type": "boolean"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")

        ep_res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints")
        ep_data = ep_res.json()
        self.assertEqual(ep_data[0]["mass_assignment_status"], "SUSPICIOUS_PROPERTIES_EXPOSED")

    def test_mass_assignment_role_permissions(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/accounts/{id}": {
                    "put": {
                        "summary": "Update Account",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "role": {"type": "string"},
                                            "permissions": {"type": "array", "items": {"type": "string"}}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")

        ep_res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints")
        ep_data = ep_res.json()
        self.assertEqual(ep_data[0]["mass_assignment_status"], "SUSPICIOUS_PROPERTIES_EXPOSED")

    def test_mass_assignment_ownership_on_post_put(self):
        from app.services.api_security_scanner import ApiSecurityScanner
        ep_info = {
            "path": "/documents/{id}",
            "method": "PATCH",
            "summary": "Update document",
            "request_body_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "owner_id": {"type": "integer"}
                }
            },
            "response_schemas": {"200": {}}
        }
        scanner = ApiSecurityScanner(project_id=self.project.id, scan_id=1)
        _, findings = scanner.analyze_endpoint(ep_info)
        ma_findings = [f for f in findings if "Mass Assignment" in f.title]
        self.assertEqual(len(ma_findings), 1)

    def test_mass_assignment_owasp_mapping(self):
        from app.services.api_security_scanner import ApiSecurityScanner
        ep_info = {
            "path": "/users",
            "method": "POST",
            "summary": "Create User",
            "request_body_schema": {
                "type": "object",
                "properties": {
                    "balance": {"type": "number"}
                }
            },
            "response_schemas": {"200": {}}
        }
        scanner = ApiSecurityScanner(project_id=self.project.id, scan_id=1)
        _, findings = scanner.analyze_endpoint(ep_info)
        ma_findings = [f for f in findings if "Mass Assignment" in f.title]
        self.assertGreaterEqual(len(ma_findings), 1)
        self.assertIn("API6:2023", ma_findings[0].owasp)

    def test_mass_assignment_remediation(self):
        from app.services.api_security_scanner import ApiSecurityScanner
        ep_info = {
            "path": "/users",
            "method": "POST",
            "summary": "Register",
            "request_body_schema": {
                "type": "object",
                "properties": {
                    "is_admin": {"type": "boolean"}
                }
            },
            "response_schemas": {"200": {}}
        }
        scanner = ApiSecurityScanner(project_id=self.project.id, scan_id=1)
        _, findings = scanner.analyze_endpoint(ep_info)
        ma_findings = [f for f in findings if "Mass Assignment" in f.title]
        self.assertIn("allowlist", ma_findings[0].description.lower() + ma_findings[0].code_snippet.lower())

    # -------------------------------------------------------------------------
    # Milestone 2 Tests: Rate Limiting & Resource Consumption (OWASP API4:2023)
    # -------------------------------------------------------------------------
    def test_rate_limit_explicit_metadata(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/api/data": {
                    "x-rate-limit": "100 per minute",
                    "get": {
                        "summary": "Get data",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")

        ep_res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints")
        ep_data = ep_res.json()
        self.assertEqual(ep_data[0]["rate_limit_status"], "PRESENT")

    def test_rate_limit_missing_metadata(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/api/status": {
                    "get": {
                        "summary": "Status check",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")

        ep_res = self.client.get(f"/api/projects/{self.project.id}/api-security/endpoints")
        ep_data = ep_res.json()
        self.assertEqual(ep_data[0]["rate_limit_status"], "MISSING")

    def test_rate_limit_resource_intensive_heuristic(self):
        spec = """{
            "openapi": "3.0.0",
            "paths": {
                "/reports/export": {
                    "post": {
                        "summary": "Generate Large Export Report",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }"""
        self.client.post(
            f"/api/projects/{self.project.id}/ingest/openapi",
            files={"file": ("openapi.json", io.BytesIO(spec.encode("utf-8")), "application/json")}
        )
        self.client.post(f"/api/projects/{self.project.id}/api-security/analyze")

        summary_res = self.client.get(f"/api/projects/{self.project.id}/api-security/summary")
        summary = summary_res.json()
        self.assertGreaterEqual(summary["missing_rate_limit_endpoints"], 1)

    def test_rate_limit_owasp_mapping(self):
        from app.services.api_security_scanner import ApiSecurityScanner
        ep_info = {
            "path": "/files/upload",
            "method": "POST",
            "summary": "Upload file",
            "response_schemas": {"200": {}}
        }
        scanner = ApiSecurityScanner(project_id=self.project.id, scan_id=1)
        _, findings = scanner.analyze_endpoint(ep_info)
        rl_findings = [f for f in findings if "Rate Limiting" in f.title]
        self.assertEqual(len(rl_findings), 1)
        self.assertEqual(rl_findings[0].owasp, "API4:2023 Unrestricted Resource Consumption")


if __name__ == "__main__":
    unittest.main()
