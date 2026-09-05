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


if __name__ == "__main__":
    unittest.main()
