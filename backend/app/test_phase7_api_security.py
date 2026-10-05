import pytest
from app.services.api_security_scanner import (
    find_sensitive_fields_in_schema,
    is_sensitive_path,
    run_static_api_analysis,
)
from app.services.api_spec_parser import OpenApiSpecParser, resolve_local_ref


def test_openapi_parser_swagger2_openapi3_and_31():
    # 1. Swagger 2.0 JSON
    swagger2_json = """{
        "swagger": "2.0",
        "info": {"title": "Test Swagger 2 API", "version": "1.0"},
        "paths": {"/pets": {"get": {"responses": {"200": {"description": "OK"}}}}}
    }"""
    parser1 = OpenApiSpecParser(swagger2_json)
    assert parser1.spec["swagger"] == "2.0"

    # 2. OpenAPI 3.0 YAML
    openapi3_yaml = """
openapi: "3.0.1"
info:
  title: "Test OpenAPI 3 API"
  version: "1.0.0"
paths:
  /users:
    get:
      summary: "List users"
      responses:
        '200':
          description: "Success"
"""
    parser2 = OpenApiSpecParser(openapi3_yaml)
    assert parser2.spec["openapi"] == "3.0.1"

    # 3. OpenAPI 3.1 JSON
    openapi31_json = """{
        "openapi": "3.1.0",
        "info": {"title": "Test OpenAPI 3.1 API", "version": "1.0.0"},
        "paths": {"/accounts": {"get": {"responses": {"200": {"description": "OK"}}}}}
    }"""
    parser3 = OpenApiSpecParser(openapi31_json)
    assert parser3.spec["openapi"] == "3.1.0"


def test_openapi_safe_local_ref_resolution():
    spec = {
        "openapi": "3.0.0",
        "components": {
            "schemas": {
                "User": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "email": {"type": "string"},
                        "password": {"type": "string"}
                    }
                }
            }
        }
    }

    # Safe local pointer resolution
    resolved = resolve_local_ref(spec, "#/components/schemas/User")
    assert resolved is not None
    assert "properties" in resolved

    # Remote URL or file references MUST BE REJECTED
    assert resolve_local_ref(spec, "http://evil.com/schema.json") is None
    assert resolve_local_ref(spec, "file:///etc/passwd") is None


def test_api_sensitive_path_and_field_detection():
    # Path sensitivity check
    assert is_sensitive_path("/api/v1/users/{id}") is True
    assert is_sensitive_path("/api/v1/payments/checkout") is True
    assert is_sensitive_path("/api/v1/public/status") is False

    # Schema sensitive field detection
    schema = {
        "type": "object",
        "properties": {
            "user_id": {"type": "integer"},
            "access_token": {"type": "string"},
            "credit_card": {"type": "string"}
        }
    }
    found = find_sensitive_fields_in_schema(schema)
    fields = [f[0] for f in found]
    assert "access_token" in fields
    assert "credit_card" in fields
