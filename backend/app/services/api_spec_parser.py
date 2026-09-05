import json
from typing import Any, Dict, List, Tuple
import yaml

MAX_SPEC_SIZE = 50 * 1024 * 1024  # 50 MB limit


def resolve_local_ref(spec: Dict[str, Any], ref_path: str) -> Any:
    """
    Safely resolve local document $ref pointers (e.g. '#/components/schemas/User').
    Rejects remote URLs or external file references.
    """
    if not ref_path or not isinstance(ref_path, str):
        return None

    if not ref_path.startswith("#/"):
        # Remote $ref URLs (http/https/file) are explicitly NOT resolved for SSRF/security reasons
        return None

    parts = ref_path.lstrip("#/").split("/")
    curr = spec
    for part in parts:
        part_decoded = part.replace("~1", "/").replace("~0", "~")
        if isinstance(curr, dict) and part_decoded in curr:
            curr = curr[part_decoded]
        else:
            return None
    return curr


def resolve_schema_refs(schema: Any, spec: Dict[str, Any], depth: int = 0) -> Any:
    """
    Recursively resolve $ref pointers in a schema up to a maximum recursion depth of 10.
    """
    if depth > 10 or not schema:
        return schema

    if isinstance(schema, dict):
        if "$ref" in schema:
            resolved = resolve_local_ref(spec, schema["$ref"])
            if resolved and isinstance(resolved, dict):
                # Combine remaining keys with resolved schema
                merged = {k: v for k, v in schema.items() if k != "$ref"}
                merged.update(resolve_schema_refs(resolved, spec, depth + 1))
                return merged
            return schema
        else:
            return {k: resolve_schema_refs(v, spec, depth + 1) for k, v in schema.items()}
    elif isinstance(schema, list):
        return [resolve_schema_refs(item, spec, depth + 1) for item in schema]

    return schema


class OpenApiSpecParser:
    def __init__(self, raw_content: str | bytes):
        if isinstance(raw_content, bytes):
            if len(raw_content) > MAX_SPEC_SIZE:
                raise ValueError("Specification size exceeds maximum allowed limit of 50MB")
            raw_content = raw_content.decode("utf-8", errors="ignore")
        elif len(raw_content.encode("utf-8")) > MAX_SPEC_SIZE:
            raise ValueError("Specification size exceeds maximum allowed limit of 50MB")

        self.raw_content = raw_content
        self.spec = self._parse_raw(raw_content)
        self._validate_structure()

    def _parse_raw(self, content: str) -> Dict[str, Any]:
        content_stripped = content.strip()
        if not content_stripped:
            raise ValueError("Specification file is empty.")

        # Try JSON first
        if content_stripped.startswith("{") or content_stripped.startswith("["):
            try:
                parsed = json.loads(content)
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON specification: {str(e)}")

        # Fallback to Safe YAML
        try:
            parsed = yaml.safe_load(content)
            if isinstance(parsed, dict):
                return parsed
            raise ValueError("Specification content must resolve to a valid JSON or YAML object.")
        except Exception as e:
            raise ValueError(f"Failed to parse OpenAPI YAML specification: {str(e)}")

    def _validate_structure(self) -> None:
        if not isinstance(self.spec, dict):
            raise ValueError("Invalid specification format: root element must be an object.")

        is_swagger_2 = "swagger" in self.spec and str(self.spec["swagger"]).startswith("2.")
        is_openapi_3 = "openapi" in self.spec and (
            str(self.spec["openapi"]).startswith("3.") or str(self.spec["openapi"]).startswith("3.1")
        )

        if not is_swagger_2 and not is_openapi_3:
            raise ValueError("Unsupported specification format. Must be OpenAPI 2.0, 3.0.x, or 3.1.x.")

        if "paths" not in self.spec or not isinstance(self.spec.get("paths"), dict):
            raise ValueError("Invalid OpenAPI specification: missing required 'paths' definition.")

        self._validate_no_remote_refs(self.spec)

    def _validate_no_remote_refs(self, node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "$ref" and isinstance(v, str):
                    lowered = v.lower()
                    if lowered.startswith(("http://", "https://", "file://", "ftp://")) or ".." in v:
                        raise ValueError(f"Remote or unsafe $ref pointers are rejected for security: '{v}'")
                else:
                    self._validate_no_remote_refs(v)
        elif isinstance(node, list):
            for item in node:
                self._validate_no_remote_refs(item)

    def get_version(self) -> str:
        if "swagger" in self.spec:
            return f"Swagger {self.spec['swagger']}"
        return f"OpenAPI {self.spec.get('openapi', '3.0')}"

    def get_security_schemes(self) -> Dict[str, Any]:
        """Extract security definitions (Swagger 2.0) or securitySchemes (OpenAPI 3.x)."""
        schemes = {}
        # OpenAPI 3.x
        components = self.spec.get("components")
        if isinstance(components, dict):
            sec_schemes = components.get("securitySchemes")
            if isinstance(sec_schemes, dict):
                schemes.update(sec_schemes)

        # Swagger 2.0
        sec_defs = self.spec.get("securityDefinitions")
        if isinstance(sec_defs, dict):
            schemes.update(sec_defs)

        return schemes

    def get_global_security(self) -> List[Dict[str, List[str]]] | None:
        global_sec = self.spec.get("security")
        if isinstance(global_sec, list):
            return global_sec
        return None

    def extract_endpoints(self) -> List[Dict[str, Any]]:
        """
        Enumerates all paths and HTTP operations, extracting schemas, parameters, auth, and summaries.
        """
        parsed_endpoints = []
        paths = self.spec.get("paths", {})
        global_security = self.get_global_security()
        security_schemes = self.get_security_schemes()

        HTTP_METHODS = {"get", "post", "put", "delete", "patch", "options", "head"}

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_parameters = path_item.get("parameters", [])
            if not isinstance(path_parameters, list):
                path_parameters = []

            for method, op in path_item.items():
                if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                    continue

                method_upper = method.upper()
                summary = op.get("summary") or op.get("description") or f"{method_upper} {path}"
                operation_id = op.get("operationId")

                # Combine path-level and operation-level parameters
                op_parameters = op.get("parameters", [])
                if not isinstance(op_parameters, list):
                    op_parameters = []
                all_parameters = path_parameters + op_parameters

                # Resolve parameters
                resolved_parameters = [
                    resolve_schema_refs(p, self.spec) for p in all_parameters if isinstance(p, dict)
                ]

                # Extract Request Body (OpenAPI 3.x vs Swagger 2.0 body param)
                request_body_schema = None
                if "requestBody" in op and isinstance(op["requestBody"], dict):
                    req_body = resolve_schema_refs(op["requestBody"], self.spec)
                    content = req_body.get("content", {})
                    if isinstance(content, dict):
                        for media_type, media_obj in content.items():
                            if isinstance(media_obj, dict) and "schema" in media_obj:
                                request_body_schema = media_obj["schema"]
                                break
                else:
                    # Check for body parameter in parameters (Swagger 2.0)
                    for param in resolved_parameters:
                        if param.get("in") == "body" and "schema" in param:
                            request_body_schema = param["schema"]
                            break

                # Extract Response Schemas
                response_schemas = {}
                responses = op.get("responses", {})
                if isinstance(responses, dict):
                    for status_code, resp_obj in responses.items():
                        if isinstance(resp_obj, dict):
                            resolved_resp = resolve_schema_refs(resp_obj, self.spec)
                            # OpenAPI 3.x content
                            if "content" in resolved_resp and isinstance(resolved_resp["content"], dict):
                                for m_type, m_obj in resolved_resp["content"].items():
                                    if isinstance(m_obj, dict) and "schema" in m_obj:
                                        response_schemas[str(status_code)] = m_obj["schema"]
                                        break
                            # Swagger 2.0 schema
                            elif "schema" in resolved_resp:
                                response_schemas[str(status_code)] = resolved_resp["schema"]

                # Extract Operation Security
                op_security = op.get("security")
                # If op_security is None, it inherits global_security.
                # If op_security is [], it explicitly overrides to NO auth!

                parsed_endpoints.append({
                    "path": path,
                    "method": method_upper,
                    "summary": str(summary)[:500],
                    "operation_id": str(operation_id) if operation_id else None,
                    "parameters": resolved_parameters,
                    "request_body_schema": request_body_schema,
                    "response_schemas": response_schemas,
                    "op_security": op_security,
                    "global_security": global_security,
                    "security_schemes": security_schemes,
                    "op_dict": op,
                    "path_item_dict": path_item,
                    "root_spec_dict": self.spec,
                })

        return parsed_endpoints
