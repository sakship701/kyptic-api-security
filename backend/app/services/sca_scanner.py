import asyncio
import json
import re
import sys
import subprocess
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Tuple

from app.services.scanner_base import BaseScanner


class SCAStatus:
    SUCCESS = "SUCCESS"
    NO_VULNERABILITIES = "NO_VULNERABILITIES"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    SCANNER_ERROR = "SCANNER_ERROR"
    NO_MANIFESTS = "NO_MANIFESTS"


class SCADependencyScanner(BaseScanner):
    def name(self) -> str:
        return "sca-dependency"

    def detect_manifests(self, target_dir: Path) -> Dict[str, List[Path]]:
        """
        Detect supported Python and Node.js dependency manifests/lockfiles in target_dir.
        """
        python_files = []
        node_files = []

        if not target_dir.exists() or not target_dir.is_dir():
            return {"python": [], "node": []}

        for path in target_dir.rglob("*"):
            # Avoid scanning inside node_modules or .git
            rel_parts = path.relative_to(target_dir).parts
            if any(p in (".git", "node_modules", "__pycache__", ".venv", "venv") for p in rel_parts):
                continue
            if path.is_file():
                filename = path.name.lower()
                if (
                    filename == "requirements.txt"
                    or (filename.startswith("requirements") and filename.endswith(".txt"))
                    or filename == "pyproject.toml"
                    or filename in ("pipfile", "pipfile.lock")
                ):
                    python_files.append(path)
                elif filename in (
                    "package.json",
                    "package-lock.json",
                    "npm-shrinkwrap.json",
                    "yarn.lock",
                    "pnpm-lock.yaml",
                ):
                    node_files.append(path)

        return {"python": python_files, "node": node_files}

    def _parse_python_requirements(self, file_path: Path) -> List[Tuple[str, str]]:
        """Parse requirement lines like package==version safely."""
        packages = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Strip environment markers and inline comments
                line = line.split("#")[0].strip().split(";")[0].strip()
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.]+)", line)
                if match:
                    pkg, ver = match.group(1), match.group(2)
                    packages.append((pkg, ver))
        except Exception:
            pass
        return packages

    def _parse_node_manifest(self, file_path: Path) -> List[Tuple[str, str]]:
        """Parse package.json or lockfiles safely without executing scripts."""
        packages = []
        try:
            filename = file_path.name.lower()
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            if filename == "package.json":
                data = json.loads(content)
                deps = {}
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    if isinstance(data.get(key), dict):
                        deps.update(data[key])
                for pkg, ver_spec in deps.items():
                    if isinstance(ver_spec, str):
                        clean_ver = re.sub(r"[^0-9\.]", "", ver_spec)
                        if clean_ver:
                            packages.append((pkg, clean_ver))

            elif filename in ("package-lock.json", "npm-shrinkwrap.json"):
                data = json.loads(content)
                pkgs_dict = data.get("packages", {})
                if isinstance(pkgs_dict, dict) and pkgs_dict:
                    for pkg_key, pkg_info in pkgs_dict.items():
                        if isinstance(pkg_info, dict):
                            ver = pkg_info.get("version")
                            name = pkg_info.get("name")
                            if not name and pkg_key.startswith("node_modules/"):
                                name = pkg_key.replace("node_modules/", "")
                            if name and ver and isinstance(name, str) and isinstance(ver, str):
                                packages.append((name, ver))
                elif isinstance(data.get("dependencies"), dict):
                    for name, info in data["dependencies"].items():
                        if isinstance(info, dict) and isinstance(info.get("version"), str):
                            packages.append((name, info["version"]))

            elif filename in ("yarn.lock", "pnpm-lock.yaml"):
                matches = re.findall(r'["\']?([a-zA-Z0-9_\-@\/]+)@(?:[^\n:]+):[^\n]*?\n\s+version\s+["\']?([a-zA-Z0-9_\-\.]+)["\']?', content)
                for pkg, ver in matches:
                    packages.append((pkg, ver))
        except Exception:
            pass
        return packages

    def _query_osv_batch(self, queries: List[Dict[str, Any]], timeout: int = 15) -> Dict[str, Any]:
        """Query OSV API batch endpoint sending ONLY package name and ecosystem version."""
        if not queries:
            return {"results": []}

        url = "https://api.osv.dev/v1/querybatch"
        payload = json.dumps({"queries": queries}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})

        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    return json.loads(response.read().decode("utf-8"))
                else:
                    raise RuntimeError(f"OSV API HTTP status {response.status}")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
            raise ConnectionError(f"Database network error: {e}")

    def _query_osv_detail(self, vuln_id: str, timeout: int = 10) -> Dict[str, Any] | None:
        """Fetch detailed OSV vulnerability record."""
        url = f"https://api.osv.dev/v1/vulns/{vuln_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "Kyptic-SCA/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status == 200:
                    return json.loads(response.read().decode("utf-8"))
        except Exception:
            pass
        return None

    async def scan(self, target_dir: Path) -> Dict[str, Any]:
        manifests = self.detect_manifests(target_dir)
        python_files = manifests["python"]
        node_files = manifests["node"]

        all_detected = python_files + node_files
        if not all_detected:
            return {
                "status": SCAStatus.NO_MANIFESTS,
                "results": [],
                "detected_files": [],
                "version": "sca-dependency 1.0.0",
                "error_message": "No supported dependency manifest or lockfile found."
            }

        detected_rel_paths = [str(p.relative_to(target_dir)) for p in all_detected]
        raw_vulnerabilities = []
        lookup_attempted = False
        lookup_failed_due_to_network = False
        scanner_error_occurred = False
        last_error_msg = ""

        # 1. Process Python manifests using pip-audit where possible
        for py_file in python_files:
            rel_file = str(py_file.relative_to(target_dir))

            # Attempt pip-audit subprocess if it's a requirements file
            if py_file.name.lower().startswith("requirements"):
                lookup_attempted = True
                cmd = [sys.executable, "-m", "pip_audit", "-r", str(py_file), "-f", "json"]
                timed_out = False
                stdout, stderr = "", ""
                try:
                    proc = subprocess.Popen(
                        cmd,
                        cwd=str(target_dir),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=False,
                        text=True,
                        encoding="utf-8",
                        errors="replace"
                    )
                    start_time = time.time()
                    while proc.poll() is None:
                        if time.time() - start_time > 120.0:
                            proc.kill()
                            proc.wait()
                            timed_out = True
                            break
                        await asyncio.sleep(0.1)

                    if timed_out:
                        scanner_error_occurred = True
                        last_error_msg = "SCA pip-audit scan timed out after 120 seconds."
                    else:
                        stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    scanner_error_occurred = True
                    last_error_msg = "SCA pip-audit scan timed out after 120 seconds."
                    try:
                        proc.kill()
                        proc.wait()
                    except Exception:
                        pass
                except Exception as ex:
                    lookup_failed_due_to_network = True
                    last_error_msg = str(ex)

                if not timed_out:
                    if proc.returncode in (0, 1):
                        try:
                            audit_data = json.loads(stdout)
                            if isinstance(audit_data, list):
                                for pkg_item in audit_data:
                                    pkg_name = pkg_item.get("name")
                                    pkg_ver = pkg_item.get("version")
                                    vulns = pkg_item.get("vulns", [])
                                    for v in vulns:
                                        raw_vulnerabilities.append({
                                            "package_name": pkg_name,
                                            "installed_version": pkg_ver,
                                            "vulnerability_id": v.get("id"),
                                            "aliases": v.get("aliases", []),
                                            "summary": v.get("details", "Dependency vulnerability detected by pip-audit."),
                                            "fix_versions": v.get("fix_versions", []),
                                            "ecosystem": "PyPI",
                                            "file_path": rel_file,
                                        })
                        except Exception as parse_err:
                            scanner_error_occurred = True
                            last_error_msg = f"Failed to parse pip-audit output: {parse_err}"
                    else:
                        if any(term in stderr.lower() for term in ("connection", "socket", "http", "network", "timeout", "service")):
                            lookup_failed_due_to_network = True
                            last_error_msg = stderr.strip() or "pip-audit failed to reach vulnerability service."
                        else:
                            scanner_error_occurred = True
                            last_error_msg = stderr.strip()

            else:
                # Python non-requirements (pyproject.toml, Pipfile) -> parse & OSV query
                parsed_pkgs = self._parse_python_requirements(py_file)
                if parsed_pkgs:
                    lookup_attempted = True
                    queries = [{"package": {"name": name, "ecosystem": "PyPI"}, "version": ver} for name, ver in parsed_pkgs]
                    try:
                        osv_batch_res = self._query_osv_batch(queries)
                        results_list = osv_batch_res.get("results", [])
                        for idx, res_item in enumerate(results_list):
                            pkg_name, pkg_ver = parsed_pkgs[idx]
                            vulns = res_item.get("vulns", [])
                            for v in vulns:
                                vuln_id = v.get("id")
                                detail = self._query_osv_detail(vuln_id) if vuln_id else None
                                raw_vulnerabilities.append({
                                    "package_name": pkg_name,
                                    "installed_version": pkg_ver,
                                    "vulnerability_id": vuln_id,
                                    "aliases": detail.get("aliases", []) if detail else [],
                                    "summary": detail.get("summary") or detail.get("details") if detail else "Vulnerability detected in dependency.",
                                    "fix_versions": [ev.get("fixed") for aff in (detail.get("affected", []) if detail else []) for r in aff.get("ranges", []) for ev in r.get("events", []) if ev.get("fixed")],
                                    "severity_raw": detail.get("database_specific", {}).get("severity") if detail else None,
                                    "cvss_vector": detail.get("severity", [{}])[0].get("score") if detail and detail.get("severity") else None,
                                    "ecosystem": "PyPI",
                                    "file_path": rel_file,
                                })
                    except ConnectionError as conn_err:
                        lookup_failed_due_to_network = True
                        last_error_msg = str(conn_err)
                    except Exception as ex:
                        scanner_error_occurred = True
                        last_error_msg = str(ex)

        # 2. Process Node.js manifests safely using parser + OSV batch query
        for node_file in node_files:
            rel_file = str(node_file.relative_to(target_dir))
            parsed_pkgs = self._parse_node_manifest(node_file)
            if parsed_pkgs:
                lookup_attempted = True
                chunk_size = 50
                for i in range(0, len(parsed_pkgs), chunk_size):
                    chunk = parsed_pkgs[i:i + chunk_size]
                    queries = [{"package": {"name": name, "ecosystem": "npm"}, "version": ver} for name, ver in chunk]
                    try:
                        osv_batch_res = self._query_osv_batch(queries)
                        results_list = osv_batch_res.get("results", [])
                        for idx, res_item in enumerate(results_list):
                            if idx < len(chunk):
                                pkg_name, pkg_ver = chunk[idx]
                                vulns = res_item.get("vulns", [])
                                for v in vulns:
                                    vuln_id = v.get("id")
                                    detail = self._query_osv_detail(vuln_id) if vuln_id else None
                                    raw_vulnerabilities.append({
                                        "package_name": pkg_name,
                                        "installed_version": pkg_ver,
                                        "vulnerability_id": vuln_id,
                                        "aliases": detail.get("aliases", []) if detail else [],
                                        "summary": detail.get("summary") or detail.get("details") if detail else "Vulnerability detected in Node dependency.",
                                        "fix_versions": [ev.get("fixed") for aff in (detail.get("affected", []) if detail else []) for r in aff.get("ranges", []) for ev in r.get("events", []) if ev.get("fixed")],
                                        "severity_raw": detail.get("database_specific", {}).get("severity") if detail else None,
                                        "cvss_vector": detail.get("severity", [{}])[0].get("score") if detail and detail.get("severity") else None,
                                        "ecosystem": "npm",
                                        "file_path": rel_file,
                                    })
                    except ConnectionError as conn_err:
                        lookup_failed_due_to_network = True
                        last_error_msg = str(conn_err)
                    except Exception as ex:
                        scanner_error_occurred = True
                        last_error_msg = str(ex)

        # 3. Determine final status
        if lookup_failed_due_to_network:
            final_status = SCAStatus.DATABASE_UNAVAILABLE
        elif scanner_error_occurred and not raw_vulnerabilities:
            final_status = SCAStatus.SCANNER_ERROR
        elif raw_vulnerabilities:
            final_status = SCAStatus.SUCCESS
        elif lookup_attempted:
            final_status = SCAStatus.NO_VULNERABILITIES
        else:
            final_status = SCAStatus.NO_MANIFESTS

        return {
            "status": final_status,
            "results": raw_vulnerabilities,
            "detected_files": detected_rel_paths,
            "version": "sca-dependency 1.0.0",
            "error_message": last_error_msg if (lookup_failed_due_to_network or scanner_error_occurred) else None
        }
