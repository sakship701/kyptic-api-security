import asyncio
import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict
from app.services.scanner_base import BaseScanner

class SemgrepSASTScanner(BaseScanner):
    def name(self) -> str:
        return "semgrep"

    def _resolve_semgrep_path(self) -> str | None:
        semgrep_path = shutil.which("semgrep")
        if not semgrep_path:
            import os
            # Safe Conda scripts search based on USERPROFILE
            user_profile = os.environ.get("USERPROFILE")
            if user_profile:
                conda_path = Path(user_profile) / "miniconda3/envs/myenv/Scripts"
                if conda_path.exists() and str(conda_path) not in os.environ.get("PATH", ""):
                    os.environ["PATH"] = str(conda_path) + os.pathsep + os.environ.get("PATH", "")
                    semgrep_path = shutil.which("semgrep")
        return semgrep_path

    async def get_version(self) -> str | None:
        """Get Semgrep version using --version."""
        semgrep_path = self._resolve_semgrep_path()
        if not semgrep_path:
            return None
        try:
            # We must use subprocess here too or create_subprocess_exec (which needs semgrep_path)
            proc = await asyncio.create_subprocess_exec(
                semgrep_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                return stdout.decode().strip()
        except Exception:
            pass
        return None

    async def scan(self, target_dir: Path) -> Dict[str, Any]:
        semgrep_path = self._resolve_semgrep_path()
        if not semgrep_path:
            raise RuntimeError(
                "Semgrep executable not found in system PATH. "
                "Please install Semgrep locally (e.g. run 'pip install semgrep') and ensure it is in your PATH."
            )

        # Build command: semgrep scan --config auto --json
        cmd = [semgrep_path, "scan", "--config", "auto", "--json", "."]

        import subprocess
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
        except Exception as e:
            raise RuntimeError(f"Failed to start Semgrep process: {e}")

        start_time = time.time()
        timeout_seconds = 120.0
        is_timed_out = False

        try:
            while proc.poll() is None:
                if time.time() - start_time > timeout_seconds:
                    proc.kill()
                    proc.wait()
                    is_timed_out = True
                    break
                await asyncio.sleep(0.2)
            if not is_timed_out:
                stdout, stderr = proc.communicate(timeout=1.0)
            else:
                stdout, stderr = "", "Semgrep execution timed out after 120 seconds."
        except asyncio.CancelledError:
            try:
                proc.terminate()
                proc.wait()
            except Exception:
                pass
            raise
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            is_timed_out = True
            stdout, stderr = "", "Semgrep execution timed out after 120 seconds."

        if is_timed_out:
            return {
                "status": "SCANNER_TIMEOUT",
                "exit_code": -1,
                "stderr": "Semgrep execution timed out after 120 seconds.",
                "results": {"results": []},
                "version": None,
                "error_message": "Semgrep execution timed out after 120 seconds."
            }

        exit_code = proc.returncode
        stderr_msg = stderr.strip()

        # Semgrep returns 0 if no findings, 1 if findings, or other values on fatal error
        if exit_code not in (0, 1):
            raise RuntimeError(f"Semgrep execution failed with code {exit_code}: {stderr_msg}")

        # Parse JSON
        try:
            results_json = json.loads(stdout)
        except Exception as e:
            raise RuntimeError(f"Failed to parse Semgrep JSON output: {e}. Output was: {stdout[:1000]}")

        version = await self.get_version()

        return {
            "status": "SUCCESS",
            "exit_code": exit_code,
            "stderr": stderr_msg,
            "results": results_json,
            "version": version
        }
