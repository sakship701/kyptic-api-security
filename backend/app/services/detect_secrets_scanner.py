import asyncio
import json
import sys
import subprocess
from pathlib import Path
from typing import Any, Dict
from app.services.scanner_base import BaseScanner

class DetectSecretsScanner(BaseScanner):
    def name(self) -> str:
        return "detect-secrets"

    async def get_version(self) -> str | None:
        """Get detect-secrets version using python -m detect_secrets --version."""
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "detect_secrets", "--version",
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
        """
        Execute the detect-secrets scan on target_dir recursively.
        Returns a dict containing results, status, etc.
        """
        # Build command: python -m detect_secrets scan --all-files .
        cmd = [sys.executable, "-m", "detect_secrets", "scan", "--all-files", "."]

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
            raise RuntimeError(f"Failed to start detect-secrets process: {e}")

        start_time = asyncio.get_event_loop().time() if asyncio.get_event_loop() else 0
        import time
        t_start = time.time()
        timeout_seconds = 60.0
        is_timed_out = False

        try:
            while proc.poll() is None:
                if time.time() - t_start > timeout_seconds:
                    proc.kill()
                    proc.wait()
                    is_timed_out = True
                    break
                await asyncio.sleep(0.2)
            if not is_timed_out:
                stdout, stderr = proc.communicate(timeout=1.0)
            else:
                stdout, stderr = "", "detect-secrets execution timed out after 60 seconds."
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
            stdout, stderr = "", "detect-secrets execution timed out after 60 seconds."

        if is_timed_out:
            return {
                "status": "SCANNER_TIMEOUT",
                "exit_code": -1,
                "stderr": "",
                "results": {"results": {}},
                "version": None,
                "error_message": "detect-secrets execution timed out after 60 seconds."
            }

        exit_code = proc.returncode
        stderr_msg = stderr.strip()

        # detect-secrets returns 0 if successful
        if exit_code != 0:
            raise RuntimeError(f"detect-secrets execution failed with code {exit_code}: {stderr_msg}")

        # Parse JSON
        try:
            results_json = json.loads(stdout)
        except Exception as e:
            # Mask any potential secrets in error message if parsing raw stdout fails
            raise RuntimeError(f"Failed to parse detect-secrets JSON output: {e}")

        version = await self.get_version()

        return {
            "status": "SUCCESS",
            "exit_code": exit_code,
            "stderr": "",  # avoid passing raw stderr which might contain matched line contents
            "results": results_json,
            "version": version
        }
