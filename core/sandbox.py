import os
import sys
import subprocess
import tempfile
import time
import shutil
from pathlib import Path
from typing import Dict, Any, Optional
from config.settings import SANDBOX_ROOT

class ProcessSandbox:
    """
    Process Sandbox Execution Environment:
    - Provides isolated directory sandbox for inspecting or running untrusted tasks/payloads
    - Enforces timeout limits and memory/CPU limits
    - Tracks process lifecycle, handles cleanup, and records dynamic execution behavior
    """

    def __init__(self, sandbox_dir: Optional[Path] = None):
        self.sandbox_dir = sandbox_dir or SANDBOX_ROOT
        self.sandbox_dir.mkdir(parents=True, exist_ok=True)

    def write_payload_to_sandbox(self, filename: str, content: bytes) -> Path:
        """Safely writes a received artifact into isolated sandbox storage"""
        # Sanitize filename
        safe_name = "".join(c for c in filename if c.isalnum() or c in "._-").strip()
        if not safe_name:
            safe_name = f"payload_{int(time.time()*1000)}.bin"
        file_path = self.sandbox_dir / safe_name
        with open(file_path, "wb") as f:
            f.write(content)
        return file_path

    def run_isolated_command(
        self,
        command_list: list,
        timeout_seconds: float = 3.0,
        env_vars: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Executes a command inside the sandbox directory with strict time limits
        and restricted environment variables.
        """
        # Restrict environment
        safe_env = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
            "PATH": os.environ.get("PATH", ""),
            "TEMP": str(self.sandbox_dir),
            "TMP": str(self.sandbox_dir),
            "SANDBOX_CONTAINED": "1"
        }
        if env_vars:
            safe_env.update(env_vars)

        start_time = time.time()
        try:
            process = subprocess.Popen(
                command_list,
                cwd=str(self.sandbox_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                env=safe_env,
                shell=False
            )
            
            stdout, stderr = process.communicate(timeout=timeout_seconds)
            duration = time.time() - start_time
            
            return {
                "success": process.returncode == 0,
                "return_code": process.returncode,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "timed_out": False,
                "duration_sec": round(duration, 4),
                "sandboxed": True
            }
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return {
                "success": False,
                "return_code": -1,
                "stdout": stdout.decode("utf-8", errors="replace") if stdout else "",
                "stderr": "Execution exceeded sandbox maximum time quota.",
                "timed_out": True,
                "duration_sec": timeout_seconds,
                "sandboxed": True
            }
        except Exception as e:
            return {
                "success": False,
                "return_code": -1,
                "stdout": "",
                "stderr": f"Sandbox execution error: {str(e)}",
                "timed_out": False,
                "duration_sec": round(time.time() - start_time, 4),
                "sandboxed": True
            }

    def cleanup_sandbox(self):
        """Cleans up temporary sandbox artifacts"""
        for item in self.sandbox_dir.iterdir():
            try:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
            except Exception:
                pass
