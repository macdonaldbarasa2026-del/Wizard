from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from app.models.schemas import ToolExecutionRecord
from app.security.sanitizer import scrub_secrets


# Strictly allowlisted tools for defensive analysis
ALLOWED_COMMANDS = {
    "strings",
    "objdump",
    "readelf",
    "file",
    "nm",
}

# Maximum output capture size in characters (256 KB)
MAX_OUTPUT_CHARS = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 6.0


class ExecutionError(RuntimeError):
    pass


class SafeExecutor:
    """Safe subprocess execution harness with strict command allowlisting, timeouts,
    output limits, and audit tracking. Arbitrary shell commands are strictly prohibited.
    """

    def __init__(self, timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS):
        self.timeout_seconds = timeout_seconds
        self.audit_log: list[ToolExecutionRecord] = []

    def execute(
        self,
        command: str,
        arguments: list[str],
        cwd: Path | None = None,
        scope_decision: str = "approved",
    ) -> ToolExecutionRecord:
        if command not in ALLOWED_COMMANDS:
            raise ExecutionError(
                f"Command '{command}' is not in the approved security tool allowlist: {sorted(ALLOWED_COMMANDS)}. "
                "Arbitrary AI shell execution is strictly disabled."
            )

        binary_path = shutil.which(command)
        if not binary_path:
            raise ExecutionError(f"Tool '{command}' is not installed or available on this system.")

        # Sanitize arguments: prevent newlines, control chars, and dangerous flags
        sanitized_args: list[str] = []
        for arg in arguments:
            arg_str = str(arg)
            if any(bad in arg_str for bad in ["\x00", "\n", "\r", ";", "&", "|", "`", "$("]):
                raise ExecutionError(f"Argument contains dangerous shell control characters: {arg_str!r}")
            if arg_str.startswith(("-exec", "--exec", "-command", "--command")):
                raise ExecutionError(f"Forbidden command argument flag: {arg_str}")
            sanitized_args.append(arg_str)

        start_time = datetime.now(timezone.utc).isoformat()
        exit_code = -1
        captured_output = ""
        captured_error: str | None = None

        # Clean, controlled execution environment
        safe_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LC_ALL": "C",
            "LANG": "C",
        }

        try:
            process = subprocess.run(
                [binary_path] + sanitized_args,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                shell=False,  # strictly no shell execution
                env=safe_env,
            )
            exit_code = process.returncode
            raw_output = process.stdout or ""
            if len(raw_output) > MAX_OUTPUT_CHARS:
                raw_output = raw_output[:MAX_OUTPUT_CHARS] + "\n...[OUTPUT TRUNCATED DUE TO SIZE LIMIT]..."
            captured_output = scrub_secrets(raw_output)

            if process.stderr:
                raw_err = process.stderr
                if len(raw_err) > MAX_OUTPUT_CHARS:
                    raw_err = raw_err[:MAX_OUTPUT_CHARS] + "\n...[STDERR TRUNCATED]..."
                captured_error = scrub_secrets(raw_err)

        except subprocess.TimeoutExpired:
            exit_code = 124
            captured_error = f"Command timed out after {self.timeout_seconds} seconds."
        except Exception as exc:
            exit_code = 1
            captured_error = f"Execution failed: {exc}"

        end_time = datetime.now(timezone.utc).isoformat()

        record = ToolExecutionRecord(
            tool=command,
            arguments=sanitized_args,
            scope_decision=scope_decision,
            start_time=start_time,
            end_time=end_time,
            exit_status=exit_code,
            output=captured_output,
            errors=captured_error,
        )

        self.audit_log.append(record)

        # Persist to central audit log if store is available
        try:
            from app.services.store import save_audit_log
            save_audit_log(record.model_dump())
        except Exception:
            pass

        return record


# Global default executor instance
safe_executor = SafeExecutor()
