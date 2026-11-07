"""Command and process execution tools for Windows MCP Server."""

import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import psutil
from security import (
    PROTECTED_PROCESS_NAMES,
    execute_elevated,
    is_admin,
    validate_command,
    validate_python_code,
)


def _decode_output(raw_bytes: bytes) -> str:
    """Safely decode command line output using common Windows encodings."""
    if not raw_bytes:
        return ""
    for enc in ("utf-8", "cp1252", "oem", "latin-1"):
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def execute_powershell(
    command: str,
    working_dir: Optional[str] = None,
    timeout: int = 120,
    elevate: bool = False,
) -> Dict[str, Any]:
    """Execute a PowerShell command on the local Windows machine.

    Enforces security guardrails to block dangerous commands, disk destruction, and remote payloads.

    Args:
        command: The PowerShell command or script block to run.
        working_dir: Directory where the command should execute (default: current directory).
        timeout: Maximum seconds to wait before terminating (default: 120).
        elevate: Whether to request Windows administrative privilege elevation (default: False).

    Returns:
        A dictionary with stdout, stderr, return_code, execution_time_seconds, and timed_out status.
    """
    # If elevation requested, route through UAC elevation executor directly
    # (execute_elevated validates the command internally)
    if elevate:
        return execute_elevated(command, timeout=timeout)

    # Guardrail: Check command safety
    is_safe, security_err = validate_command(command)
    if not is_safe:
        return {
            "stdout": "",
            "stderr": security_err or "Command blocked by security guardrails.",
            "return_code": -1,
            "timed_out": False,
            "execution_time_seconds": 0.0,
            "blocked_by_guardrail": True,
        }

    cwd = os.path.abspath(working_dir) if working_dir else os.getcwd()
    if not os.path.exists(cwd):
        return {
            "stdout": "",
            "stderr": f"Working directory does not exist: {cwd}",
            "return_code": -1,
            "timed_out": False,
            "execution_time_seconds": 0.0,
        }

    # Use PowerShell with bypass policy and UTF-8 output encoding
    ps_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {command}",
    ]

    start_time = time.time()
    try:
        proc = subprocess.Popen(
            ps_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
        )
        try:
            raw_stdout, raw_stderr = proc.communicate(timeout=timeout)
            exec_time = round(time.time() - start_time, 2)
            return {
                "stdout": _decode_output(raw_stdout),
                "stderr": _decode_output(raw_stderr),
                "return_code": proc.returncode,
                "timed_out": False,
                "execution_time_seconds": exec_time,
            }
        except subprocess.TimeoutExpired:
            # Safely terminate process tree
            try:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                parent.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            proc.communicate()
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds.",
                "return_code": -1,
                "timed_out": True,
                "execution_time_seconds": timeout,
            }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Execution error: {str(e)}",
            "return_code": -1,
            "timed_out": False,
            "execution_time_seconds": round(time.time() - start_time, 2),
        }


def execute_cmd(
    command: str,
    working_dir: Optional[str] = None,
    timeout: int = 120,
) -> Dict[str, Any]:
    """Execute a Command Prompt (cmd.exe) command on Windows.

    Enforces security guardrails to block dangerous commands, disk destruction, and remote payloads.

    Args:
        command: The cmd.exe command to execute.
        working_dir: Working directory (default: current directory).
        timeout: Maximum seconds to wait before terminating (default: 120).

    Returns:
        A dictionary with stdout, stderr, return_code, execution_time_seconds, and timed_out status.
    """
    # Guardrail check
    is_safe, security_err = validate_command(command)
    if not is_safe:
        return {
            "stdout": "",
            "stderr": security_err or "Command blocked by security guardrails.",
            "return_code": -1,
            "timed_out": False,
            "execution_time_seconds": 0.0,
            "blocked_by_guardrail": True,
        }

    cwd = os.path.abspath(working_dir) if working_dir else os.getcwd()
    if not os.path.exists(cwd):
        return {
            "stdout": "",
            "stderr": f"Working directory does not exist: {cwd}",
            "return_code": -1,
            "timed_out": False,
            "execution_time_seconds": 0.0,
        }

    cmd = ["cmd.exe", "/c", command]
    start_time = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
        )
        try:
            raw_stdout, raw_stderr = proc.communicate(timeout=timeout)
            exec_time = round(time.time() - start_time, 2)
            return {
                "stdout": _decode_output(raw_stdout),
                "stderr": _decode_output(raw_stderr),
                "return_code": proc.returncode,
                "timed_out": False,
                "execution_time_seconds": exec_time,
            }
        except subprocess.TimeoutExpired:
            try:
                parent = psutil.Process(proc.pid)
                for child in parent.children(recursive=True):
                    try:
                        child.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                parent.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            proc.communicate()
            return {
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds.",
                "return_code": -1,
                "timed_out": True,
                "execution_time_seconds": timeout,
            }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Execution error: {str(e)}",
            "return_code": -1,
            "timed_out": False,
            "execution_time_seconds": round(time.time() - start_time, 2),
        }


def execute_python(
    code: str,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Execute Python code in the server's virtual environment.

    Enforces AST inspection to block dangerous system manipulation and remote payloads.

    Args:
        code: Python source code snippet to run.
        timeout: Maximum execution time in seconds (default: 60).

    Returns:
        A dictionary with stdout, stderr, return_code, execution_time_seconds, and timed_out status.
    """
    # Guardrail check
    is_safe, security_err = validate_python_code(code)
    if not is_safe:
        return {
            "stdout": "",
            "stderr": security_err or "Python code blocked by security guardrails.",
            "return_code": -1,
            "timed_out": False,
            "execution_time_seconds": 0.0,
            "blocked_by_guardrail": True,
        }

    start_time = time.time()
    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            raw_stdout, raw_stderr = proc.communicate(timeout=timeout)
            return {
                "stdout": _decode_output(raw_stdout),
                "stderr": _decode_output(raw_stderr),
                "return_code": proc.returncode,
                "timed_out": False,
                "execution_time_seconds": round(time.time() - start_time, 2),
            }
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return {
                "stdout": "",
                "stderr": f"Python execution timed out after {timeout} seconds.",
                "return_code": -1,
                "timed_out": True,
                "execution_time_seconds": timeout,
            }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Python execution failed: {str(e)}",
            "return_code": -1,
            "timed_out": False,
            "execution_time_seconds": round(time.time() - start_time, 2),
        }


def list_processes(
    filter_name: Optional[str] = None,
    sort_by: str = "cpu",
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """List running processes on the system with CPU, memory, and PID info.

    Args:
        filter_name: Optional substring to filter process names (case-insensitive, e.g., 'chrome').
        sort_by: Metric to sort by: 'cpu' or 'memory' (default: 'cpu').
        limit: Maximum number of processes to return (clamped between 1 and 500, default: 25).

    Returns:
        List of process information objects.
    """
    limit = max(1, min(limit, 500))
    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status", "username"]):
        try:
            info = p.info
            name = info.get("name") or ""
            if filter_name and filter_name.lower() not in name.lower():
                continue
            mem_mb = round(info["memory_info"].rss / (1024 * 1024), 1) if info.get("memory_info") else 0.0
            procs.append({
                "pid": info.get("pid"),
                "name": name,
                "cpu_percent": info.get("cpu_percent") or 0.0,
                "memory_mb": mem_mb,
                "status": info.get("status"),
                "username": info.get("username"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if sort_by.lower() == "memory":
        procs.sort(key=lambda x: x["memory_mb"], reverse=True)
    else:
        procs.sort(key=lambda x: x["cpu_percent"], reverse=True)

    return procs[:limit]


def kill_process(
    pid: Optional[int] = None,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    """Terminate a process by PID or process name, protecting critical OS and server processes.

    Args:
        pid: The Process ID to terminate.
        name: Name of process(es) to terminate (e.g., 'notepad.exe').

    Returns:
        A dictionary summarizing terminated processes and any errors.
    """
    if pid is None and not name:
        return {"success": False, "message": "Must provide either pid or name."}

    my_pid = os.getpid()
    try:
        parent_pid = psutil.Process(my_pid).ppid()
    except Exception:
        parent_pid = None

    killed = []
    errors = []

    # 1. Kill by PID
    if pid is not None:
        if pid in (my_pid, parent_pid):
            return {
                "success": False,
                "message": f"REFUSED: Termination of MCP server process or its direct parent (PID {pid}) is prohibited.",
                "killed_processes": [],
                "errors": ["Target process is protected."],
            }
        try:
            p = psutil.Process(pid)
            p_name = p.name()
            if p_name.lower() in PROTECTED_PROCESS_NAMES:
                return {
                    "success": False,
                    "message": f"REFUSED: Termination of critical Windows system process '{p_name}' (PID {pid}) is prohibited.",
                    "killed_processes": [],
                    "errors": ["Target process is protected."],
                }
            p.terminate()
            p.wait(timeout=3)
            killed.append({"pid": pid, "name": p_name})
        except psutil.TimeoutExpired:
            try:
                p.kill()
                killed.append({"pid": pid, "name": p.name(), "forced": True})
            except Exception as e:
                errors.append(f"PID {pid}: {str(e)}")
        except Exception as e:
            errors.append(f"PID {pid}: {str(e)}")

    # 2. Kill by Name
    if name:
        target_name_lower = name.strip().lower()
        if target_name_lower in PROTECTED_PROCESS_NAMES:
            return {
                "success": False,
                "message": f"REFUSED: Termination of critical Windows system process '{name}' is prohibited.",
                "killed_processes": [],
                "errors": ["Target process is protected."],
            }

        for p in psutil.process_iter(["pid", "name"]):
            try:
                p_info = p.info
                p_pid = p_info["pid"]
                p_name = p_info["name"] or ""
                if p_name.lower() == target_name_lower:
                    if p_pid in (my_pid, parent_pid):
                        errors.append(f"Skipped PID {p_pid} (MCP server process protected)")
                        continue
                    p.terminate()
                    killed.append({"pid": p_pid, "name": p_name})
            except Exception as e:
                errors.append(f"Process {name}: {str(e)}")

    return {
        "success": len(killed) > 0,
        "killed_processes": killed,
        "errors": errors,
    }


def execute_elevated_command(
    command: str,
    timeout: int = 120,
) -> Dict[str, Any]:
    """Execute a command with Administrator / Elevated privileges.

    Triggers Windows UAC elevation if not already running as Administrator.
    Strictly validates the command against security guardrails before permitting elevation.

    Args:
        command: PowerShell command to run with elevated permissions.
        timeout: Maximum seconds to wait before terminating (default: 120).

    Returns:
        Dictionary with command output, return code, and elevation status.
    """
    return execute_elevated(command=command, timeout=timeout)


def get_security_status() -> Dict[str, Any]:
    """Get the current security, guardrail, and privilege status of the MCP server.

    Returns:
        Dictionary detailing admin status, strict mode, elevation policy, and audit log file.
    """
    import security
    return {
        "is_admin": is_admin(),
        "strict_mode": security.STRICT_MODE,
        "allow_elevation": security.ALLOW_ELEVATION,
        "audit_log_path": security.AUDIT_LOG_FILE,
        "protected_system_roots": len(security.CRITICAL_PATHS) + len(security.SYSTEM_DRIVES),
        "dangerous_patterns_blocked": len(security.DANGEROUS_COMMAND_PATTERNS),
        "protected_system_processes": len(security.PROTECTED_PROCESS_NAMES),
    }
