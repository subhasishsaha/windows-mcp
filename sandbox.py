"""Windows Job Object Sandboxing Engine for Windows MCP Server.

Provides kernel-enforced containment and resource isolation for subprocess execution:
- Memory limits (process and job-wide commitments)
- Process count limits (anti-fork bomb defense)
- Atomic termination of complete process trees on timeout or parent death
- UI restrictions (blocks desktop switching, system shutdown, global atom table manipulation)
"""

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# Try importing Win32 APIs
try:
    import win32api
    import win32con
    import win32job
    import pywintypes
    HAS_WIN32JOB = True
except ImportError:
    HAS_WIN32JOB = False


@dataclass
class JobSandboxConfig:
    """Configuration options and resource quotas for Windows Job Object sandbox."""
    max_memory_mb: int = 512              # Per-process memory limit
    max_job_memory_mb: int = 1024         # Cumulative job memory limit
    max_processes: int = 16               # Maximum concurrent processes (fork-bomb mitigation)
    kill_on_close: bool = True            # Terminate child processes if job handle closes or server dies
    ui_restrictions: bool = True          # Block UI interaction, desktop switching, shutdown calls
    die_on_unhandled_exception: bool = True  # Suppress GUI crash dialogs (WerFault.exe)


def is_job_sandbox_supported() -> bool:
    """Check if Windows Job Object sandboxing is supported in the current environment."""
    return HAS_WIN32JOB and os.name == "nt"


class WindowsJobSandbox:
    """Manages a Win32 Job Object lifecycle with strict resource quotas and restrictions."""

    def __init__(self, config: Optional[JobSandboxConfig] = None) -> None:
        self.config = config or JobSandboxConfig()
        self.job_handle = None
        self._is_active = False

    def __enter__(self) -> "WindowsJobSandbox":
        self.create_job()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def create_job(self) -> Any:
        """Create and configure the Win32 Job Object."""
        if not is_job_sandbox_supported():
            return None

        # Create an anonymous job object
        self.job_handle = win32job.CreateJobObject(None, "")

        # 1. Configure Basic & Extended Limit Information
        extended_limits = win32job.QueryInformationJobObject(
            self.job_handle,
            win32job.JobObjectExtendedLimitInformation,
        )

        limit_flags = 0
        if self.config.kill_on_close:
            limit_flags |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if self.config.die_on_unhandled_exception:
            limit_flags |= win32job.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION

        if self.config.max_memory_mb > 0:
            limit_flags |= win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY
            extended_limits["ProcessMemoryLimit"] = int(self.config.max_memory_mb * 1024 * 1024)

        if self.config.max_job_memory_mb > 0:
            limit_flags |= win32job.JOB_OBJECT_LIMIT_JOB_MEMORY
            extended_limits["JobMemoryLimit"] = int(self.config.max_job_memory_mb * 1024 * 1024)

        if self.config.max_processes > 0:
            limit_flags |= win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            extended_limits["BasicLimitInformation"]["ActiveProcessLimit"] = int(self.config.max_processes)

        extended_limits["BasicLimitInformation"]["LimitFlags"] = limit_flags
        win32job.SetInformationJobObject(
            self.job_handle,
            win32job.JobObjectExtendedLimitInformation,
            extended_limits,
        )

        # 2. Configure Basic UI Restrictions (if enabled)
        if self.config.ui_restrictions:
            ui_flags = (
                win32job.JOB_OBJECT_UILIMIT_HANDLES            # Prevent using handles of windows outside the job
                | win32job.JOB_OBJECT_UILIMIT_GLOBALATOMS      # Prevent adding atoms to the global atom table
                | win32job.JOB_OBJECT_UILIMIT_DESKTOP          # Prevent creating or switching desktops
                | win32job.JOB_OBJECT_UILIMIT_EXITWINDOWS      # Prevent calling ExitWindows or ExitWindowsEx
                | win32job.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS  # Prevent changing system parameters
            )
            win32job.SetInformationJobObject(
                self.job_handle,
                win32job.JobObjectBasicUIRestrictions,
                {"UIRestrictionsClass": ui_flags},
            )

        self._is_active = True
        return self.job_handle

    def assign_process(self, proc: subprocess.Popen) -> bool:
        """Assign a running subprocess to the Job Object.

        Args:
            proc: Subprocess instance to bind to the sandbox.

        Returns:
            True if assigned successfully; False if the process exited before assignment or assignment failed.
        """
        if not self.job_handle or not self._is_active:
            return False

        try:
            # Proc._handle is the Win32 HANDLE to the child process
            raw_handle = int(proc._handle)
            win32job.AssignProcessToJobObject(self.job_handle, raw_handle)
            return True
        except pywintypes.error as err:
            # WinError 5 (Access Denied) happens if process terminated before assignment
            if proc.poll() is not None:
                return False
            # Otherwise re-raise or return False
            return False
        except Exception:
            return False

    def terminate(self, exit_code: int = 1) -> bool:
        """Atomically terminate all processes running inside the Job Object.

        Args:
            exit_code: Exit code assigned to terminated processes.

        Returns:
            True if terminated successfully.
        """
        if not self.job_handle or not self._is_active:
            return False
        try:
            win32job.TerminateJobObject(self.job_handle, exit_code)
            return True
        except Exception:
            return False

    def get_metrics(self) -> Dict[str, Any]:
        """Query resource accounting metrics from the Job Object.

        Returns:
            Dictionary with peak memory, total processes, and CPU time.
        """
        if not self.job_handle or not self._is_active:
            return {}

        metrics: Dict[str, Any] = {}
        try:
            extended = win32job.QueryInformationJobObject(
                self.job_handle,
                win32job.JobObjectExtendedLimitInformation,
            )
            peak_job_bytes = extended.get("PeakJobMemoryUsed", 0)
            peak_proc_bytes = extended.get("PeakProcessMemoryUsed", 0)
            metrics["peak_job_memory_mb"] = round(peak_job_bytes / (1024 * 1024), 2)
            metrics["peak_process_memory_mb"] = round(peak_proc_bytes / (1024 * 1024), 2)
        except Exception:
            pass

        try:
            accounting = win32job.QueryInformationJobObject(
                self.job_handle,
                win32job.JobObjectBasicAccountingInformation,
            )
            metrics["total_processes_spawned"] = accounting.get("TotalProcesses", 0)
            metrics["active_processes"] = accounting.get("ActiveProcesses", 0)
            # Time in 100-nanosecond units: 10,000,000 units = 1 second
            user_time = accounting.get("TotalUserTime", 0) / 10_000_000
            kernel_time = accounting.get("TotalKernelTime", 0) / 10_000_000
            metrics["cpu_user_seconds"] = round(user_time, 3)
            metrics["cpu_kernel_seconds"] = round(kernel_time, 3)
        except Exception:
            pass

        return metrics

    def close(self) -> None:
        """Close the Job Object handle, terminating child processes if kill_on_close is set."""
        if self.job_handle:
            try:
                win32api.CloseHandle(self.job_handle)
            except Exception:
                pass
            finally:
                self.job_handle = None
                self._is_active = False


def run_in_job_sandbox(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = 120,
    config: Optional[JobSandboxConfig] = None,
) -> Tuple[bytes, bytes, int, bool, Dict[str, Any]]:
    """Execute a command inside an isolated Windows Job Object sandbox.

    Args:
        cmd: Command and arguments list.
        cwd: Working directory.
        timeout: Maximum seconds before atomic termination.
        config: Optional JobSandboxConfig limits.

    Returns:
        Tuple of (stdout_bytes, stderr_bytes, return_code, timed_out, metrics).
    """
    cfg = config or JobSandboxConfig()
    sandbox = WindowsJobSandbox(cfg)
    sandbox.create_job()

    timed_out = False
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
        )
        # Immediately assign the process to the Job Object
        sandbox.assign_process(proc)

        try:
            raw_stdout, raw_stderr = proc.communicate(timeout=timeout)
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            # Atomically terminate the entire process hierarchy in kernel
            sandbox.terminate(exit_code=win32con.STATUS_TIMEOUT if HAS_WIN32JOB else -1)
            raw_stdout, raw_stderr = proc.communicate()
            returncode = -1

        metrics = sandbox.get_metrics()
        return raw_stdout, raw_stderr, returncode, timed_out, metrics

    finally:
        sandbox.close()
