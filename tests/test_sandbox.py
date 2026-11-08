"""Unit tests for Windows Job Object Sandboxing Engine."""

import sys
import unittest
from unittest.mock import patch
from sandbox import (
    JobSandboxConfig,
    WindowsJobSandbox,
    is_job_sandbox_supported,
    run_in_job_sandbox,
)
from tools.command_tools import (
    execute_cmd,
    execute_powershell,
    execute_python,
    get_security_status,
)


class TestWindowsJobSandbox(unittest.TestCase):
    """Test suite for Windows Job Object sandboxing and resource containment."""

    def setUp(self):
        if not is_job_sandbox_supported():
            self.skipTest("Windows Job Object sandboxing requires Windows OS and pywin32.")

    def test_job_object_lifecycle(self):
        """Test creating and destroying a Windows Job Object with custom config."""
        cfg = JobSandboxConfig(
            max_memory_mb=256,
            max_job_memory_mb=512,
            max_processes=8,
            kill_on_close=True,
            ui_restrictions=True,
        )
        sandbox = WindowsJobSandbox(cfg)
        handle = sandbox.create_job()
        self.assertIsNotNone(handle)
        self.assertTrue(sandbox._is_active)
        sandbox.close()
        self.assertIsNone(sandbox.job_handle)
        self.assertFalse(sandbox._is_active)

    def test_run_in_job_sandbox_success(self):
        """Test executing a command inside the Job Object sandbox and receiving metrics."""
        raw_stdout, raw_stderr, ret, timed_out, metrics = run_in_job_sandbox(
            ["cmd.exe", "/c", "echo Sandbox Test Successful"],
            timeout=10,
        )
        self.assertEqual(ret, 0)
        self.assertFalse(timed_out)
        self.assertIn("Sandbox Test Successful", raw_stdout.decode())
        self.assertIn("peak_job_memory_mb", metrics)
        self.assertIn("total_processes_spawned", metrics)
        self.assertGreater(metrics["peak_job_memory_mb"], 0)

    def test_run_in_job_sandbox_timeout_atomic_kill(self):
        """Test that timeouts trigger atomic kernel termination of the entire job."""
        raw_stdout, raw_stderr, ret, timed_out, metrics = run_in_job_sandbox(
            ["powershell.exe", "-NoProfile", "-Command", "Start-Sleep -Seconds 15"],
            timeout=1,
        )
        self.assertTrue(timed_out)
        self.assertEqual(ret, -1)

    def test_process_quota_limit(self):
        """Test that exceeding max_processes triggers Windows kernel quota enforcement."""
        cfg = JobSandboxConfig(max_processes=2)
        code = (
            "import subprocess, sys\n"
            "for i in range(10):\n"
            "    try:\n"
            "        subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])\n"
            "    except OSError:\n"
            "        print('QUOTA_BLOCKED')\n"
            "        break\n"
        )
        raw_stdout, raw_stderr, ret, timed_out, _ = run_in_job_sandbox(
            [sys.executable, "-c", code],
            timeout=10,
            config=cfg,
        )
        self.assertIn("QUOTA_BLOCKED", raw_stdout.decode())

    def test_execute_powershell_sandboxed(self):
        """Test execute_powershell tool running with mandatory sandboxing."""
        res = execute_powershell("Write-Output 'PowerShell In Job Sandbox'")
        self.assertEqual(res["return_code"], 0)
        self.assertIn("PowerShell In Job Sandbox", res["stdout"])
        self.assertTrue(res.get("sandboxed"))
        self.assertEqual(res.get("sandbox_backend"), "windows_job_object")
        self.assertIn("sandbox_metrics", res)
        self.assertIn("peak_job_memory_mb", res["sandbox_metrics"])

    def test_execute_cmd_sandboxed(self):
        """Test execute_cmd tool running with mandatory sandboxing."""
        res = execute_cmd("echo CMD In Job Sandbox")
        self.assertEqual(res["return_code"], 0)
        self.assertIn("CMD In Job Sandbox", res["stdout"])
        self.assertTrue(res.get("sandboxed"))
        self.assertEqual(res.get("sandbox_backend"), "windows_job_object")

    def test_execute_python_sandboxed(self):
        """Test execute_python tool running with mandatory sandboxing."""
        res = execute_python("print(2 ** 10)")
        self.assertEqual(res["return_code"], 0)
        self.assertIn("1024", res["stdout"])
        self.assertTrue(res.get("sandboxed"))
        self.assertEqual(res.get("sandbox_backend"), "windows_job_object")

    def test_sandbox_is_mandatory_and_cannot_be_bypassed(self):
        """Test that every command execution is sandboxed and cannot be bypassed."""
        res_cmd = execute_cmd("echo Always Sandboxed")
        self.assertTrue(res_cmd.get("sandboxed"))
        self.assertEqual(res_cmd.get("sandbox_backend"), "windows_job_object")

        res_ps = execute_powershell("Write-Output 'Always Sandboxed'")
        self.assertTrue(res_ps.get("sandboxed"))
        self.assertEqual(res_ps.get("sandbox_backend"), "windows_job_object")

        res_py = execute_python("print('Always Sandboxed')")
        self.assertTrue(res_py.get("sandboxed"))
        self.assertEqual(res_py.get("sandbox_backend"), "windows_job_object")

    def test_get_security_status_includes_sandbox_info(self):
        """Test that get_security_status provides mandatory sandbox metadata."""
        status = get_security_status()
        self.assertEqual(status["sandbox_backend"], "windows_job_object")
        self.assertTrue(status["sandbox_supported"])
        self.assertTrue(status["sandbox_mandatory"])
        self.assertFalse(status["sandbox_bypass_allowed"])
        self.assertIn("sandbox_limits", status)
        self.assertEqual(status["sandbox_limits"]["max_memory_mb"], 512)
        self.assertEqual(status["sandbox_limits"]["max_processes"], 16)

    def test_job_assignment_failure_terminates_process(self):
        """Test that if assigning a process to the job sandbox fails, the process is killed and an error is raised."""
        with patch.object(WindowsJobSandbox, "assign_process", return_value=False):
            with self.assertRaises(RuntimeError) as ctx:
                run_in_job_sandbox([sys.executable, "-c", "import time; time.sleep(10)"], timeout=5)
            self.assertIn("Failed to assign child process", str(ctx.exception))

    def test_stdin_isolation_devnull(self):
        """Test that child process stdin is isolated with DEVNULL and EOF is reached immediately."""
        raw_stdout, raw_stderr, ret, timed_out, _ = run_in_job_sandbox(
            [sys.executable, "-c", "import sys; content = sys.stdin.read(); print(f'STDIN_LEN:{len(content)}')"],
            timeout=5,
        )
        self.assertEqual(ret, 0)
        self.assertFalse(timed_out)
        self.assertIn("STDIN_LEN:0", raw_stdout.decode())
