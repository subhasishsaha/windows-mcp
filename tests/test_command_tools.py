"""Unit tests for command execution, Python runner, and process management tools."""

import os
import unittest
from tools.command_tools import (
    execute_cmd,
    execute_powershell,
    execute_python,
    get_security_status,
    kill_process,
    list_processes,
)


class TestCommandTools(unittest.TestCase):
    """Test suite for command_tools module."""

    def test_execute_powershell_success(self):
        """Test successful execution of a PowerShell command."""
        res = execute_powershell("Write-Output 'Hello MCP'")
        self.assertEqual(res["return_code"], 0)
        self.assertIn("Hello MCP", res["stdout"])
        self.assertFalse(res["timed_out"])
        self.assertIn("execution_time_seconds", res)

    def test_execute_powershell_guardrail_block(self):
        """Test that PowerShell command guardrails block dangerous execution."""
        res = execute_powershell("format c: /fs:ntfs")
        self.assertEqual(res["return_code"], -1)
        self.assertTrue(res.get("blocked_by_guardrail"))
        self.assertIn("SECURITY POLICY VIOLATION", res["stderr"])

    def test_execute_powershell_invalid_working_dir(self):
        """Test PowerShell execution with non-existent working directory."""
        res = execute_powershell("dir", working_dir=r"C:\NonExistent_Dir_12345_MCP")
        self.assertEqual(res["return_code"], -1)
        self.assertIn("Working directory does not exist", res["stderr"])

    def test_execute_powershell_timeout(self):
        """Test that long-running commands terminate cleanly on timeout."""
        res = execute_powershell("Start-Sleep -Seconds 10", timeout=1)
        self.assertTrue(res["timed_out"])
        self.assertEqual(res["return_code"], -1)
        self.assertIn("timed out", res["stderr"])

    def test_execute_cmd_success(self):
        """Test successful execution of a CMD command."""
        res = execute_cmd("echo Hello CMD")
        self.assertEqual(res["return_code"], 0)
        self.assertIn("Hello CMD", res["stdout"])
        self.assertFalse(res["timed_out"])

    def test_execute_cmd_guardrail_block(self):
        """Test that CMD guardrails intercept dangerous commands."""
        res = execute_cmd("vssadmin delete shadows /all /quiet")
        self.assertEqual(res["return_code"], -1)
        self.assertTrue(res.get("blocked_by_guardrail"))
        self.assertIn("SECURITY POLICY VIOLATION", res["stderr"])

    def test_execute_python_success(self):
        """Test executing Python code snippet in virtual environment."""
        res = execute_python("import math; print(int(math.sqrt(64)))")
        self.assertEqual(res["return_code"], 0)
        self.assertIn("8", res["stdout"])
        self.assertFalse(res["timed_out"])

    def test_execute_python_guardrail_block(self):
        """Test that Python code guardrails intercept dangerous calls."""
        res = execute_python("import os; os.system('format c:')")
        self.assertEqual(res["return_code"], -1)
        self.assertTrue(res.get("blocked_by_guardrail"))
        self.assertIn("SECURITY POLICY VIOLATION", res["stderr"])

    def test_list_processes(self):
        """Test listing system processes."""
        procs = list_processes(limit=10)
        self.assertIsInstance(procs, list)
        self.assertGreater(len(procs), 0)
        first = procs[0]
        self.assertIn("pid", first)
        self.assertIn("name", first)
        self.assertIn("cpu_percent", first)
        self.assertIn("memory_mb", first)

        # Test filter
        filtered = list_processes(filter_name="python", limit=5)
        for p in filtered:
            self.assertIn("python", p["name"].lower())

    def test_kill_process_refuses_protected(self):
        """Test that kill_process protects critical OS and server processes."""
        # 1. Critical OS process name
        res = kill_process(name="csrss.exe")
        self.assertFalse(res["success"])
        self.assertIn("REFUSED", res["message"])

        # 2. Server's own PID
        my_pid = os.getpid()
        res_pid = kill_process(pid=my_pid)
        self.assertFalse(res_pid["success"])
        self.assertIn("REFUSED", res_pid["message"])

    def test_get_security_status(self):
        """Test inspecting server security status."""
        status = get_security_status()
        self.assertIn("is_admin", status)
        self.assertIn("strict_mode", status)
        self.assertIn("allow_elevation", status)
        self.assertIn("audit_log_path", status)
        self.assertIn("protected_system_roots", status)
        self.assertIn("dangerous_patterns_blocked", status)
        self.assertIn("protected_system_processes", status)


if __name__ == "__main__":
    unittest.main()
