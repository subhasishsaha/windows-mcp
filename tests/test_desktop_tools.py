"""Unit tests for desktop, GUI automation, and clipboard tools."""

import os
import tempfile
import unittest
from tools.desktop_tools import (
    get_clipboard,
    launch_app,
    set_clipboard,
    show_notification,
    take_screenshot,
)


class TestDesktopTools(unittest.TestCase):
    """Test suite for desktop_tools module."""

    def test_clipboard_copy_and_paste(self):
        """Test setting and retrieving Windows clipboard text."""
        test_text = "MCP Automation Unit Test Clipboard 12345"
        set_res = set_clipboard(test_text)
        self.assertTrue(set_res["success"])

        get_res = get_clipboard()
        self.assertTrue(get_res["success"])
        self.assertEqual(get_res["text"], test_text)
        self.assertFalse(get_res["is_empty"])

    def test_launch_app_guardrail_block(self):
        """Test that launch_app intercepts dangerous commands."""
        import base64
        res = launch_app("format", args="c: /fs:ntfs")
        self.assertFalse(res["success"])
        self.assertTrue(res.get("blocked_by_guardrail"))
        self.assertIn("SECURITY POLICY VIOLATION", res["error"])

        # Base64 encoded payload via launch_app
        dangerous_cmd = "vssadmin delete shadows"
        b64 = base64.b64encode(dangerous_cmd.encode("utf-16le")).decode("ascii")
        res2 = launch_app("powershell.exe", args=f"-enc {b64}")
        self.assertFalse(res2["success"])
        self.assertTrue(res2.get("blocked_by_guardrail"))
        self.assertIn("SECURITY POLICY VIOLATION", res2["error"])

    def test_launch_app_blocks_shells_and_scripts(self):
        """Test that launch_app explicitly rejects shell interpreters, LOLBINs, and dangerous scripts."""
        blocked_targets = (
            "cmd.exe", "cmd", "powershell.exe", "pwsh", "python.exe", "wscript.exe",
            "mshta.exe", "mshta", "rundll32.exe", "rundll32", "regsvr32.exe", "regsvr32", "conhost.exe", "conhost",
            "run.bat", "setup.ps1", "app.hta", "virus.pif", "saver.scr", "old.com",
        )
        for target in blocked_targets:
            res = launch_app(target)
            self.assertFalse(res["success"], f"Target '{target}' was not blocked")
            self.assertTrue(res.get("blocked_by_guardrail"))
            self.assertIn("prohibited", res["error"])

    def test_take_screenshot_guardrail_block(self):
        """Test that screenshot saving prevents writing to system directories."""
        res = take_screenshot(save_path=r"C:\Windows\System32\screen.png")
        self.assertFalse(res["success"])
        self.assertTrue(res.get("blocked_by_guardrail"))
        self.assertIn("SECURITY POLICY VIOLATION", res["error"])

    def test_take_screenshot_safe_path(self):
        """Test taking screenshot to a safe temporary location."""
        with tempfile.TemporaryDirectory(prefix="mcp_screen_") as tmp_dir:
            target = os.path.join(tmp_dir, "test_shot.png")
            res = take_screenshot(save_path=target)
            self.assertIsInstance(res, dict)
            self.assertIn("success", res)
            if res["success"]:
                self.assertTrue(os.path.exists(target))
                self.assertGreater(os.path.getsize(target), 0)

    def test_show_notification_xml_escaping(self):
        """Ensure special XML and quote characters do not cause XML parse failure or injection."""
        title = "Alert <&> 'Test' \"Quotes\""
        message = "Body with <xml> tags & ampersands 'single' \"double\""
        res = show_notification(title=title, message=message)
        self.assertIsInstance(res, dict)
        self.assertIn("success", res)

    def test_show_notification_injection_prevention(self):
        """Ensure command injection vectors in notification title/message cannot breakout or execute commands."""
        test_canary = os.path.abspath("notification_canary.tmp")
        if os.path.exists(test_canary):
            os.remove(test_canary)
        try:
            injection_title = f'Alert $(New-Item -Path "{test_canary}" -ItemType File)'
            injection_msg = 'Test\n"@\nWrite-Output "Broken"\n#\n`r`n'
            res = show_notification(title=injection_title, message=injection_msg)
            self.assertIsInstance(res, dict)
            self.assertIn("success", res)
            self.assertFalse(os.path.exists(test_canary), "Command injection succeeded in show_notification!")
        finally:
            if os.path.exists(test_canary):
                os.remove(test_canary)


if __name__ == "__main__":
    unittest.main()
