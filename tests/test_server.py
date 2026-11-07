"""Unit tests for server initialization, tool registration, and network defenses."""

import asyncio
import unittest
from server import _is_loopback, _is_safe_host, _is_safe_origin, mcp


class TestServerConfiguration(unittest.TestCase):
    """Test suite for server tool registration and network defenses."""

    def test_registered_tools(self):
        """Verify that all 22 anticipated tools are registered on the FastMCP instance."""
        tools = asyncio.run(mcp.list_tools())
        tool_names = {t.name for t in tools}

        expected_tools = [
            "execute_powershell",
            "execute_elevated_command",
            "get_security_status",
            "execute_cmd",
            "execute_python",
            "list_processes",
            "kill_process",
            "read_file",
            "write_file",
            "list_directory",
            "search_files",
            "get_file_info",
            "delete_file_or_dir",
            "copy_or_move",
            "get_system_info",
            "get_network_info",
            "get_environment",
            "launch_app",
            "get_clipboard",
            "set_clipboard",
            "take_screenshot",
            "show_notification",
        ]

        self.assertEqual(len(tool_names), len(expected_tools))
        for expected in expected_tools:
            self.assertIn(expected, tool_names, f"Tool '{expected}' is missing from FastMCP registry")

    def test_registered_resources_and_prompts(self):
        """Verify that system resources and prompts are properly registered."""
        # Resources
        resources = asyncio.run(mcp.list_resources())
        resource_uris = {str(r.uri) for r in resources}
        self.assertIn("system://specs", resource_uris)
        self.assertIn("system://network", resource_uris)

        # Prompts
        prompts = asyncio.run(mcp.list_prompts())
        prompt_names = {p.name for p in prompts}
        self.assertIn("system_health_check", prompt_names)

    def test_loopback_detection(self):
        """Test loopback IP defense."""
        # Valid loopbacks
        for h in ("127.0.0.1", "localhost", "::1", "127.0.0.2", "127.1.2.3"):
            self.assertTrue(_is_loopback(h), f"Failed to identify loopback: {h}")

        # Invalid remote interfaces
        for h in ("0.0.0.0", "192.168.1.10", "10.0.0.1", "attacker.com", "8.8.8.8"):
            self.assertFalse(_is_loopback(h), f"Falsely identified as loopback: {h}")

    def test_safe_origin_detection(self):
        """Test CORS Origin defense against Drive-By Browser and DNS-Rebinding attacks."""
        # Safe origins
        self.assertTrue(_is_safe_origin(""))  # CLI / AGY CLI / curl
        self.assertTrue(_is_safe_origin("null"))  # Electron / local file
        self.assertTrue(_is_safe_origin("http://localhost"))
        self.assertTrue(_is_safe_origin("http://localhost:3000"))
        self.assertTrue(_is_safe_origin("http://127.0.0.1"))
        self.assertTrue(_is_safe_origin("http://127.0.0.1:8000"))
        self.assertTrue(_is_safe_origin("http://[::1]:8000"))
        self.assertTrue(_is_safe_origin("https://localhost:8000"))
        self.assertTrue(_is_safe_origin("vscode-webview://12345"))
        self.assertTrue(_is_safe_origin("cursor-webview://12345"))

        # Untrusted public web origins
        self.assertFalse(_is_safe_origin("https://evil.com"))
        self.assertFalse(_is_safe_origin("http://attacker.org"))
        self.assertFalse(_is_safe_origin("https://phishing.xyz"))
        self.assertFalse(_is_safe_origin("http://192.168.1.50:8000"))

    def test_safe_host_dns_rebinding_defense(self):
        """Test Host header validation to prevent DNS-Rebinding attacks."""
        # Safe local hosts
        self.assertTrue(_is_safe_host(""))
        self.assertTrue(_is_safe_host("127.0.0.1"))
        self.assertTrue(_is_safe_host("127.0.0.1:8000"))
        self.assertTrue(_is_safe_host("localhost"))
        self.assertTrue(_is_safe_host("localhost:8000"))
        self.assertTrue(_is_safe_host("::1"))
        self.assertTrue(_is_safe_host("testserver"))

        # Dangerous / rebind hosts
        self.assertFalse(_is_safe_host("evil.com"))
        self.assertFalse(_is_safe_host("evil.com:8000"))
        self.assertFalse(_is_safe_host("attacker.internal"))
        self.assertFalse(_is_safe_host("192.168.1.100:8000"))


if __name__ == "__main__":
    unittest.main()
