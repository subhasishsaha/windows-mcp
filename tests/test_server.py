"""Unit tests for server initialization, tool registration, and network defenses."""

import asyncio
import os
import unittest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from server import LocalCorsMiddleware, _is_loopback, _is_safe_host, _is_safe_origin, mcp


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

        # Malicious domains attempting DNS rebinding via 127. prefix
        for h in (
            "127.0.0.1.attacker.com",
            "127.evil.com",
            "127.fake.net",
            "127.0.0.1.nip.io",
            "127.attacker.com",
            "127a.com",
        ):
            self.assertFalse(_is_loopback(h), f"Falsely identified DNS rebinding domain as loopback: {h}")

    def test_safe_origin_detection(self):
        """Test CORS Origin defense against Drive-By Browser and DNS-Rebinding attacks."""
        # Safe origins
        self.assertTrue(_is_safe_origin(""))  # CLI / AGY CLI / curl
        self.assertTrue(_is_safe_origin("http://localhost"))
        self.assertTrue(_is_safe_origin("http://localhost:3000"))
        self.assertTrue(_is_safe_origin("http://127.0.0.1"))
        self.assertTrue(_is_safe_origin("http://127.0.0.1:8000"))
        self.assertTrue(_is_safe_origin("http://[::1]:8000"))
        self.assertTrue(_is_safe_origin("https://localhost:8000"))
        self.assertTrue(_is_safe_origin("vscode-webview://12345"))
        self.assertTrue(_is_safe_origin("cursor-webview://12345"))

        # Untrusted public web origins & null origin (sandboxed iframes)
        self.assertFalse(_is_safe_origin("null"))  # Block null origin from browser sandboxed iframes
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
        self.assertTrue(_is_safe_host("[::1]"))
        self.assertTrue(_is_safe_host("[::1]:8000"))
        self.assertTrue(_is_safe_host("testserver"))

        # Dangerous / rebind hosts
        self.assertFalse(_is_safe_host("evil.com"))
        self.assertFalse(_is_safe_host("evil.com:8000"))
        self.assertFalse(_is_safe_host("attacker.internal"))
        self.assertFalse(_is_safe_host("192.168.1.100:8000"))
        self.assertFalse(_is_safe_host("127.0.0.1.attacker.com"))
        self.assertFalse(_is_safe_host("127.0.0.1.attacker.com:8000"))
        self.assertFalse(_is_safe_host("127.evil.com"))
        self.assertFalse(_is_safe_host("127.evil.com:8000"))
        self.assertFalse(_is_safe_host("127.attacker.com"))
        self.assertFalse(_is_safe_host("127.attacker.com:8000"))
        self.assertFalse(_is_safe_host("127-attacker.com"))
        self.assertFalse(_is_safe_host("127a.com"))

        # Malformed port & suffix DNS rebinding evasions
        self.assertFalse(_is_safe_host("[::1].evil.com"))
        self.assertFalse(_is_safe_host("[::1]:8000.evil.com"))
        self.assertFalse(_is_safe_host("127.0.0.1:8000.evil.com"))
        self.assertFalse(_is_safe_host("localhost:8000.evil.com"))
        self.assertFalse(_is_safe_host("127.0.0.1:abc"))
        self.assertFalse(_is_safe_host("[::1]:abc"))
        self.assertFalse(_is_safe_host("[::1]:70000"))
        self.assertFalse(_is_safe_host("127.0.0.1:0"))

    def test_auth_token_middleware(self):
        """Test optional MCP_AUTH_TOKEN Bearer authentication in LocalCorsMiddleware."""
        async def mock_endpoint(request):
            return JSONResponse({"status": "ok"})

        app = Starlette(
            routes=[Route("/mcp", mock_endpoint, methods=["GET", "POST"])],
            middleware=[Middleware(LocalCorsMiddleware, allowed_host="127.0.0.1")],
        )
        client = TestClient(app, base_url="http://127.0.0.1:8000")

        # 1. Without MCP_AUTH_TOKEN set, requests succeed
        old_token = os.environ.pop("MCP_AUTH_TOKEN", None)
        try:
            res = client.get("/mcp")
            self.assertEqual(res.status_code, 200)

            # 2. With MCP_AUTH_TOKEN set
            os.environ["MCP_AUTH_TOKEN"] = "super-secret-mcp-key"

            # Request without token is 401 Unauthorized
            res_no_auth = client.get("/mcp")
            self.assertEqual(res_no_auth.status_code, 401)
            self.assertIn("Unauthorized", res_no_auth.text)

            # Request with wrong token is 401
            res_wrong = client.get("/mcp", headers={"Authorization": "Bearer wrong-key"})
            self.assertEqual(res_wrong.status_code, 401)

            # Request with correct Bearer token succeeds
            res_ok = client.get("/mcp", headers={"Authorization": "Bearer super-secret-mcp-key"})
            self.assertEqual(res_ok.status_code, 200)
            self.assertEqual(res_ok.json(), {"status": "ok"})

            # OPTIONS preflight request succeeds without auth
            res_options = client.options("/mcp")
            self.assertEqual(res_options.status_code, 200)

            # Case-insensitive auth scheme per RFC 7235
            res_lower_scheme = client.get("/mcp", headers={"Authorization": "bearer super-secret-mcp-key"})
            self.assertEqual(res_lower_scheme.status_code, 200)

            res_upper_scheme = client.get("/mcp", headers={"Authorization": "BEARER super-secret-mcp-key"})
            self.assertEqual(res_upper_scheme.status_code, 200)

            res_lower_header = client.get("/mcp", headers={"authorization": "Bearer super-secret-mcp-key"})
            self.assertEqual(res_lower_header.status_code, 200)
        finally:
            if old_token is not None:
                os.environ["MCP_AUTH_TOKEN"] = old_token
            else:
                os.environ.pop("MCP_AUTH_TOKEN", None)

    def test_local_cors_middleware_blocks_dns_rebinding_hosts(self):
        """Ensure LocalCorsMiddleware blocks requests with DNS-rebinding Host headers (HTTP 403)."""
        async def mock_endpoint(request):
            return JSONResponse({"status": "ok"})

        app = Starlette(
            routes=[Route("/mcp", mock_endpoint, methods=["GET", "POST"])],
            middleware=[Middleware(LocalCorsMiddleware, allowed_host="127.0.0.1")],
        )
        client = TestClient(app, base_url="http://127.0.0.1:8000")

        # DNS rebinding hosts must receive 403 Forbidden
        rebinding_hosts = [
            "127.0.0.1.attacker.com",
            "127.0.0.1.attacker.com:8000",
            "127.evil.com",
            "127.evil.com:8000",
            "127.attacker.com:8000",
            "evil.com",
            "evil.com:8000",
            "[::1].evil.com",
            "127.0.0.1:8000.evil.com",
            "localhost:8000.evil.com",
            "[::1]:8000.evil.com",
        ]
        for bad_host in rebinding_hosts:
            res = client.get("/mcp", headers={"host": bad_host})
            self.assertEqual(res.status_code, 403, f"Host '{bad_host}' was not blocked (got {res.status_code})")
            self.assertIn("Host header validation failed", res.text)

        # Legitimate loopback hosts must receive 200 OK
        valid_hosts = [
            "127.0.0.1",
            "127.0.0.1:8000",
            "localhost",
            "localhost:8000",
            "testserver",
        ]
        for good_host in valid_hosts:
            res = client.get("/mcp", headers={"host": good_host})
            self.assertEqual(res.status_code, 200, f"Valid host '{good_host}' was blocked (got {res.status_code})")


if __name__ == "__main__":
    unittest.main()
