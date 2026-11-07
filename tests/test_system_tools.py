"""Unit tests for system monitoring and hardware tools."""

import os
import unittest
from tools.system_tools import get_environment, get_network_info, get_system_info


class TestSystemTools(unittest.TestCase):
    """Test suite for system_tools module."""

    def test_get_system_info(self):
        """Test retrieving system hardware and OS status."""
        info = get_system_info()
        self.assertIn("os", info)
        self.assertIn("cpu", info)
        self.assertIn("memory", info)
        self.assertIn("disks", info)
        self.assertIn("hostname", info)
        self.assertIn("uptime", info)

        # Validate cpu fields
        cpu = info["cpu"]
        self.assertIn("usage_percent", cpu)
        self.assertIn("logical_cores", cpu)
        self.assertGreater(cpu["logical_cores"], 0)

        # Validate memory fields
        mem = info["memory"]
        self.assertGreater(mem["total_gb"], 0)
        self.assertGreaterEqual(mem["percent_used"], 0)

        # Validate disk fields
        disks = info["disks"]
        self.assertIsInstance(disks, list)
        self.assertGreater(len(disks), 0)
        self.assertIn("device", disks[0])
        self.assertIn("mountpoint", disks[0])

    def test_get_network_info(self):
        """Test retrieving network adapters and connectivity status."""
        net = get_network_info()
        self.assertIn("hostname", net)
        self.assertIn("internet_connected", net)
        self.assertIn("active_interfaces", net)
        self.assertIsInstance(net["internet_connected"], bool)
        self.assertIsInstance(net["active_interfaces"], list)

    def test_get_environment_whitelist(self):
        """Test retrieving whitelisted safe environment variables."""
        env = get_environment()
        self.assertIn("environment_variables", env)
        vars_dict = env["environment_variables"]
        self.assertIn("OS", vars_dict)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", vars_dict)

    def test_get_environment_specific_and_masking(self):
        """Test looking up specific variables and masking secrets in STRICT_MODE."""
        # Non-sensitive variable
        res_os = get_environment(var_name="OS")
        self.assertTrue(res_os["exists"])
        self.assertFalse(res_os["is_masked"])
        self.assertIsNotNone(res_os["value"])

        # Sensitive variable masking
        test_var_name = "TEST_MCP_SECRET_KEY"
        os.environ[test_var_name] = "super_confidential_secret_value"
        try:
            res_secret = get_environment(var_name=test_var_name)
            self.assertTrue(res_secret["exists"])
            self.assertTrue(res_secret["is_masked"])
            self.assertEqual(res_secret["value"], "********")
            self.assertIn("note", res_secret)
        finally:
            del os.environ[test_var_name]


if __name__ == "__main__":
    unittest.main()
