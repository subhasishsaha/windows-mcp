"""System and hardware monitoring tools for Windows MCP Server."""

import os
import platform
import re
import socket
import time
from typing import Any, Dict, Optional
import psutil
from security import STRICT_MODE

SENSITIVE_VAR_PATTERN = re.compile(
    r"(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|CERT|PRIVATE|SIGNING|PAT|CONNSTR|CONNECTIONSTRING|DATABASE_URL|DB_URI|REDIS_URL|MONGO_URI|API_KEY|ACCESS_KEY|CLIENT_SECRET)",
    re.IGNORECASE,
)


def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system status: OS, CPU, RAM, Disk partitions, and Battery.

    Returns:
        Dictionary containing hardware and OS status metrics.
    """
    # CPU
    cpu_usage = psutil.cpu_percent(interval=0.3)
    cpu_count_logical = psutil.cpu_count(logical=True)
    cpu_count_physical = psutil.cpu_count(logical=False)

    # Memory
    mem = psutil.virtual_memory()
    mem_total_gb = round(mem.total / (1024**3), 2)
    mem_avail_gb = round(mem.available / (1024**3), 2)
    mem_used_gb = round(mem.used / (1024**3), 2)

    # Disks
    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
                "total_gb": round(usage.total / (1024**3), 2),
                "used_gb": round(usage.used / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "percent_used": usage.percent,
            })
        except (PermissionError, OSError):
            continue

    # Battery
    battery = psutil.sensors_battery()
    battery_info = None
    if battery is not None:
        battery_info = {
            "percent": battery.percent,
            "plugged_in": battery.power_plugged,
            "seconds_left": battery.secsleft if battery.secsleft >= 0 else "Charging or calculating",
        }

    # Uptime
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)
    uptime_str = f"{uptime_seconds // 3600}h {(uptime_seconds % 3600) // 60}m"

    return {
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "hostname": socket.gethostname(),
        "username": os.environ.get("USERNAME", "Unknown"),
        "uptime": uptime_str,
        "cpu": {
            "usage_percent": cpu_usage,
            "physical_cores": cpu_count_physical,
            "logical_cores": cpu_count_logical,
        },
        "memory": {
            "total_gb": mem_total_gb,
            "used_gb": mem_used_gb,
            "available_gb": mem_avail_gb,
            "percent_used": mem.percent,
        },
        "disks": disks,
        "battery": battery_info,
    }


def get_network_info() -> Dict[str, Any]:
    """Get active network adapters, IP addresses, and check internet connectivity.

    Returns:
        Dictionary with adapter info, local IPs, and internet connection status.
    """
    interfaces = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for name, addr_list in addrs.items():
        is_up = stats[name].isup if name in stats else False
        ipv4_list = [a.address for a in addr_list if a.family == socket.AF_INET]
        if ipv4_list and is_up:
            interfaces.append({
                "interface": name,
                "is_up": is_up,
                "ipv4": ipv4_list,
                "speed_mbps": stats[name].speed if name in stats else 0,
            })

    # Test internet connection
    has_internet = False
    for test_target in (("8.8.8.8", 53), ("1.1.1.1", 53)):
        try:
            sock = socket.create_connection(test_target, timeout=2)
            sock.close()
            has_internet = True
            break
        except OSError:
            continue

    return {
        "hostname": socket.gethostname(),
        "internet_connected": has_internet,
        "active_interfaces": interfaces,
    }


def get_environment(var_name: Optional[str] = None) -> Dict[str, Any]:
    """Get a specific environment variable or list common non-sensitive environment variables.

    In STRICT_MODE, values of sensitive environment variables (keys, secrets, passwords, tokens)
    are masked to prevent accidental leakage in LLM contexts.

    Args:
        var_name: Specific variable name to look up. If None, returns common system vars.

    Returns:
        Dictionary of variable names and values.
    """
    if var_name:
        val = os.environ.get(var_name)
        if val is not None and STRICT_MODE and SENSITIVE_VAR_PATTERN.search(var_name):
            return {
                "variable": var_name,
                "value": "********",
                "is_masked": True,
                "exists": True,
                "note": "Sensitive environment variable masked in STRICT_MODE.",
            }
        return {
            "variable": var_name,
            "value": val,
            "exists": val is not None,
            "is_masked": False,
        }

    # Whitelist of safe variables to expose when listing
    safe_vars = [
        "COMPUTERNAME",
        "OS",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "NUMBER_OF_PROCESSORS",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "PATHEXT",
    ]
    result = {}
    for k in safe_vars:
        if k in os.environ:
            result[k] = os.environ[k]

    return {"environment_variables": result}
