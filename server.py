"""Windows Control Center Local MCP Server.

Provides AGY CLI / Antigravity with full, authorized access to your Windows computer locally:
- PowerShell & CMD command execution
- Python script runner (inside virtual environment)
- Process monitoring and management (CPU, RAM, termination)
- File system read/write/search/delete/copy
- System status (CPU, RAM, Disks, Battery, Uptime)
- Network configuration and connectivity
- Desktop automation (Application launcher, Clipboard, Notifications, Screenshots)

STRICT LOCALHOST ONLY: Binds exclusively to 127.0.0.1 on the /mcp endpoint. No cloud exposure.
"""

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional
from fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.routing import Route
import uvicorn

# Import underlying tool implementations
from tools.command_tools import (
    execute_cmd as _execute_cmd,
    execute_elevated_command as _execute_elevated_command,
    execute_powershell as _execute_powershell,
    execute_python as _execute_python,
    get_security_status as _get_security_status,
    kill_process as _kill_process,
    list_processes as _list_processes,
)
from tools.desktop_tools import (
    get_clipboard as _get_clipboard,
    launch_app as _launch_app,
    set_clipboard as _set_clipboard,
    show_notification as _show_notification,
    take_screenshot as _take_screenshot,
)
from tools.filesystem_tools import (
    copy_or_move as _copy_or_move,
    delete_file_or_dir as _delete_file_or_dir,
    get_file_info as _get_file_info,
    list_directory as _list_directory,
    read_file as _read_file,
    search_files as _search_files,
    write_file as _write_file,
)
from tools.system_tools import (
    get_environment as _get_environment,
    get_network_info as _get_network_info,
    get_system_info as _get_system_info,
)

# Configure logging to sys.stderr exclusively so stdout remains clean for MCP JSON-RPC
logger = logging.getLogger("WindowsMCP")
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
)

# Initialize FastMCP Server
mcp = FastMCP(
    name="Windows-Control-Center",
    instructions=(
        "Windows Control Center MCP Server. This server allows the AI assistant to interact "
        "with the user's Windows PC: executing shell commands (PowerShell/CMD), running Python scripts, "
        "reading/writing files, monitoring system health (CPU, RAM, Disks, Battery), inspecting "
        "and managing processes, reading/writing clipboard text, launching applications/URLs, "
        "taking desktop screenshots, and displaying desktop notifications."
    ),
)


# ==========================================
# Category 1: Command & Process Execution
# ==========================================


@mcp.tool()
def execute_powershell(
    command: str,
    working_dir: Optional[str] = None,
    timeout: int = 120,
    elevate: bool = False,
) -> Dict[str, Any]:
    """Execute a PowerShell command or script on the Windows computer.

    Protected by security guardrails against RCE, disk formatting, and malicious payloads.

    Args:
        command: The PowerShell command, cmdlet, or script block to run.
        working_dir: Working directory path (default: current directory).
        timeout: Maximum execution time in seconds before terminating (default: 120).
        elevate: Whether to request Windows administrative privilege elevation (default: False).

    Returns:
        Dictionary with 'stdout', 'stderr', 'return_code', 'execution_time_seconds', and 'timed_out'.
    """
    logger.info("Executing PowerShell command (elevate=%s): %s", elevate, command[:100])
    return _execute_powershell(command=command, working_dir=working_dir, timeout=timeout, elevate=elevate)


@mcp.tool()
def execute_elevated_command(
    command: str,
    timeout: int = 120,
) -> Dict[str, Any]:
    """Execute a command with Administrator / Elevated privileges via Windows UAC.

    Validates against security guardrails before granting elevation.

    Args:
        command: PowerShell command or script to execute with elevation.
        timeout: Maximum execution time in seconds (default: 120).

    Returns:
        Dictionary with stdout, stderr, return_code, execution_time_seconds, and elevation status.
    """
    logger.warning("Executing ELEVATED command: %s", command[:100])
    return _execute_elevated_command(command=command, timeout=timeout)


@mcp.tool()
def get_security_status() -> Dict[str, Any]:
    """Inspect active security guardrails, administrative status, and safeguards.

    Returns:
        Dictionary with is_admin, strict_mode, allow_elevation, and protection metrics.
    """
    return _get_security_status()


@mcp.tool()
def execute_cmd(
    command: str,
    working_dir: Optional[str] = None,
    timeout: int = 120,
) -> Dict[str, Any]:
    """Execute a Command Prompt (cmd.exe) command or batch line on Windows.

    Args:
        command: The cmd.exe command to run.
        working_dir: Working directory path (default: current directory).
        timeout: Maximum execution time in seconds (default: 120).

    Returns:
        Dictionary with 'stdout', 'stderr', 'return_code', and 'timed_out'.
    """
    logger.info("Executing CMD command: %s", command[:100])
    return _execute_cmd(command=command, working_dir=working_dir, timeout=timeout)


@mcp.tool()
def execute_python(
    code: str,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Execute Python code snippet directly inside this server's virtual environment.

    Args:
        code: Python source code snippet to execute.
        timeout: Maximum seconds to wait before terminating (default: 60).

    Returns:
        Dictionary with 'stdout', 'stderr', 'return_code', and 'timed_out'.
    """
    logger.info("Executing Python snippet (%d characters)", len(code))
    return _execute_python(code=code, timeout=timeout)


@mcp.tool()
def list_processes(
    filter_name: Optional[str] = None,
    sort_by: str = "cpu",
    limit: int = 25,
) -> List[Dict[str, Any]]:
    """List running processes on the system with PID, CPU %, memory usage, and user info.

    Args:
        filter_name: Optional case-insensitive substring to filter processes (e.g., 'chrome', 'python', 'code').
        sort_by: Metric to sort by: 'cpu' or 'memory' (default: 'cpu').
        limit: Maximum number of processes to return (default: 25).

    Returns:
        List of process objects containing pid, name, cpu_percent, memory_mb, status, username.
    """
    return _list_processes(filter_name=filter_name, sort_by=sort_by, limit=limit)


@mcp.tool()
def kill_process(
    pid: Optional[int] = None,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    """Terminate a running process by Process ID (PID) or process executable name.

    Guards critical Windows system processes (csrss, lsass, etc.) and the MCP server itself.

    Args:
        pid: The numeric Process ID to kill.
        name: Name of the process image to terminate (e.g., 'notepad.exe').

    Returns:
        Dictionary confirming killed processes and any permission/not-found errors.
    """
    logger.info("Killing process pid=%s, name=%s", pid, name)
    return _kill_process(pid=pid, name=name)


# ==========================================
# Category 2: File System Operations
# ==========================================


@mcp.tool()
def read_file(
    path: str,
    start_line: int = 1,
    max_lines: int = 500,
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """Read contents of a file on the local machine with line-range pagination.

    Args:
        path: Path to the target file (relative or absolute).
        start_line: 1-indexed line number to start reading from (default: 1).
        max_lines: Maximum number of lines to return (default: 500).
        encoding: File encoding (default: 'utf-8').

    Returns:
        Dictionary with file content, path, total_lines, and truncation status.
    """
    return _read_file(path=path, start_line=start_line, max_lines=max_lines, encoding=encoding)


@mcp.tool()
def write_file(
    path: str,
    content: str,
    mode: str = "w",
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """Write or append text content to a file. Automatically creates parent directories.

    Args:
        path: Path where the file should be written.
        content: Text content to write into the file.
        mode: 'w' to overwrite existing file, or 'a' to append (default: 'w').
        encoding: File encoding (default: 'utf-8').

    Returns:
        Dictionary with status, bytes written, and absolute path.
    """
    logger.info("Writing file %s (mode=%s, %d characters)", path, mode, len(content))
    return _write_file(path=path, content=content, mode=mode, encoding=encoding)


@mcp.tool()
def list_directory(
    path: str = ".",
    recursive: bool = False,
    max_depth: int = 2,
    max_items: int = 100,
) -> Dict[str, Any]:
    """List files and folders in a directory with file sizes and modification timestamps.

    Args:
        path: Directory path to inspect (default: current directory).
        recursive: Whether to recursively scan child directories (default: False).
        max_depth: Maximum recursion depth when recursive=True (default: 2).
        max_items: Maximum items to return (default: 100).

    Returns:
        Dictionary with item metadata (name, path, is_dir, size_bytes, modified).
    """
    return _list_directory(path=path, recursive=recursive, max_depth=max_depth, max_items=max_items)


@mcp.tool()
def search_files(
    pattern: str,
    root_path: str = ".",
    max_results: int = 50,
) -> Dict[str, Any]:
    """Search for files and directories matching a wildcard pattern (e.g. '*.py', 'report*.*').

    Args:
        pattern: Wildcard search pattern (e.g., '*.docx', 'config*.json').
        root_path: Root folder where search begins (default: current directory).
        max_results: Maximum results to return (default: 50).

    Returns:
        Dictionary with count and list of matched files.
    """
    return _search_files(pattern=pattern, root_path=root_path, max_results=max_results)


@mcp.tool()
def get_file_info(path: str) -> Dict[str, Any]:
    """Get detailed metadata for a file or directory (size, timestamps, permissions, extension).

    Args:
        path: Path to inspect.

    Returns:
        Dictionary with size, created, modified, accessed, and type information.
    """
    return _get_file_info(path=path)


@mcp.tool()
def delete_file_or_dir(path: str, recursive: bool = False) -> Dict[str, Any]:
    """Delete a file or directory on the computer safely.

    Protected against accidental or malicious deletion of system directories or drive roots.

    Args:
        path: Path of the file or directory to delete.
        recursive: If True, delete non-empty directories recursively (default: False).

    Returns:
        Dictionary confirming deletion action or error details.
    """
    logger.warning("Deleting path: %s (recursive=%s)", path, recursive)
    return _delete_file_or_dir(path=path, recursive=recursive)


@mcp.tool()
def copy_or_move(
    source: str,
    destination: str,
    action: str = "copy",
) -> Dict[str, Any]:
    """Copy or move a file or directory from source to destination.

    Validates that destination (and source if moving) is not a protected system path.

    Args:
        source: Source file or folder path.
        destination: Destination file or folder path.
        action: 'copy' or 'move' (default: 'copy').

    Returns:
        Dictionary confirming operation status and paths.
    """
    logger.info("%s from %s to %s", action.capitalize(), source, destination)
    return _copy_or_move(source=source, destination=destination, action=action)


# ==========================================
# Category 3: System & Hardware Monitoring
# ==========================================


@mcp.tool()
def get_system_info() -> Dict[str, Any]:
    """Get full system health: OS version, CPU cores & usage, RAM usage, all disk drives, and battery.

    Returns:
        Dictionary with detailed OS, CPU, Memory, Disk drives (C:, D:, E: etc.), and Battery stats.
    """
    return _get_system_info()


@mcp.tool()
def get_network_info() -> Dict[str, Any]:
    """Get network adapters, local IPv4 addresses, and check active internet connectivity.

    Returns:
        Dictionary with hostname, active adapters, IPv4 addresses, and internet ping status.
    """
    return _get_network_info()


@mcp.tool()
def get_environment(var_name: Optional[str] = None) -> Dict[str, Any]:
    """Get a specific environment variable or view common system environment variables.

    Masks sensitive secrets (keys, passwords, tokens) when STRICT_MODE is active.

    Args:
        var_name: Specific variable name to retrieve. If None, lists standard system variables.

    Returns:
        Dictionary with variable names and values.
    """
    return _get_environment(var_name=var_name)


# ==========================================
# Category 4: Desktop & GUI Automation
# ==========================================


@mcp.tool()
def launch_app(
    target: str,
    args: Optional[str] = None,
) -> Dict[str, Any]:
    """Launch an application (e.g. notepad, calc, code), open a file, or open a website URL.

    Guarded against shell command injection and dangerous system executables.

    Args:
        target: Application executable/shortcut name, document path, or website URL (e.g. 'https://...').
        args: Optional command line arguments.

    Returns:
        Dictionary with launch status and action taken.
    """
    logger.info("Launching: target=%s, args=%s", target, args)
    return _launch_app(target=target, args=args)


@mcp.tool()
def get_clipboard() -> Dict[str, Any]:
    """Read the current text content from the Windows clipboard.

    Returns:
        Dictionary with clipboard text content, character count, and empty status.
    """
    return _get_clipboard()


@mcp.tool()
def set_clipboard(text: str) -> Dict[str, Any]:
    """Copy text to the Windows clipboard so the user or an app can paste it.

    Args:
        text: Text string to place into clipboard.

    Returns:
        Dictionary indicating status and characters copied.
    """
    return _set_clipboard(text=text)


@mcp.tool()
def take_screenshot(save_path: Optional[str] = None) -> Dict[str, Any]:
    """Take a screenshot of the primary Windows display and save it as a PNG file.

    Args:
        save_path: Optional file path for the screenshot. Defaults to a timestamped file in 'screenshots/'.

    Returns:
        Dictionary with image path, dimensions, and capture status.
    """
    logger.info("Taking screenshot (save_path=%s)", save_path)
    return _take_screenshot(save_path=save_path)


@mcp.tool()
def show_notification(title: str, message: str) -> Dict[str, Any]:
    """Display a Windows toast or balloon notification on the user's desktop screen.

    Args:
        title: Notification header text.
        message: Notification message text.

    Returns:
        Dictionary confirming notification dispatch.
    """
    logger.info("Displaying desktop notification: '%s' - '%s'", title, message)
    return _show_notification(title=title, message=message)


# ==========================================
# Resources & Prompts
# ==========================================


@mcp.resource("system://specs")
def system_specs_resource() -> str:
    """Read-only resource presenting system hardware, OS, and disk summary."""
    info = _get_system_info()
    return json.dumps(info, indent=2)


@mcp.resource("system://network")
def system_network_resource() -> str:
    """Read-only resource presenting active network interfaces and connectivity."""
    info = _get_network_info()
    return json.dumps(info, indent=2)


@mcp.prompt("system_health_check")
def system_health_check_prompt() -> str:
    """Prompt template to inspect Windows laptop performance, disk space, and running tasks."""
    return (
        "Please check the overall health of my Windows computer. "
        "1. Check CPU and memory usage using `get_system_info`.\n"
        "2. Check if any disk drive is running out of space.\n"
        "3. List top 5 processes consuming the most CPU or memory using `list_processes`.\n"
        "4. Summarize any recommendations or issues found."
    )


# ==========================================
# Main Entry Point & Host Defense
# ==========================================

ALLOWED_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _is_loopback(host: str) -> bool:
    """Check if the provided host address is strictly a loopback address."""
    clean_host = host.strip().lower()
    return clean_host in ALLOWED_LOOPBACK_HOSTS or clean_host.startswith("127.")


def _is_safe_origin(origin: str) -> bool:
    """Validate that the Origin header comes from a trusted local context.

    Rejects arbitrary public website origins to prevent Cross-Origin Browser /
    DNS-Rebinding attacks against the local MCP server.
    """
    if not origin:
        return True
    origin_lower = origin.strip().lower()
    if origin_lower == "null":
        return True  # Local file / Electron
    if origin_lower.startswith(("http://127.0.0.1:", "http://localhost:")):
        return True
    if origin_lower.startswith(("vscode-", "cursor-")):
        return True
    return False


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Windows Control Center Local MCP Server for AGY CLI / Antigravity"
    )
    parser.add_argument(
        "--transport",
        choices=["http", "stdio"],
        default="http",
        help="MCP transport protocol (default: http). Use 'stdio' for direct sub-process spawning.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Local loopback host IP (default: 127.0.0.1 - strictly localhost only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Local port number (default: 8000)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--allow-remote-access",
        action="store_true",
        default=False,
        help="Explicitly permit binding to external network interfaces (INSECURE: allows LAN devices to execute local tools).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    logger.setLevel(getattr(logging, args.log_level))

    # Guardrail: Enforce loopback binding unless explicitly overridden
    if not _is_loopback(args.host) and not args.allow_remote_access:
        logger.error(
            "SECURITY REFUSAL: Refusing to bind to non-localhost address '%s'. "
            "MCP provides local OS execution and must remain loopback-only. "
            "If you intentionally require remote LAN access, pass '--allow-remote-access'.",
            args.host,
        )
        sys.exit(1)

    logger.info("Starting Windows-Control-Center Local MCP Server...")
    logger.info("Transport: %s", args.transport)

    if args.transport == "http":
        logger.info("Configuring Streamable HTTP local endpoint at /mcp...")

        base_app = mcp.http_app(
            transport="http",
            path="/mcp",
            host_origin_protection=False,
            allowed_hosts=["127.0.0.1", "localhost"],
            allowed_origins=["*"],
        )
        asgi_app = base_app.routes[0].endpoint

        class LocalCorsMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                origin = request.headers.get("origin", "")
                if origin and not _is_safe_origin(origin):
                    logger.warning("BLOCKED untrusted cross-origin request from: %s", origin)
                    return Response(
                        status_code=403,
                        content="Cross-Origin requests from external domains are prohibited.",
                    )

                allow_origin = origin if origin else "*"

                if request.method == "HEAD":
                    return Response(
                        status_code=200,
                        headers={
                            "Content-Type": "application/json",
                            "Access-Control-Allow-Origin": allow_origin,
                            "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        },
                    )
                if request.method == "OPTIONS":
                    return Response(
                        status_code=200,
                        headers={
                            "Access-Control-Allow-Origin": allow_origin,
                            "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
                            "Access-Control-Allow-Headers": "*",
                        },
                    )

                response = await call_next(request)
                response.headers["Access-Control-Allow-Origin"] = allow_origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, HEAD, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "*"
                return response

        # Strictly /mcp endpoint only (no cloud/sse routes)
        local_app = Starlette(
            routes=[
                Route("/mcp", asgi_app),
            ],
            middleware=[Middleware(LocalCorsMiddleware)],
            lifespan=base_app.lifespan,
        )

        logger.info(
            "Listening strictly on http://%s:%d/mcp (Local loopback only)",
            args.host,
            args.port,
        )
        uvicorn.run(
            local_app,
            host=args.host,
            port=args.port,
            log_level=args.log_level.lower(),
        )
    else:
        # stdio transport (local subprocess spawned by AGY CLI / clients)
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
