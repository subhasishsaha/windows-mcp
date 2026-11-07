# 🪟 Windows Control Center MCP Server

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6.svg)](https://www.microsoft.com/windows)
[![Protocol: Model Context Protocol](https://img.shields.io/badge/protocol-MCP%202024--11--05-purple.svg)](https://modelcontextprotocol.io/)
[![Built with FastMCP](https://img.shields.io/badge/built%20with-FastMCP%20v4-brightgreen.svg)](https://github.com/jlowin/fastmcp)
[![Tests: 50 Passing](https://img.shields.io/badge/tests-50%20passed-success.svg)](tests/)

A secure, high-performance, strictly local **Model Context Protocol (MCP)** server built with **FastMCP** that connects AI assistants (**Antigravity, AGY CLI, Claude Desktop, Cursor, Cline, Roo Code**) to your local Windows environment.

It provides authorized, guardrail-protected control over:
- **PowerShell & CMD Execution** (with optional Windows UAC elevation)
- **Virtual Environment Python Runner** (with AST-based safety analysis)
- **Process Inspection & Management** (CPU/RAM metrics, safe termination)
- **Filesystem Operations** (read with pagination, write, search, move, safe delete)
- **Hardware & System Health Monitoring** (CPU, RAM, Disks, Battery, Uptime, Network)
- **Desktop & GUI Automation** (Application launcher, Clipboard, Toast notifications, Screenshots)

---

## 🛡️ Security Architecture & Guardrails

Connecting an LLM to native OS execution requires defense-in-depth. Windows Control Center MCP implements a multi-layer security engine ([`security.py`](security.py)) that actively validates all commands, code, and paths prior to execution.

```
                  ┌────────────────────────────────────────────────────────┐
                  │                   AI Client / Agent                    │
                  │   (AGY CLI / Claude Desktop / Cursor / Cline / Roo)    │
                  └───────────────────────────┬────────────────────────────┘
                                              │ (JSON-RPC via HTTP / Stdio)
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                             Windows Control Center MCP Server                            │
│                                                                                          │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                              Security Guardrail Engine                             │  │
│  │                                                                                    │  │
│  │   [Command Guard]            [AST Code Guard]             [Path Safety Guard]      │  │
│  │   • RCE & Download Cradles   • Shell string inspection    • Drive root protection  │  │
│  │   • Ransomware / VSSAdmin    • Path deletion inspection   • Critical OS dirs       │  │
│  │   • Defender / Firewall Off  • Obfuscated exec/eval block • Junction resolution   │  │
│  │   • Base64 De-obfuscation    • Network socket guards      • User AppData guards    │  │
│  └────────────────────────────────────────┬───────────────────────────────────────────┘  │
│                                           │                                              │
│                                           ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                   Tool Catalog                                     │  │
│  │   • PowerShell & CMD         • Filesystem Tools          • System Monitoring       │  │
│  │   • Python Runner            • Desktop Automation        • Windows UAC Elevation   │  │
│  └────────────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Remote Code Execution (RCE) & Download Cradles
- Intercepts and blocks download-and-execute pipelines (`curl/wget/iwr/irm | iex/powershell/cmd/sh`).
- Blocks remote script download methods (`(New-Object Net.WebClient).DownloadString(...)`).
- Intercepts Living-off-the-Land (LOLBIN) download vectors (`certutil -urlcache`, `bitsadmin /transfer`, `mshta http://...`, `regsvr32 /i:http`, `msiexec /i http://...`).
- Blocks reverse shell listeners (`nc -e`, `ncat`, `netcat`, `powercat`, `bash -i >& /dev/tcp`).

### 2. Base64 De-obfuscation & Deep Inspection
- Detects PowerShell `-EncodedCommand` / `-enc` payloads.
- Automatically decodes base64 UTF-16LE payloads and recursively validates the inner command string against security policies.

### 3. Python AST Code Inspection
- The `execute_python` runner parses Python code into an Abstract Syntax Tree (AST).
- Analyzes function calls:
  - Validates command strings passed to `os.system()`, `subprocess.run()`, `subprocess.Popen()`.
  - Validates paths passed to `shutil.rmtree()`, `os.remove()`, `os.unlink()`, `os.rmdir()`.
  - Validates file write targets in `open(..., 'w'/'a')`.
  - Blocks dynamic obfuscation constructs (`exec(base64.b64decode(...))`).

### 4. Disk & Partition Destruction Guards
- Prohibits destructive commands: `format <drive>:`, `Format-Volume`, `Clear-Disk`, `Initialize-Disk`, `Remove-Partition`, and `diskpart`.
- Prohibits ransomware patterns: `vssadmin delete shadows`, `wmic shadowcopy delete`, WMI/CIM `Win32_ShadowCopy` deletion, `wbadmin delete`, `fsutil usn deletejournal`, and `bcdedit /delete`.

### 5. Critical Filesystem Protection
- Destructive operations (`delete`, `overwrite`, `move`) are blocked against:
  - All drive roots (`C:\`, `D:\`, `E:\`, etc.)
  - Critical system directories: `C:\Windows`, `C:\Windows\System32`, `C:\Windows\SysWOW64`
  - Program files: `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`
  - System recovery and boot state: `C:\Boot`, `C:\Recovery`, `System Volume Information`, `$Recycle.Bin`
  - User system AppData: `%LOCALAPPDATA%\Microsoft\Windows`
- **Canonical Path Resolution**: Evaluates both `os.path.abspath` and `os.path.realpath` to prevent symlink and NTFS directory junction bypasses.

### 6. Process Protection (BSOD Prevention)
- Critical Windows kernel processes (`csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `wininit.exe`, `winlogon.exe`, `dwm.exe`) are protected from termination.
- Protects the MCP server process (`os.getpid()`) and its parent from accidental self-termination.

### 7. Network Defenses & CORS Protection
- **Strict Loopback Binding**: Binds exclusively to `127.0.0.1` by default. Refuses to bind to external LAN interfaces without explicit `--allow-remote-access`.
- **CORS & DNS Rebinding Defense**: Rejects cross-origin web requests from external domains. Only allows localhost, 127.0.0.1, Electron (`null`), and local editor webviews (`vscode-*`, `cursor-*`).

### 8. Controlled Elevation via Windows UAC
- Commands requesting administrative privileges trigger standard Windows User Account Control (UAC) prompts (`Start-Process -Verb RunAs`), ensuring physical user awareness.
- Elevation policy is configurable via `MCP_ALLOW_ELEVATION`.

---

## 🧰 Available Tools (22 Tools)

### Category 1: Command & Process Execution
| Tool | Description |
| :--- | :--- |
| `execute_powershell` | Execute PowerShell commands/scripts with guardrail enforcement. Supports `elevate=True`. |
| `execute_cmd` | Execute Command Prompt (`cmd.exe`) commands with guardrail protection. |
| `execute_python` | Execute Python snippets inside the virtual environment with AST inspection. |
| `execute_elevated_command` | Execute PowerShell with Administrator privileges via Windows UAC prompt. |
| `list_processes` | List running processes with PID, CPU %, memory usage, and user details (sort by `cpu` or `memory`). |
| `kill_process` | Terminate processes by PID or name (guards critical system and server processes). |
| `get_security_status` | Inspect active guardrails, admin privilege status, and configuration. |

### Category 2: File System Operations
| Tool | Description |
| :--- | :--- |
| `read_file` | Read text file contents with line-range pagination (`start_line`, `max_lines`). |
| `write_file` | Write or append text content to a file (creates parent directories; guard protected). |
| `list_directory` | List folder items with file sizes, types, and modification timestamps. |
| `search_files` | Wildcard pattern file search across directory trees (`*.py`, `config*.json`). |
| `get_file_info` | Detailed file metadata (size, created, modified, accessed, file type). |
| `delete_file_or_dir` | Safely delete files or non-empty directories (system path guard protected). |
| `copy_or_move` | Copy or move files/directories with destination and source safety validation. |

### Category 3: System & Hardware Monitoring
| Tool | Description |
| :--- | :--- |
| `get_system_info` | Comprehensive system health: OS specs, CPU cores/usage, RAM, all disk partitions, and battery. |
| `get_network_info` | Active network adapters, local IPv4 addresses, and active internet connectivity check. |
| `get_environment` | Retrieve system environment variables (masks sensitive API keys/passwords in `STRICT_MODE`). |

### Category 4: Desktop & GUI Automation
| Tool | Description |
| :--- | :--- |
| `launch_app` | Launch applications (`notepad`, `msedge`, `calc`), open files, or open URLs (injection protected). |
| `get_clipboard` | Read text currently stored in the Windows clipboard. |
| `set_clipboard` | Copy text to the Windows clipboard. |
| `take_screenshot` | Capture primary display to PNG (PIL ImageGrab with PowerShell Graphics fallback). |
| `show_notification` | Display desktop toast or balloon notifications (XML-escaped and injection safe). |

### Resources & Prompts
- **Resource `system://specs`**: Read-only JSON stream of CPU, memory, OS, and disk status.
- **Resource `system://network`**: Read-only JSON stream of active network interfaces and connectivity.
- **Prompt `system_health_check`**: Guided diagnostic prompt template to assess system load, disk space, and processes.

---

## 🚀 Quick Start

### Prerequisites
- **Windows 10 / 11** or **Windows Server 2019+**
- **Python 3.10+** (64-bit recommended)

### 1. Installation

```powershell
# Clone the repository
git clone https://github.com/your-username/windows-mcp.git
cd windows-mcp

# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Running the Server

#### Option A: Streamable HTTP Mode (Recommended for AGY CLI / Web clients)
```powershell
# Double-click start_local_server.bat, or run:
python server.py --transport http --host 127.0.0.1 --port 8000
```
Server endpoint: `http://127.0.0.1:8000/mcp`

#### Option B: Stdio Transport Mode (For Claude Desktop, Cursor, Cline, Roo Code)
```powershell
python server.py --transport stdio
```

---

## 🔌 Client Configurations

### 1. AGY CLI / Antigravity

Register the local server:
```bash
agy mcp add windows-control --url http://127.0.0.1:8000/mcp
```
Verify status:
```bash
agy mcp list
```

### 2. Claude Desktop (`claude_desktop_config.json`)

Path: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "windows-control": {
      "command": "python",
      "args": [
        "E:\\Projects\\windows-mcp\\server.py",
        "--transport",
        "stdio"
      ]
    }
  }
}
```

### 3. Cline / Roo Code (VS Code Extension)

In Cline / Roo Code MCP Settings:

```json
{
  "mcpServers": {
    "windows-control": {
      "command": "python",
      "args": [
        "E:\\Projects\\windows-mcp\\server.py",
        "--transport",
        "stdio"
      ],
      "env": {
        "MCP_STRICT_MODE": "true",
        "MCP_ALLOW_ELEVATION": "true"
      },
      "disabled": false,
      "autoApprove": [
        "get_system_info",
        "get_network_info",
        "list_processes",
        "get_file_info",
        "read_file",
        "list_directory",
        "search_files"
      ]
    }
  }
}
```

---

## ⚙️ Configuration & Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `MCP_STRICT_MODE` | `true` | When active, enforces strict validation and masks sensitive tokens in environment variables. |
| `MCP_ALLOW_ELEVATION` | `true` | Allows tools to request administrative elevation via Windows UAC. Set to `false` to completely disable elevation. |
| `MCP_AUDIT_LOG_FILE` | `security_audit.log` | Path for the security audit log file recording all allowed/blocked events. |

---

## 🧪 Testing

The repository includes a comprehensive test suite of 50 unit and integration tests covering security guardrails, command tools, filesystem protection, system monitoring, and server endpoints.

```powershell
# Run the complete test suite
pytest -v
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
