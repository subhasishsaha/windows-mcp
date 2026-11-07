# Contributing to Windows Control Center MCP

Thank you for your interest in contributing to **Windows Control Center MCP**! We welcome contributions to enhance security guardrails, expand tool capabilities, and improve platform reliability.

---

## 🔒 Security Policy & Disclosures

Because this MCP server provides authorized system automation on local Windows machines, security and safety guardrails are paramount.

- **Vulnerability Disclosures**: If you discover a security bypass, command injection vector, path traversal bug, or privilege escalation vulnerability, please **do not** open a public issue. Instead, report it privately via GitHub Security Advisories or contact the maintainers directly.
- **Rule of Least Privilege**: Any new tool or enhancement must maintain defensive guardrails preventing unauthorized disk formatting, remote payload execution, or destructive system modification.

---

## 🛠️ Development Setup

### Prerequisites

- **Windows 10 / 11** or **Windows Server 2019+**
- **Python 3.10+** (64-bit recommended)
- **PowerShell 5.1+**

### Local Setup

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/your-username/windows-mcp.git
   cd windows-mcp
   ```

2. **Create and activate a virtual environment**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```powershell
   pip install -r requirements.txt
   pip install -e ".[dev]"
   ```

---

## 🧪 Running Tests

Always ensure the automated test suite passes before submitting changes:

```powershell
pytest -v
```

To run a specific test suite:
```powershell
pytest tests/test_security.py -v
pytest tests/test_command_tools.py -v
pytest tests/test_filesystem_tools.py -v
pytest tests/test_system_tools.py -v
pytest tests/test_desktop_tools.py -v
pytest tests/test_server.py -v
```

---

## 📋 Code Conventions

- **Clean stdout in stdio mode**: Standard output (`sys.stdout`) must remain completely dedicated to JSON-RPC protocol messages. All logging, warnings, and diagnostic information must go to `sys.stderr`.
- **Validation**:
  - Any command execution must call `validate_command()` before execution.
  - Any file deletion or write must call `validate_path_safety()`.
  - Application launchers must not use shell string concatenation (`shell=True`).
- **Typing & Documentation**: Add type annotations and Google/Sphinx-style docstrings to all tool functions.

---

## 🚀 Submitting Pull Requests

1. Create a feature branch: `git checkout -b feature/my-enhancement`
2. Make your changes and add corresponding unit tests in `tests/`
3. Run the full test suite (`pytest`) and ensure all 50+ tests pass
4. Commit your changes with clear messages: `git commit -m "feat(security): add detection for X"`
5. Push to your branch and open a Pull Request
