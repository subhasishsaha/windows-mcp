"""Security, Guardrails, and Privilege Management for Windows MCP Server.

Provides:
- Comprehensive regex and AST-based detection of dangerous/remote code execution (RCE).
- De-obfuscation and inspection of base64-encoded PowerShell payloads.
- Python AST inspection blocking shell calls, path destruction, and obfuscated payloads.
- System disk, volume, and critical path destruction guards.
- Antivirus, firewall, and defense evasion prevention.
- Reverse shell and network payload blocking.
- Critical system and server self-process termination prevention.
- Controlled administrative privilege elevation (RunAs / UAC).
- Security audit logging with configurable file location.
"""

import ast
import base64
import ctypes
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("WindowsMCP.Security")

# ---------------------------------------------------------------------------
# Configuration & Flags
# ---------------------------------------------------------------------------
STRICT_MODE = os.environ.get("MCP_STRICT_MODE", "true").lower() in ("true", "1", "yes")
ALLOW_ELEVATION = os.environ.get("MCP_ALLOW_ELEVATION", "true").lower() in ("true", "1", "yes")
AUDIT_LOG_FILE = os.path.abspath(os.environ.get("MCP_AUDIT_LOG_FILE", "security_audit.log"))

# ---------------------------------------------------------------------------
# Protected Paths (Never allow deletion or destructive modification)
# ---------------------------------------------------------------------------
SYSTEM_DRIVES = [f"{d}:\\" for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]

def _get_critical_paths() -> List[str]:
    """Dynamically determine critical system paths to protect."""
    paths = [
        os.environ.get("SystemRoot", r"C:\Windows"),
        os.environ.get("WinDir", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramData", r"C:\ProgramData"),
        r"C:\Windows",
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
        r"C:\Boot",
        r"C:\Recovery",
        r"C:\System Volume Information",
        r"C:\$Recycle.Bin",
    ]
    # Add system drive roots if different from C:
    sys_drive = os.environ.get("SystemDrive", "C:")
    if sys_drive:
        paths.extend([
            rf"{sys_drive}\Windows",
            rf"{sys_drive}\Windows\System32",
            rf"{sys_drive}\Program Files",
            rf"{sys_drive}\Program Files (x86)",
            rf"{sys_drive}\ProgramData",
        ])
    # Normalize paths
    normalized = []
    for p in paths:
        if p:
            norm = os.path.abspath(p).lower().rstrip("\\/")
            if norm not in normalized:
                normalized.append(norm)
    return normalized

CRITICAL_PATHS = _get_critical_paths()

# Critical system processes that must never be terminated (prevents BSOD / system hang)
PROTECTED_PROCESS_NAMES = {
    "system",
    "system idle process",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "svchost.exe",
    "sihost.exe",
    "explorer.exe",
}

RESERVED_DEVICE_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
}

# Shell interpreters and script files disallowed in launch_app (prevents sandbox bypass)
DISALLOWED_LAUNCH_TARGETS = {
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "bash",
    "bash.exe",
    "sh",
    "sh.exe",
    "wsl",
    "wsl.exe",
    "python",
    "python.exe",
    "pythonw",
    "pythonw.exe",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe",
    "mshta",
    "mshta.exe",
    "rundll32",
    "rundll32.exe",
    "regsvr32",
    "regsvr32.exe",
    "conhost",
    "conhost.exe",
}
DISALLOWED_LAUNCH_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".wsf",
    ".sh",
    ".hta",
    ".pif",
    ".scr",
    ".com",
}

# Sensitive credential directories and filenames protected from direct read exfiltration
SENSITIVE_CREDENTIAL_DIRS = {
    ".ssh",
    ".aws",
    ".azure",
    ".gcloud",
    ".kube",
    ".gnupg",
    ".docker",
}
SENSITIVE_CREDENTIAL_FILES = {
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".env",
    ".netrc",
    "_netrc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "sam",
    "system",
    "security",
}

# ---------------------------------------------------------------------------
# Dangerous Pattern Definitions
# ---------------------------------------------------------------------------
DANGEROUS_COMMAND_PATTERNS = [
    # 1. Disk & Volume Destruction
    (
        r"\bformat(\.com)?\b.*[a-zA-Z]:",
        "Disk formatting command detected (format <drive>:).",
    ),
    (
        r"\bFormat-Volume\b",
        "PowerShell disk volume formatting cmdlet (Format-Volume) is blocked.",
    ),
    (
        r"\bClear-Disk\b",
        "PowerShell disk clearing cmdlet (Clear-Disk) is blocked.",
    ),
    (
        r"\bInitialize-Disk\b",
        "PowerShell disk initialization cmdlet (Initialize-Disk) is blocked.",
    ),
    (
        r"\bRemove-Partition\b",
        "PowerShell partition removal cmdlet (Remove-Partition) is blocked.",
    ),
    (
        r"\bdiskpart(\.exe)?\b",
        "Direct disk partitioning tool (diskpart) is blocked.",
    ),
    (
        r"\bvssadmin(\.exe)?\s+delete\s+shadows\b",
        "Ransomware pattern: Shadow copy deletion (vssadmin delete shadows) is blocked.",
    ),
    (
        r"\bwmic(\.exe)?\s+shadowcopy\s+delete\b",
        "Ransomware pattern: WMIC shadow copy deletion is blocked.",
    ),
    (
        r"(?:Get-WmiObject|Get-CimInstance)\s+.*Win32_ShadowCopy.*(?:Delete|Remove)\b",
        "PowerShell WMI/CIM shadow copy deletion is blocked.",
    ),
    (
        r"\bRemove-CimInstance\b.*Win32_ShadowCopy",
        "PowerShell CIM instance shadow copy deletion is blocked.",
    ),
    (
        r"\bwbadmin(\.exe)?\s+delete\b",
        "Backup catalog deletion (wbadmin delete) is blocked.",
    ),
    (
        r"\bfsutil(\.exe)?\s+usn\s+deletejournal\b",
        "USN journal deletion (fsutil) is blocked.",
    ),
    (
        r"\bbcdedit(\.exe)?(?:\s+|\s*/)(?:delete|set)\b",
        "Boot configuration modification/deletion (bcdedit) is blocked.",
    ),

    # 2. Defense Evasion & Security Disabling
    (
        r"(?:Set-MpPreference|Add-MpPreference)\s+.*-(DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|DisableIntrusionPreventionSystem|DisableScriptScanning)\s*(?::|\s+)(\$true|1|true)",
        "Disabling Windows Defender security protection is blocked.",
    ),
    (
        r"(?:Set-MpPreference|Add-MpPreference)\s+.*-(ExclusionPath|ExclusionProcess|ExclusionExtension)\b",
        "Modifying Windows Defender exclusions is blocked.",
    ),
    (
        r"netsh(\.exe)?\s+advfirewall\s+set\s+.*state\s+off",
        "Disabling Windows Firewall via netsh is blocked.",
    ),
    (
        r"Set-NetFirewallProfile\s+.*-Enabled\s+(\$false|0|false)\b",
        "Disabling Windows Firewall profile is blocked.",
    ),
    (
        r"(?:sc(\.exe)?\s+stop|stop-service|net\s+stop)\s+(windefend|mpssvc|wuauserv)",
        "Stopping Windows Defender or security services is blocked.",
    ),
    (
        r"\btaskkill(\.exe)?(?:\s+|/|\b).*(?:\/|-)?im(?::|\s+|\/.*|\b).*msmpeng\.exe",
        "Terminating Windows Defender process (MsMpEng) is blocked.",
    ),

    # 3. Remote Code Execution (RCE) / Unsafe Download & Execute
    (
        r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\s+.*\|\s*(?:iex|invoke-expression|powershell|cmd|sh|bash)\b",
        "Remote code execution pipeline (download | execute) is blocked.",
    ),
    (
        r"(?:iex|invoke-expression)\s*(?:[-(]|\s).*(?:net\.webclient|downloadstring|downloaddata|iwr|irm|invoke-webrequest|invoke-restmethod)",
        "WebClient or web request remote script execution is blocked.",
    ),
    (
        r"certutil(\.exe)?\s+(-urlcache|-split).*http",
        "Living-off-the-land payload download via certutil is blocked.",
    ),
    (
        r"bitsadmin(\.exe)?\s+/transfer.*http",
        "Payload download via bitsadmin is blocked.",
    ),
    (
        r"mshta(\.exe)?\s+http",
        "Remote HTA script execution via mshta is blocked.",
    ),
    (
        r"regsvr32(\.exe)?\s+.*\/s\s+\/u\s+\/i:http",
        "Squiblydoo remote COM scriptlet execution via regsvr32 is blocked.",
    ),
    (
        r"msiexec(\.exe)?\s+.*\/i\s+http",
        "Remote MSI package execution via msiexec is blocked.",
    ),

    # 4. Reverse Shells & Malicious Network Listeners
    (
        r"\b(?:nc|ncat|netcat)(\.exe)?\b.*-e\s+(?:cmd|powershell|bash|sh)",
        "Netcat reverse shell execution (-e cmd/powershell) is blocked.",
    ),
    (
        r"\bpowercat\b",
        "Powercat reverse shell tool is blocked.",
    ),
    (
        r"bash\s+-i\s+>&\s+/dev/tcp/",
        "Bash TCP reverse shell is blocked.",
    ),

    # 5. Dangerous Recursive Root & System Deletions
    (
        r"\b(?:rd|rmdir)\b(?:\s+|(?=/))(?=.*(?:\/s|\/q))(?=.*(?:\b[a-zA-Z]:(?:[\\\/](?:\*|\*\.\*)?)?(?:[\"'\s;&|>}]|$)|windows|system32))",
        "Recursive deletion of entire drive root or Windows system directories is blocked.",
    ),
    (
        r"\b(?:del|erase)\b(?:\s+|(?=/))(?=.*(?:\/s|\/f|\/q))(?=.*(?:\b[a-zA-Z]:(?:[\\\/](?:\*|\*\.\*)?)?(?:[\"'\s;&|>}]|$)|windows|system32))",
        "Recursive deletion of entire drive root or Windows system directories is blocked.",
    ),
    (
        r"\b(?:remove-item|rm|ri)\b\s+(?=.*(?:-recurse|-r|-force|-fo))(?=.*(?:\b[a-zA-Z]:(?:[\\\/](?:\*|\*\.\*)?)?(?:[\"'\s;&|>}]|$)|windows|system32))",
        "PowerShell recursive deletion of drive root or Windows system directories is blocked.",
    ),

    # 6. Denial of Service / Fork Bombs
    (
        r"%\s*0\s*\|\s*%\s*0",
        "Batch fork bomb detected (%0|%0).",
    ),
    (
        r":\(\)\s*\{\s*:\|:&\s*\};:",
        "Fork bomb detected.",
    ),
]


# ---------------------------------------------------------------------------
# Privilege & Elevation Helpers
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    """Check if the current process is running with administrative elevation."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Audit Logger
# ---------------------------------------------------------------------------
def audit_log(event: str, command: str, allowed: bool, reason: str = "", elevated: bool = False) -> None:
    """Record all security-sensitive executions to the security audit log."""
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "command": command[:200],
        "allowed": allowed,
        "elevated": elevated,
        "is_admin": is_admin(),
        "reason": reason,
    }
    try:
        log_dir = os.path.dirname(AUDIT_LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error("Failed to write to audit log: %s", e)


# ---------------------------------------------------------------------------
# Validation Functions
# ---------------------------------------------------------------------------
def _normalize_windows_path(path: str) -> str:
    """Normalize Windows paths, removing extended prefixes (\\?\\, \\.\\) and resolving UNC admin shares."""
    if not path:
        return ""
    norm = path.strip().strip("\"'").replace("/", "\\")
    if re.match(r"^[a-zA-Z]:$", norm):
        norm = norm + "\\"
    # Extended UNC prefix: \\?\UNC\server\share
    if norm.lower().startswith("\\\\?\\unc\\"):
        norm = "\\\\" + norm[8:]
    # Extended or device prefix: \\?\ or \\.\
    elif norm.lower().startswith(("\\\\?\\", "\\\\.\\")):
        norm = norm[4:]
    # Localhost UNC admin shares: \\localhost\c$\..., \\127.0.0.1\c$\..., \\::1\c$\...
    unc_match = re.match(
        r"^\\\\(?:localhost|127\.0\.0\.1|::1|[a-zA-Z0-9_\-]+)\\([a-zA-Z])(?:\$|\\|\b)(.*)$",
        norm,
        re.IGNORECASE,
    )
    if unc_match:
        drive_letter = unc_match.group(1).upper()
        rest = unc_match.group(2).lstrip("\\")
        norm = f"{drive_letter}:\\{rest}" if rest else f"{drive_letter}:\\"
    return norm


_POWERSHELL_ENC_PATTERN = re.compile(
    r"(?:[-/](?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand))\s*(?:[:=]|\s)\s*['\"]?([A-Za-z0-9+/= \r\n]{4,})['\"]?",
    re.IGNORECASE,
)
_FROM_BASE64_PATTERN = re.compile(
    r"(?:\[(?:System\.)?Convert\]::FromBase64String|frombase64string)\s*\(\s*['\"]([A-Za-z0-9+/= \r\n]{4,})['\"]\s*\)",
    re.IGNORECASE,
)


def _check_encoded_command(command: str) -> Tuple[bool, Optional[str]]:
    """Inspect and decode Base64-encoded PowerShell commands and FromBase64String calls.

    Args:
        command: Command string that might contain encoded PowerShell payload.

    Returns:
        (is_safe, error_reason)
    """
    b64_matches = []
    for m in _POWERSHELL_ENC_PATTERN.finditer(command):
        b64_matches.append(m.group(1).replace(" ", "").replace("\r", "").replace("\n", ""))
    for m in _FROM_BASE64_PATTERN.finditer(command):
        b64_matches.append(m.group(1).replace(" ", "").replace("\r", "").replace("\n", ""))

    if not b64_matches:
        return True, None

    for b64_str in b64_matches:
        decoded_cmd = ""
        try:
            decoded_bytes = base64.b64decode(b64_str, validate=True)
            # Try UTF-16LE first (PowerShell EncodedCommand standard)
            if len(decoded_bytes) >= 2 and len(decoded_bytes) % 2 == 0:
                try:
                    decoded_cmd = decoded_bytes.decode("utf-16le").strip()
                except UnicodeDecodeError:
                    pass
            # Fallback to UTF-8
            if not decoded_cmd:
                try:
                    decoded_cmd = decoded_bytes.decode("utf-8").strip()
                except UnicodeDecodeError:
                    pass
            # Fallback to Latin-1
            if not decoded_cmd:
                decoded_cmd = decoded_bytes.decode("latin-1", errors="ignore").strip()
        except Exception as e:
            if STRICT_MODE:
                return False, f"SECURITY POLICY VIOLATION: Malformed base64 encoded command detected: {str(e)}"
            continue

        if decoded_cmd:
            is_safe, reason = validate_command(decoded_cmd, _is_subcheck=True)
            if not is_safe:
                return False, f"SECURITY POLICY VIOLATION (Obfuscated Payload): {reason}"

    return True, None


def _normalize_command_variants(command: str) -> List[str]:
    """Generate normalized command variants to defeat shell escape, quote wrapping, and delimiter evasions."""
    clean_cmd = command.strip()
    if not clean_cmd:
        return []

    # 1. Base escape stripping: remove PowerShell backticks and CMD carets
    base = clean_cmd.replace("`", "").replace("^", "")

    # 2. Strip single and double quotes
    no_quotes = base.replace('"', "").replace("'", "")

    # 3. Insert space before CMD switches preceded by alphanumeric characters
    switch_spaced = re.sub(r'([a-zA-Z0-9])/', r'\1 /', no_quotes)

    # 4. Quote-to-space normalization (handles unspaced quotes e.g. vssadmin"delete""shadows")
    quotes_as_spaces = re.sub(r'["\']+', ' ', base)
    quotes_as_spaces = re.sub(r'([a-zA-Z0-9])/', r'\1 /', quotes_as_spaces)

    candidates = [clean_cmd, base, no_quotes, switch_spaced, quotes_as_spaces]
    normalized_list: List[str] = []
    for c in candidates:
        if c and c not in normalized_list:
            normalized_list.append(c)
        cleaned = " ".join(c.split())
        if cleaned and cleaned not in normalized_list:
            normalized_list.append(cleaned)

    return normalized_list


def validate_command(command: str, _is_subcheck: bool = False) -> Tuple[bool, Optional[str]]:
    """Validate a shell command against the guardrail policy.

    Args:
        command: Command string to inspect.
        _is_subcheck: Internal flag to prevent redundant audit log entries.

    Returns:
        (is_safe, error_reason)
    """
    clean_cmd = command.strip()
    if not clean_cmd:
        return True, None

    normalized_variants = _normalize_command_variants(clean_cmd)

    # 1. Check for encoded PowerShell payload bypasses across original and normalized variants
    for variant in normalized_variants:
        enc_safe, enc_err = _check_encoded_command(variant)
        if not enc_safe:
            if not _is_subcheck:
                audit_log("COMMAND_BLOCKED", command, allowed=False, reason=enc_err or "")
            return False, enc_err

    # 2. Check dangerous regex patterns against original and all normalized variants
    for pattern, description in DANGEROUS_COMMAND_PATTERNS:
        for variant in normalized_variants:
            if re.search(pattern, variant, re.IGNORECASE):
                if not _is_subcheck:
                    audit_log("COMMAND_BLOCKED", command, allowed=False, reason=description)
                return False, f"SECURITY POLICY VIOLATION: {description}"

    if not _is_subcheck:
        audit_log("COMMAND_ALLOWED", command, allowed=True)
    return True, None


def validate_path_safety(path: str, operation: str = "delete") -> Tuple[bool, Optional[str]]:
    """Validate that a target file/directory path is not a critical system path, drive root, or device.

    Resolves normalized, absolute, and real (canonical symlink/junction) paths to prevent traversal.

    Args:
        path: Path string to check.
        operation: Nature of operation (e.g. 'delete', 'write', 'move').

    Returns:
        (is_safe, error_reason)
    """
    if not path or not path.strip():
        return False, "SECURITY POLICY VIOLATION: Path cannot be empty."

    clean_raw = path.strip().strip("\"'")
    if re.match(r"^[a-zA-Z]:$", clean_raw):
        clean_raw = clean_raw + "\\"
    normalized = _normalize_windows_path(clean_raw)

    # 1. Check for reserved DOS device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
    for check_str in (clean_raw, normalized):
        base_name = os.path.basename(check_str).lower().split(".")[0]
        if base_name in RESERVED_DEVICE_NAMES:
            reason = f"Access to Windows reserved device '{check_str}' is prohibited."
            audit_log("PATH_BLOCKED", path, allowed=False, reason=reason)
            return False, f"SECURITY POLICY VIOLATION: {reason}"

    try:
        abs_raw = os.path.abspath(clean_raw).lower().rstrip("\\/")
        abs_norm = os.path.abspath(normalized).lower().rstrip("\\/")
        real_norm = os.path.realpath(normalized).lower().rstrip("\\/")
    except Exception as e:
        return False, f"Invalid path resolution: {str(e)}"

    paths_to_check = {abs_raw, abs_norm, real_norm}
    # Also normalize resolved paths to strip any extended prefixes
    for p in list(paths_to_check):
        p_norm = _normalize_windows_path(p).lower().rstrip("\\/")
        if p_norm:
            paths_to_check.add(p_norm)

    # Protect security audit log file from deletion or modification
    audit_log_norm = os.path.abspath(AUDIT_LOG_FILE).lower().rstrip("\\/")
    for p in paths_to_check:
        if p == audit_log_norm:
            reason = f"Destructive operation '{operation}' is prohibited on security audit log: {path}"
            audit_log("PATH_BLOCKED", path, allowed=False, reason=reason)
            return False, f"SECURITY POLICY VIOLATION: {reason}"

    for p in paths_to_check:
        # 2. Check drive roots (e.g. C:, C:\, D:\)
        drive, tail = os.path.splitdrive(p)
        if drive and tail in ("", "\\", "/"):
            reason = f"Destructive operation '{operation}' is prohibited on drive root: {path}"
            audit_log("PATH_BLOCKED", path, allowed=False, reason=reason)
            return False, f"SECURITY POLICY VIOLATION: {reason}"

        # 3. Check critical system directories and subdirectories
        for crit in CRITICAL_PATHS:
            if not crit:
                continue
            if p == crit or p.startswith(crit + "\\"):
                reason = f"Destructive operation '{operation}' is prohibited in protected system path: {crit}"
                audit_log("PATH_BLOCKED", path, allowed=False, reason=reason)
                return False, f"SECURITY POLICY VIOLATION: {reason}"

        # 4. Check User AppData Windows system state
        user_appdata = os.environ.get("LOCALAPPDATA", "")
        if user_appdata:
            protected_appdata = os.path.abspath(os.path.join(user_appdata, "Microsoft", "Windows")).lower().rstrip("\\/")
            if p == protected_appdata or p.startswith(protected_appdata + "\\"):
                reason = f"Destructive operation '{operation}' is prohibited in User System AppData."
                audit_log("PATH_BLOCKED", path, allowed=False, reason=reason)
                return False, f"SECURITY POLICY VIOLATION: {reason}"

    return True, None


def validate_launch_safety(target: str, args: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """Validate that target application is not a command interpreter or script bypassing the sandbox.

    Args:
        target: Application name, path, or URL.
        args: Optional command line arguments.

    Returns:
        (is_safe, error_reason)
    """
    if not target or not target.strip():
        return False, "SECURITY POLICY VIOLATION: Launch target cannot be empty."

    clean_target = target.strip().strip("\"'")
    clean_args = args.strip() if args else ""

    # Check against general dangerous command patterns
    cmd_to_validate = f"{clean_target} {clean_args}".strip()
    is_safe, cmd_err = validate_command(cmd_to_validate)
    if not is_safe:
        return False, cmd_err

    # Allow web URLs
    if clean_target.lower().startswith(("http://", "https://")):
        return True, None

    # Check executable base name and extension against disallowed shells and scripts
    norm = _normalize_windows_path(clean_target)
    base_name = os.path.basename(norm).lower()
    root_name, ext = os.path.splitext(base_name)

    if base_name in DISALLOWED_LAUNCH_TARGETS or root_name in DISALLOWED_LAUNCH_TARGETS:
        reason = (
            f"Launching shell interpreter or runtime '{base_name}' via launch_app is prohibited to "
            "prevent sandbox evasion. Use execute_powershell, execute_cmd, or execute_python instead."
        )
        audit_log("LAUNCH_BLOCKED", cmd_to_validate, allowed=False, reason=reason)
        return False, f"SECURITY POLICY VIOLATION: {reason}"

    if ext in DISALLOWED_LAUNCH_EXTENSIONS:
        reason = (
            f"Launching script file with extension '{ext}' via launch_app is prohibited to "
            "prevent sandbox evasion. Use execute_powershell, execute_cmd, or execute_python instead."
        )
        audit_log("LAUNCH_BLOCKED", cmd_to_validate, allowed=False, reason=reason)
        return False, f"SECURITY POLICY VIOLATION: {reason}"

    return True, None


def validate_read_safety(path: str) -> Tuple[bool, Optional[str]]:
    """Validate that a target read path does not access protected credential or secret files.

    Args:
        path: File path to check.

    Returns:
        (is_safe, error_reason)
    """
    if not path or not path.strip():
        return False, "SECURITY POLICY VIOLATION: Path cannot be empty."

    clean_raw = path.strip().strip("\"'")
    if re.match(r"^[a-zA-Z]:$", clean_raw):
        clean_raw = clean_raw + "\\"
    normalized = _normalize_windows_path(clean_raw)

    # 1. Check for reserved DOS device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) to prevent hang
    for check_str in (clean_raw, normalized):
        base_name = os.path.basename(check_str).lower().split(".")[0]
        if base_name in RESERVED_DEVICE_NAMES:
            reason = f"Reading Windows reserved device '{check_str}' is prohibited."
            audit_log("READ_BLOCKED", path, allowed=False, reason=reason)
            return False, f"SECURITY POLICY VIOLATION: {reason}"

    try:
        abs_raw = os.path.abspath(clean_raw).lower().replace("/", "\\")
        abs_norm = os.path.abspath(normalized).lower().replace("/", "\\")
        real_norm = os.path.realpath(normalized).lower().replace("/", "\\")
    except Exception as e:
        return False, f"Invalid path resolution: {str(e)}"

    paths_to_check = {abs_raw, abs_norm, real_norm}

    # Unconditional protection for SAM / SYSTEM / SECURITY registry hives regardless of STRICT_MODE
    for p in paths_to_check:
        if "\\system32\\config\\sam" in p or "\\system32\\config\\system" in p or "\\system32\\config\\security" in p:
            reason = "Reading Windows SAM/SYSTEM/SECURITY registry hive is prohibited."
            audit_log("READ_BLOCKED", path, allowed=False, reason=reason)
            return False, f"SECURITY POLICY VIOLATION: {reason}"

    if STRICT_MODE:
        for p in paths_to_check:
            parts = [part.strip("\\/") for part in p.split("\\") if part.strip("\\/")]
            # Check directory names
            for part in parts:
                if part.lower() in SENSITIVE_CREDENTIAL_DIRS:
                    reason = f"Reading credential store or secret directory '{part}' is prohibited in STRICT_MODE."
                    audit_log("READ_BLOCKED", path, allowed=False, reason=reason)
                    return False, f"SECURITY POLICY VIOLATION: {reason}"

            # Check leaf filename
            leaf = parts[-1].lower() if parts else ""
            if (
                leaf in SENSITIVE_CREDENTIAL_FILES
                or leaf.startswith("id_")
                or leaf == ".env"
                or leaf.startswith(".env.")
                or leaf in (".netrc", "_netrc")
            ):
                reason = f"Reading private key, environment, or credential file '{leaf}' is prohibited in STRICT_MODE."
                audit_log("READ_BLOCKED", path, allowed=False, reason=reason)
                return False, f"SECURITY POLICY VIOLATION: {reason}"

    return True, None


def _resolve_ast_str(node: ast.AST, scope: Dict[str, str]) -> Optional[str]:
    """Helper to statically resolve constant strings, binary concatenations, and variable references."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_ast_str(node.left, scope)
        right = _resolve_ast_str(node.right, scope)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.Name):
        return scope.get(node.id)
    if isinstance(node, (ast.List, ast.Tuple)):
        parts = [_resolve_ast_str(elt, scope) for elt in node.elts]
        if all(p is not None for p in parts):
            return " ".join(parts)
    if isinstance(node, ast.JoinedStr):
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                parts.append(str(val.value))
            elif isinstance(val, ast.FormattedValue):
                res = _resolve_ast_str(val.value, scope)
                if res is not None:
                    parts.append(res)
                else:
                    return None
        return "".join(parts)
    return None


def validate_python_code(code: str) -> Tuple[bool, Optional[str]]:
    """Inspect Python code AST to prevent dangerous calls, shell injection, or path tampering.

    Args:
        code: Python source code snippet.

    Returns:
        (is_safe, error_reason)
    """
    clean_code = code.strip()
    if not clean_code:
        return True, None

    # Check for dangerous regex patterns in the code text
    for pattern, description in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, clean_code, re.IGNORECASE):
            audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=description)
            return False, f"SECURITY POLICY VIOLATION (Python Code): {description}"

    try:
        tree = ast.parse(clean_code)
    except Exception:
        # Normal execution will catch and report Python syntax or parsing errors
        return True, None

    # Build local variable scope mapping for string assignments
    scope_vars: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            val_str = _resolve_ast_str(node.value, scope_vars)
            if val_str is not None:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        scope_vars[target.id] = val_str

    # Inspect AST Nodes
    for node in ast.walk(tree):
        # 1. Inspect function calls
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            # Check shell execution functions: os.system, subprocess.run/call/Popen, etc.
            if func_name in ("system", "popen", "spawnl", "spawnv", "run", "call", "check_call", "check_output", "Popen"):
                if node.args:
                    cmd_str = _resolve_ast_str(node.args[0], scope_vars)
                    if cmd_str is not None:
                        is_safe, reason = validate_command(cmd_str, _is_subcheck=True)
                        if not is_safe:
                            audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=reason or "")
                            return False, f"SECURITY POLICY VIOLATION (Python Shell Call): {reason}"
                    elif STRICT_MODE:
                        reason = "Dynamic or unresolvable shell command execution is prohibited in STRICT_MODE."
                        audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=reason)
                        return False, f"SECURITY POLICY VIOLATION (Python Shell Call): {reason}"

            # Check destructive filesystem calls: shutil.rmtree, os.remove, os.unlink, os.rmdir, os.removedirs
            if func_name in ("rmtree", "remove", "unlink", "rmdir", "removedirs"):
                if node.args:
                    target_path = _resolve_ast_str(node.args[0], scope_vars)
                    if target_path is not None:
                        is_safe, reason = validate_path_safety(target_path, operation="delete")
                        if not is_safe:
                            audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=reason or "")
                            return False, f"SECURITY POLICY VIOLATION (Python Path Deletion): {reason}"
                    elif STRICT_MODE:
                        reason = "Dynamic or unresolvable destructive path operation is prohibited in STRICT_MODE."
                        audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=reason)
                        return False, f"SECURITY POLICY VIOLATION (Python Path Deletion): {reason}"

            # Check file write/overwrite via open()
            if func_name == "open" and len(node.args) >= 2:
                mode_str = _resolve_ast_str(node.args[1], scope_vars)
                if mode_str and any(m in mode_str for m in ("w", "a", "+")):
                    target_path = _resolve_ast_str(node.args[0], scope_vars)
                    if target_path is not None:
                        is_safe, reason = validate_path_safety(target_path, operation="write")
                        if not is_safe:
                            audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=reason or "")
                            return False, f"SECURITY POLICY VIOLATION (Python File Overwrite): {reason}"
                    elif STRICT_MODE:
                        reason = "Dynamic or unresolvable file write/overwrite path is prohibited in STRICT_MODE."
                        audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=reason)
                        return False, f"SECURITY POLICY VIOLATION (Python File Overwrite): {reason}"

            # Check dynamic execution: exec/eval
            if func_name in ("exec", "eval"):
                if node.args:
                    inner_code = _resolve_ast_str(node.args[0], scope_vars)
                    if inner_code is not None:
                        # Recursively validate static code passed to exec/eval
                        is_safe, reason = validate_python_code(inner_code)
                        if not is_safe:
                            audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=reason or "")
                            return False, reason
                    elif STRICT_MODE:
                        reason = "Dynamic exec/eval with unresolvable or decoded payload is prohibited in STRICT_MODE."
                        audit_log("PYTHON_BLOCKED", code[:100], allowed=False, reason=reason)
                        return False, f"SECURITY POLICY VIOLATION (Python Code): {reason}"

    audit_log("PYTHON_ALLOWED", code[:100], allowed=True)
    return True, None


# ---------------------------------------------------------------------------
# Elevated Command Execution
# ---------------------------------------------------------------------------
def execute_elevated(command: str, timeout: int = 120, working_dir: Optional[str] = None) -> Dict[str, Any]:
    """Execute a PowerShell command with administrative privileges via Windows UAC elevation.

    Enforces all security guardrails before granting elevation.

    Args:
        command: The PowerShell command to run with elevated permissions.
        timeout: Maximum seconds to wait before timing out (default: 120).
        working_dir: Directory where the command should execute (default: None).

    Returns:
        Dictionary with stdout, stderr, return_code, execution_time_seconds, elevated, and timed_out.
    """
    start_time = time.time()
    if not ALLOW_ELEVATION:
        return {
            "stdout": "",
            "stderr": "ADMIN ELEVATION DISABLED: Elevated command execution is disabled in server policy.",
            "return_code": -1,
            "elevated": False,
            "timed_out": False,
            "execution_time_seconds": 0.0,
        }

    # Validate working_dir if provided
    resolved_cwd = None
    if working_dir:
        resolved_cwd = os.path.abspath(working_dir)
        if not os.path.isdir(resolved_cwd):
            return {
                "stdout": "",
                "stderr": f"Invalid working directory: {working_dir}",
                "return_code": -1,
                "elevated": False,
                "timed_out": False,
                "execution_time_seconds": 0.0,
            }

    # 1. Enforce security guardrails first
    is_safe, error_msg = validate_command(command)
    if not is_safe:
        return {
            "stdout": "",
            "stderr": error_msg or "Blocked by guardrail.",
            "return_code": -1,
            "elevated": False,
            "timed_out": False,
            "execution_time_seconds": 0.0,
        }

    audit_log("ELEVATED_REQUEST", command, allowed=True, elevated=True)

    # If the server is already running elevated as Administrator, execute directly
    if is_admin():
        try:
            # Use PowerShell directly without circular import
            ps_script = f"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; & {{ {command} }}"
            enc = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
                capture_output=True,
                text=True,
                cwd=resolved_cwd,
                timeout=timeout,
            )
            return {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "return_code": proc.returncode,
                "elevated": True,
                "admin_session": True,
                "timed_out": False,
                "execution_time_seconds": round(time.time() - start_time, 2),
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Elevated command timed out after {timeout} seconds.",
                "return_code": -1,
                "elevated": True,
                "admin_session": True,
                "timed_out": True,
                "execution_time_seconds": timeout,
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": f"Direct elevated execution failed: {str(e)}",
                "return_code": -1,
                "elevated": True,
                "admin_session": True,
                "timed_out": False,
                "execution_time_seconds": round(time.time() - start_time, 2),
            }

    # Otherwise, trigger elevation via PowerShell 'Start-Process -Verb RunAs'
    mcp_temp_dir = os.path.join(tempfile.gettempdir(), f"mcp_elev_{os.getpid()}_{int(time.time() * 1000)}")
    os.makedirs(mcp_temp_dir, exist_ok=True)
    out_file = os.path.join(mcp_temp_dir, "stdout.txt")
    err_file = os.path.join(mcp_temp_dir, "stderr.txt")

    # Safe PowerShell wrapper
    out_escaped = out_file.replace("'", "''")
    err_escaped = err_file.replace("'", "''")
    cd_clause = ""
    if resolved_cwd:
        cd_escaped = resolved_cwd.replace("'", "''")
        cd_clause = f"Set-Location -LiteralPath '{cd_escaped}'; "

    wrapper = f"""
$ErrorActionPreference = 'Continue'
try {{
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    {cd_clause}& {{ {command} }} *>&1 | Out-File -FilePath '{out_escaped}' -Encoding UTF8
    $ec = $LASTEXITCODE
    if ($null -eq $ec) {{ $ec = 0 }}
}} catch {{
    $_ | Out-File -FilePath '{err_escaped}' -Encoding UTF8
    $ec = 1
}}
exit $ec
"""
    try:
        enc_script = base64.b64encode(wrapper.encode("utf-16le")).decode("ascii")

        # Start-Process with -PassThru -Wait so the outer process captures the inner exit code
        launcher_script = (
            f"$p = Start-Process powershell.exe -Verb RunAs -Wait -PassThru "
            f"-ArgumentList '-NoProfile -ExecutionPolicy Bypass -EncodedCommand {enc_script}'; "
            f"if ($p) {{ exit $p.ExitCode }} else {{ exit 1 }}"
        )
        launcher_enc = base64.b64encode(launcher_script.encode("utf-16le")).decode("ascii")

        ps_launcher = [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            launcher_enc,
        ]

        proc = subprocess.run(ps_launcher, capture_output=True, text=True, timeout=timeout)

        stdout_content = ""
        stderr_content = ""
        if os.path.exists(out_file):
            try:
                # utf-8-sig strips potential UTF-8 BOM emitted by Out-File in Windows PowerShell
                with open(out_file, "r", encoding="utf-8-sig", errors="replace") as f:
                    stdout_content = f.read()
            except Exception:
                pass

        if os.path.exists(err_file):
            try:
                with open(err_file, "r", encoding="utf-8-sig", errors="replace") as f:
                    stderr_content = f.read()
            except Exception:
                pass

        final_stderr = stderr_content or (proc.stderr.strip() if proc.returncode != 0 else "")

        return {
            "stdout": stdout_content,
            "stderr": final_stderr,
            "return_code": proc.returncode,
            "elevated": True,
            "timed_out": False,
            "execution_time_seconds": round(time.time() - start_time, 2),
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Elevated command timed out after {timeout} seconds.",
            "return_code": -1,
            "elevated": True,
            "timed_out": True,
            "execution_time_seconds": timeout,
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Elevated execution failed: {str(e)}",
            "return_code": -1,
            "elevated": True,
            "timed_out": False,
            "execution_time_seconds": round(time.time() - start_time, 2),
        }
    finally:
        if os.path.exists(mcp_temp_dir):
            try:
                shutil.rmtree(mcp_temp_dir, ignore_errors=True)
            except Exception:
                pass
