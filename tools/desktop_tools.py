"""Desktop and GUI automation tools for Windows MCP Server."""

import base64
import os
import shlex
import subprocess
import time
import webbrowser
from typing import Any, Dict, Optional
import pyperclip
from PIL import ImageGrab
from security import validate_launch_safety, validate_path_safety


def launch_app(
    target: str,
    args: Optional[str] = None,
) -> Dict[str, Any]:
    """Launch an application, open a file in its default program, or open a URL in the browser.

    Args:
        target: Application name/path (e.g., 'notepad', 'calc', 'msedge'), file path, or URL (e.g. 'https://google.com').
        args: Optional command line arguments to pass to the application.

    Returns:
        Dictionary with status and launched target.
    """
    clean_target = target.strip()
    clean_args = args.strip() if args else ""

    # Guardrail: Enforce launch safety against dangerous executables, parameters, and shell sandbox evasion
    is_safe, sec_err = validate_launch_safety(clean_target, clean_args)
    if not is_safe:
        return {
            "success": False,
            "error": sec_err or "Command blocked by security guardrails.",
            "target": clean_target,
            "blocked_by_guardrail": True,
        }

    # URL handling
    if clean_target.startswith("http://") or clean_target.startswith("https://"):
        try:
            webbrowser.open(clean_target)
            return {"success": True, "action": "opened_url", "target": clean_target}
        except Exception as e:
            return {"success": False, "error": str(e), "target": clean_target}

    # Desktop apps: use Win32 ShellExecute via os.startfile (no cmd.exe shell injection vulnerability)
    try:
        if clean_args:
            os.startfile(clean_target, arguments=clean_args)
            return {"success": True, "action": "launched_with_args", "target": clean_target, "args": clean_args}
        else:
            os.startfile(clean_target)
            return {"success": True, "action": "opened_file_or_app", "target": clean_target}
    except Exception as start_err:
        # Fallback to direct subprocess spawn without shell=True to prevent injection (posix=False for Windows paths)
        try:
            split_args = shlex.split(clean_args, posix=False) if clean_args else []
            subprocess.Popen([clean_target] + split_args, shell=False)
            return {"success": True, "action": "spawned_process", "target": clean_target}
        except Exception as spawn_err:
            return {
                "success": False,
                "error": f"Failed to launch '{clean_target}': {str(start_err)}; fallback error: {str(spawn_err)}",
                "target": clean_target,
            }


def get_clipboard() -> Dict[str, Any]:
    """Retrieve text currently stored in the Windows clipboard.

    Returns:
        Dictionary with clipboard text content and character count.
    """
    try:
        content = pyperclip.paste()
        return {
            "success": True,
            "text": content,
            "character_count": len(content),
            "is_empty": len(content) == 0,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "text": ""}


def set_clipboard(text: str) -> Dict[str, Any]:
    """Copy text to the Windows clipboard.

    Args:
        text: Text string to copy into clipboard.

    Returns:
        Dictionary indicating status and length of text copied.
    """
    try:
        pyperclip.copy(text)
        return {
            "success": True,
            "message": "Text successfully copied to clipboard.",
            "character_count": len(text),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def take_screenshot(save_path: Optional[str] = None) -> Dict[str, Any]:
    """Take a screenshot of the primary display and save it to a PNG file.

    Args:
        save_path: Path where the PNG image should be saved. If omitted, saves with timestamp in 'screenshots/'.

    Returns:
        Dictionary with image path, dimensions, and status.
    """
    if not save_path:
        screenshots_dir = os.path.abspath("screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        target_path = os.path.join(screenshots_dir, f"screenshot_{timestamp}.png")
    else:
        target_path = os.path.abspath(save_path)
        parent = os.path.dirname(target_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    # Guardrail: Prevent saving screenshots into protected system directories
    is_safe, sec_err = validate_path_safety(target_path, operation="write")
    if not is_safe:
        return {
            "success": False,
            "error": sec_err or "Path blocked by security guardrails.",
            "path": target_path,
            "blocked_by_guardrail": True,
        }

    # Attempt 1: PIL ImageGrab
    try:
        image = ImageGrab.grab()
        image.save(target_path, "PNG")
        return {
            "success": True,
            "path": target_path,
            "width": image.width,
            "height": image.height,
            "method": "PIL.ImageGrab",
        }
    except Exception as pil_err:
        # Attempt 2: PowerShell Drawing Screen Capture fallback
        safe_path = target_path.replace("'", "''")
        ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
$bmp.Save('{safe_path}', [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
"""
        try:
            enc = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
            res = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if os.path.exists(target_path) and os.path.getsize(target_path) > 0:
                return {
                    "success": True,
                    "path": target_path,
                    "method": "PowerShell.Graphics",
                }
            else:
                return {
                    "success": False,
                    "error": (
                        f"Screenshot capture failed. Note: Screenshots require an interactive Windows session. "
                        f"PIL error: {str(pil_err)}; PS error: {res.stderr.strip()}"
                    ),
                }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to capture screenshot: {str(e)}",
            }


def show_notification(title: str, message: str) -> Dict[str, Any]:
    """Display a Windows desktop toast or balloon notification safely.

    Args:
        title: Notification header text.
        message: Notification body text.

    Returns:
        Dictionary with notification delivery status.
    """
    # Encode safe strings into base64 to eliminate any PowerShell quoting or script injection issues
    b64_title = base64.b64encode(title.encode("utf-8")).decode("ascii")
    b64_msg = base64.b64encode(message.encode("utf-8")).decode("ascii")

    ps_script = f"""
$rawTitle = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64_title}'))
$rawMessage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{b64_msg}'))

try {{
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    $xmlDoc = New-Object System.Xml.XmlDocument
    $xmlDoc.LoadXml('<toast><visual><binding template="ToastGeneric"><text></text><text></text></binding></visual></toast>')
    $xmlDoc.DocumentElement.visual.binding.text[0].InnerText = $rawTitle
    $xmlDoc.DocumentElement.visual.binding.text[1].InnerText = $rawMessage

    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml($xmlDoc.OuterXml)
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Windows MCP Assistant").Show($toast)
}} catch {{
    Add-Type -AssemblyName System.Windows.Forms
    $notify = New-Object System.Windows.Forms.NotifyIcon
    $notify.Icon = [System.Drawing.SystemIcons]::Information
    $notify.Visible = $true
    $notify.ShowBalloonTip(3000, $rawTitle, $rawMessage, [System.Windows.Forms.ToolTipIcon]::Info)
    Start-Sleep -Seconds 1
    $notify.Dispose()
}}
"""
    try:
        enc = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return {
            "success": res.returncode == 0,
            "title": title,
            "message": message,
            "stderr": res.stderr if res.returncode != 0 else "",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
