"""File system manipulation tools for Windows MCP Server."""

import fnmatch
import os
import re
import shutil
import stat
import time
from typing import Any, Dict
from security import validate_path_safety, validate_read_safety


def _format_time(timestamp: float) -> str:
    """Format Unix timestamp into readable ISO-like string."""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
    except Exception:
        return ""


def _remove_readonly(func: Any, path: str, exc_info: Any) -> None:
    """Error handler for shutil.rmtree on Windows to clear read-only file attributes."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


def read_file(
    path: str,
    start_line: int = 1,
    max_lines: int = 500,
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """Read contents of a text file with line-range pagination.

    Args:
        path: Path to the file (absolute or relative).
        start_line: 1-indexed line number to start reading from (default: 1).
        max_lines: Maximum number of lines to return (clamped between 1 and 5000, default: 500).
        encoding: Text encoding (default: 'utf-8').

    Returns:
        Dictionary containing file content, total line count, and range details.
    """
    clean_path = path.strip().strip("\"'") if path else ""
    if re.match(r"^[a-zA-Z]:$", clean_path):
        clean_path = clean_path + "\\"
    abs_path = os.path.abspath(clean_path)

    # Guardrail: Prevent unauthorized exfiltration of credential stores and sensitive files
    is_safe, sec_err = validate_read_safety(abs_path)
    if not is_safe:
        return {"error": sec_err or "Reading sensitive file blocked by security guardrails.", "path": abs_path, "blocked_by_guardrail": True}

    if not os.path.exists(abs_path):
        return {"error": f"File does not exist: {abs_path}", "path": abs_path}
    if not os.path.isfile(abs_path):
        return {"error": f"Path is a directory, not a file: {abs_path}", "path": abs_path}

    max_lines = max(1, min(max_lines, 5000))
    start_line = max(1, start_line)

    lines = []
    total_lines = 0

    # Stream lines safely without loading multi-gigabyte files entirely into memory
    read_success = False
    for enc in (encoding, "utf-8", "cp1252", "latin-1"):
        try:
            with open(abs_path, "r", encoding=enc, errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    total_lines += 1
                    if start_line <= idx < start_line + max_lines:
                        lines.append(line)
            read_success = True
            break
        except Exception:
            continue

    if not read_success:
        return {"error": f"Unable to read file: {abs_path}", "path": abs_path}

    end_line = min(total_lines, start_line + len(lines) - 1) if lines else start_line - 1

    return {
        "path": abs_path,
        "total_lines": total_lines,
        "start_line": start_line,
        "end_line": end_line,
        "content": "".join(lines),
        "is_truncated": (start_line + max_lines - 1) < total_lines,
    }


def write_file(
    path: str,
    content: str,
    mode: str = "w",
    encoding: str = "utf-8",
) -> Dict[str, Any]:
    """Write or append text content to a file. Creates parent directories if missing.

    Args:
        path: Target file path.
        content: Text content to write.
        mode: 'w' to overwrite or 'a' to append (default: 'w').
        encoding: File encoding (default: 'utf-8').

    Returns:
        Dictionary with status, bytes written, and absolute path.
    """
    if mode not in ("w", "a"):
        return {"success": False, "error": f"Invalid mode '{mode}'. Use 'w' or 'a'."}

    clean_path = path.strip().strip("\"'") if path else ""
    if re.match(r"^[a-zA-Z]:$", clean_path):
        clean_path = clean_path + "\\"
    abs_path = os.path.abspath(clean_path)

    # Guardrail: Prevent overwriting critical system files
    is_safe, path_err = validate_path_safety(abs_path, operation="write")
    if not is_safe:
        return {"success": False, "error": path_err, "path": abs_path, "blocked_by_guardrail": True}

    parent_dir = os.path.dirname(abs_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    try:
        with open(abs_path, mode, encoding=encoding) as f:
            f.write(content)
        bytes_written = len(content.encode(encoding))

        return {
            "success": True,
            "path": abs_path,
            "mode": mode,
            "characters_written": len(content),
            "bytes_written": bytes_written,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "path": abs_path}


def list_directory(
    path: str = ".",
    recursive: bool = False,
    max_depth: int = 2,
    max_items: int = 100,
) -> Dict[str, Any]:
    """List contents of a directory with file sizes and modification dates.

    Args:
        path: Directory path (default: current directory).
        recursive: Whether to list subdirectories recursively (default: False).
        max_depth: Maximum recursion depth when recursive is True (default: 2).
        max_items: Maximum items to return to prevent overflowing context (default: 100).

    Returns:
        Dictionary with item list and total count.
    """
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        return {"error": f"Directory does not exist: {abs_path}", "items": []}
    if not os.path.isdir(abs_path):
        return {"error": f"Path is not a directory: {abs_path}", "items": []}

    max_items = max(1, min(max_items, 1000))
    items = []

    def scan_dir(current_dir: str, depth: int):
        nonlocal items
        if len(items) >= max_items:
            return
        try:
            with os.scandir(current_dir) as entries:
                for entry in sorted(entries, key=lambda e: (not e.is_dir(), e.name.lower())):
                    if len(items) >= max_items:
                        break
                    try:
                        stat_res = entry.stat()
                        is_dir = entry.is_dir()
                        items.append({
                            "name": entry.name,
                            "path": entry.path,
                            "is_dir": is_dir,
                            "size_bytes": stat_res.st_size if not is_dir else 0,
                            "modified": _format_time(stat_res.st_mtime),
                        })
                        if is_dir and recursive and depth < max_depth:
                            scan_dir(entry.path, depth + 1)
                    except (PermissionError, OSError):
                        continue
        except (PermissionError, OSError):
            pass

    scan_dir(abs_path, 1)

    return {
        "directory": abs_path,
        "total_items": len(items),
        "truncated": len(items) >= max_items,
        "items": items,
    }


def search_files(
    pattern: str,
    root_path: str = ".",
    max_results: int = 50,
) -> Dict[str, Any]:
    """Search for files and directories matching a pattern/wildcard (e.g. '*.py', 'test_*').

    Args:
        pattern: Wildcard search pattern (e.g. '*.txt', '*config*').
        root_path: Starting root directory (default: current directory).
        max_results: Maximum results to return (default: 50).

    Returns:
        Dictionary containing matched files and their metadata.
    """
    abs_root = os.path.abspath(root_path)
    if not os.path.exists(abs_root):
        return {"error": f"Root path does not exist: {abs_root}", "results": []}

    max_results = max(1, min(max_results, 500))
    results = []

    for root, dirs, files in os.walk(abs_root):
        if len(results) >= max_results:
            break
        for name in files + dirs:
            if fnmatch.fnmatch(name.lower(), pattern.lower()):
                full_path = os.path.join(root, name)
                is_dir = os.path.isdir(full_path)
                try:
                    stat_res = os.stat(full_path)
                    results.append({
                        "name": name,
                        "path": full_path,
                        "is_dir": is_dir,
                        "size_bytes": stat_res.st_size if not is_dir else 0,
                        "modified": _format_time(stat_res.st_mtime),
                    })
                except OSError:
                    results.append({"name": name, "path": full_path, "is_dir": is_dir})
                if len(results) >= max_results:
                    break

    return {
        "root_path": abs_root,
        "pattern": pattern,
        "count": len(results),
        "results": results,
    }


def get_file_info(path: str) -> Dict[str, Any]:
    """Get detailed metadata about a file or folder. Read-only operation.

    Args:
        path: Path to inspect.

    Returns:
        Dictionary with size, timestamps, permissions, and file type.
    """
    abs_path = os.path.abspath(path)

    if not os.path.exists(abs_path) and not os.path.islink(abs_path):
        return {"error": f"Path not found: {abs_path}"}

    try:
        stat_res = os.stat(abs_path)
        is_dir = os.path.isdir(abs_path)
        return {
            "path": abs_path,
            "name": os.path.basename(abs_path),
            "is_dir": is_dir,
            "is_file": os.path.isfile(abs_path),
            "is_symlink": os.path.islink(abs_path),
            "size_bytes": stat_res.st_size if not is_dir else 0,
            "size_formatted": f"{stat_res.st_size / (1024 * 1024):.2f} MB" if not is_dir else "N/A",
            "created": _format_time(stat_res.st_ctime),
            "modified": _format_time(stat_res.st_mtime),
            "accessed": _format_time(stat_res.st_atime),
            "extension": os.path.splitext(abs_path)[1].lower() if not is_dir else "",
        }
    except Exception as e:
        return {"error": str(e), "path": abs_path}


def delete_file_or_dir(path: str, recursive: bool = False) -> Dict[str, Any]:
    """Delete a file or folder safely with guardrails against system directory deletion.

    Args:
        path: Path to delete.
        recursive: If True, delete non-empty folders recursively (default: False).

    Returns:
        Dictionary with deletion status and path.
    """
    clean_path = path.strip().strip("\"'") if path else ""
    if re.match(r"^[a-zA-Z]:$", clean_path):
        clean_path = clean_path + "\\"
    abs_path = os.path.abspath(clean_path)

    # Guardrail: Prevent deleting critical system roots and OS directories
    is_safe, path_err = validate_path_safety(abs_path, operation="delete")
    if not is_safe:
        return {"success": False, "error": path_err, "path": abs_path, "blocked_by_guardrail": True}

    if not os.path.exists(abs_path) and not os.path.islink(abs_path):
        return {"success": False, "error": f"Path does not exist: {abs_path}"}

    try:
        if os.path.islink(abs_path) or os.path.isfile(abs_path):
            try:
                os.remove(abs_path)
            except PermissionError:
                # Clear Windows read-only flag and retry
                os.chmod(abs_path, stat.S_IWRITE)
                os.remove(abs_path)
            return {"success": True, "action": "deleted_file", "path": abs_path}
        elif os.path.isdir(abs_path):
            if recursive:
                shutil.rmtree(abs_path, onerror=_remove_readonly)
                return {"success": True, "action": "deleted_directory_recursive", "path": abs_path}
            else:
                try:
                    os.rmdir(abs_path)
                except PermissionError:
                    os.chmod(abs_path, stat.S_IWRITE)
                    os.rmdir(abs_path)
                return {"success": True, "action": "deleted_directory", "path": abs_path}
        return {"success": False, "error": "Unknown path type", "path": abs_path}
    except Exception as e:
        return {"success": False, "error": str(e), "path": abs_path}


def copy_or_move(
    source: str,
    destination: str,
    action: str = "copy",
) -> Dict[str, Any]:
    """Copy or move a file or directory with path protection guardrails.

    Args:
        source: Source path.
        destination: Target destination path.
        action: 'copy' or 'move' (default: 'copy').

    Returns:
        Dictionary with status, source, and destination paths.
    """
    clean_action = action.lower().strip()
    if clean_action not in ("copy", "move"):
        return {"success": False, "error": f"Invalid action: '{action}'. Use 'copy' or 'move'."}

    clean_src = source.strip().strip("\"'") if source else ""
    if re.match(r"^[a-zA-Z]:$", clean_src):
        clean_src = clean_src + "\\"
    clean_dst = destination.strip().strip("\"'") if destination else ""
    if re.match(r"^[a-zA-Z]:$", clean_dst):
        clean_dst = clean_dst + "\\"
    src_abs = os.path.abspath(clean_src)
    dst_abs = os.path.abspath(clean_dst)

    # Guardrail: Validate destination for write/overwrite
    is_safe_dst, dst_err = validate_path_safety(dst_abs, operation="write")
    if not is_safe_dst:
        return {"success": False, "error": dst_err, "destination": dst_abs, "blocked_by_guardrail": True}

    # Guardrail: Prevent credential exfiltration from sensitive source
    is_safe_read, read_err = validate_read_safety(src_abs)
    if not is_safe_read:
        return {"success": False, "error": read_err or "Reading sensitive file blocked by security guardrails.", "source": src_abs, "blocked_by_guardrail": True}

    # Guardrail: If moving, validate source because moving deletes the original
    if clean_action == "move":
        is_safe_src, src_err = validate_path_safety(src_abs, operation="delete")
        if not is_safe_src:
            return {"success": False, "error": src_err, "source": src_abs, "blocked_by_guardrail": True}

    if not os.path.exists(src_abs) and not os.path.islink(src_abs):
        return {"success": False, "error": f"Source does not exist: {src_abs}"}

    try:
        dst_parent = os.path.dirname(dst_abs)
        if dst_parent and not os.path.exists(dst_parent):
            os.makedirs(dst_parent, exist_ok=True)

        if clean_action == "copy":
            if os.path.isdir(src_abs):
                shutil.copytree(src_abs, dst_abs, dirs_exist_ok=True)
            else:
                shutil.copy2(src_abs, dst_abs)
            return {"success": True, "action": "copied", "source": src_abs, "destination": dst_abs}
        else:
            # Move
            shutil.move(src_abs, dst_abs)
            return {"success": True, "action": "moved", "source": src_abs, "destination": dst_abs}
    except Exception as e:
        return {"success": False, "error": str(e), "source": src_abs, "destination": dst_abs}
