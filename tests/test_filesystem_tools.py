"""Unit tests for file system manipulation tools and path safety guardrails."""

import os
import shutil
import tempfile
import unittest
from tools.filesystem_tools import (
    copy_or_move,
    delete_file_or_dir,
    get_file_info,
    list_directory,
    read_file,
    search_files,
    write_file,
)


class TestFilesystemTools(unittest.TestCase):
    """Test suite for filesystem_tools module."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="mcp_fs_test_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir)
            except Exception:
                pass

    def test_write_and_read_file_pagination(self):
        """Test writing text and paginating file reads."""
        test_file = os.path.join(self.test_dir, "test_lines.txt")
        lines = [f"Line {i}\n" for i in range(1, 21)]
        write_res = write_file(test_file, "".join(lines))
        self.assertTrue(write_res["success"])

        # Read page 1: lines 1-5
        page1 = read_file(test_file, start_line=1, max_lines=5)
        self.assertEqual(page1["total_lines"], 20)
        self.assertEqual(page1["start_line"], 1)
        self.assertEqual(page1["end_line"], 5)
        self.assertTrue(page1["is_truncated"])
        self.assertIn("Line 1", page1["content"])
        self.assertIn("Line 5", page1["content"])
        self.assertNotIn("Line 6", page1["content"])

        # Read page 2: lines 6-10
        page2 = read_file(test_file, start_line=6, max_lines=5)
        self.assertEqual(page2["start_line"], 6)
        self.assertEqual(page2["end_line"], 10)
        self.assertIn("Line 6", page2["content"])
        self.assertIn("Line 10", page2["content"])

    def test_read_nonexistent_file(self):
        """Test reading a file that does not exist."""
        bad_path = os.path.join(self.test_dir, "nonexistent.txt")
        res = read_file(bad_path)
        self.assertIn("error", res)

    def test_write_file_guardrail_block(self):
        """Test that writing to protected system directories is blocked."""
        system_file = r"C:\Windows\System32\mcp_exploit_test.dll"
        res = write_file(system_file, "evil content")
        self.assertFalse(res["success"])
        self.assertTrue(res.get("blocked_by_guardrail"))
        self.assertIn("SECURITY POLICY VIOLATION", res["error"])

    def test_get_file_info_system_file_allowed(self):
        """Ensure get_file_info can inspect metadata of system files without false-positive blocks."""
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        res = get_file_info(system_root)
        self.assertFalse(res.get("blocked_by_guardrail", False))
        self.assertIn("path", res)
        self.assertTrue(res.get("is_dir"))

        cmd_path = os.path.join(system_root, "System32", "cmd.exe")
        if os.path.exists(cmd_path):
            info = get_file_info(cmd_path)
            self.assertFalse(info.get("blocked_by_guardrail", False))
            self.assertIn("size_bytes", info)
            self.assertTrue(info.get("is_file"))

    def test_delete_file_and_dir_success(self):
        """Test safe file and directory deletion."""
        sub_dir = os.path.join(self.test_dir, "sub")
        os.makedirs(sub_dir)
        dummy_file = os.path.join(sub_dir, "file.txt")
        write_file(dummy_file, "content")

        # Delete file
        del_file = delete_file_or_dir(dummy_file)
        self.assertTrue(del_file["success"])
        self.assertFalse(os.path.exists(dummy_file))

        # Delete directory
        del_dir = delete_file_or_dir(sub_dir, recursive=True)
        self.assertTrue(del_dir["success"])
        self.assertFalse(os.path.exists(sub_dir))

    def test_delete_guardrail_blocks_system_path(self):
        """Test that delete_file_or_dir prevents deleting system paths and drive roots."""
        for target in ("C:\\", r"C:\Windows", r"C:\Windows\System32"):
            res = delete_file_or_dir(target, recursive=True)
            self.assertFalse(res["success"])
            self.assertTrue(res.get("blocked_by_guardrail"))
            self.assertIn("SECURITY POLICY VIOLATION", res["error"])

    def test_copy_or_move(self):
        """Test copying and moving files."""
        src = os.path.join(self.test_dir, "source.txt")
        dst = os.path.join(self.test_dir, "dest.txt")
        write_file(src, "test copy content")

        # Copy
        res_copy = copy_or_move(src, dst, action="copy")
        self.assertTrue(res_copy["success"])
        self.assertTrue(os.path.exists(src))
        self.assertTrue(os.path.exists(dst))

        # Move
        dst2 = os.path.join(self.test_dir, "dest2.txt")
        res_move = copy_or_move(dst, dst2, action="move")
        self.assertTrue(res_move["success"])
        self.assertFalse(os.path.exists(dst))
        self.assertTrue(os.path.exists(dst2))

    def test_copy_or_move_guardrail_block(self):
        """Test that copy_or_move protects system destinations and sources."""
        src = os.path.join(self.test_dir, "payload.dll")
        write_file(src, "payload")

        # Destination in system path blocked
        res_dest_block = copy_or_move(src, r"C:\Windows\System32\payload.dll", action="copy")
        self.assertFalse(res_dest_block["success"])
        self.assertTrue(res_dest_block.get("blocked_by_guardrail"))

        # Source in system path moving blocked
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        res_src_block = copy_or_move(system_root, os.path.join(self.test_dir, "stolen"), action="move")
        self.assertFalse(res_src_block["success"])
        self.assertTrue(res_src_block.get("blocked_by_guardrail"))

    def test_list_and_search_files(self):
        """Test directory listing and wildcard file search."""
        f1 = os.path.join(self.test_dir, "report_2026.docx")
        f2 = os.path.join(self.test_dir, "data_report.json")
        write_file(f1, "docx content")
        write_file(f2, "{}")

        listing = list_directory(self.test_dir)
        self.assertEqual(listing["total_items"], 2)

        search_res = search_files("*.docx", root_path=self.test_dir)
        self.assertEqual(search_res["count"], 1)
        self.assertEqual(search_res["results"][0]["name"], "report_2026.docx")


if __name__ == "__main__":
    unittest.main()
