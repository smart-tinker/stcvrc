import hashlib
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

import windows


class WindowsInputsTests(unittest.TestCase):
    def test_timeout_kills_owned_tree_before_waiting_for_parent(self):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.pid = 43123
        process.poll.return_value = 1
        process.communicate.side_effect = [subprocess.TimeoutExpired(["fixture"], 1), ("", None)]
        events = mock.Mock()
        events.attach_mock(process.communicate, "communicate")
        with mock.patch.object(windows.subprocess, "Popen", return_value=process) as start, \
                mock.patch.object(windows.subprocess, "run") as kill:
            events.attach_mock(kill, "kill")
            with self.assertRaises(subprocess.TimeoutExpired):
                windows.run_fixture(["fixture"], timeout=1)
            start.assert_called_once_with(["fixture"], stdout=subprocess.PIPE, stderr=None, text=True)
        self.assertEqual(events.mock_calls, [
            mock.call.communicate(timeout=1),
            mock.call.kill(["taskkill.exe", "/PID", "43123", "/T", "/F"], check=True, timeout=15),
            mock.call.communicate(timeout=15),
        ])

    def test_failure_inherits_stderr_and_reports_captured_stdout(self):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.communicate.return_value = ("fixture diagnostic\n", None)
        process.returncode = 7
        process.poll.return_value = 7
        with mock.patch.object(windows.subprocess, "Popen", return_value=process) as start, \
                mock.patch.object(windows.sys, "stderr", new_callable=io.StringIO) as stderr:
            with self.assertRaises(subprocess.CalledProcessError):
                windows.run_fixture(["fixture"])
            self.assertIsNone(start.call_args.kwargs["stderr"])
            self.assertIn("fixture diagnostic", stderr.getvalue())

    def test_child_stderr_reaches_driver_log_on_failure(self):
        child = "import sys; sys.stderr.write('fixture-stderr-marker\\n'); sys.exit(7)"
        driver = f"import sys,windows; windows.run_fixture([sys.executable,'-c',{child!r}])"
        completed = subprocess.run([sys.executable, "-c", driver], cwd=pathlib.Path(__file__).parent,
                                   capture_output=True, text=True, timeout=15)
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("fixture-stderr-marker", completed.stderr.splitlines())

    @unittest.skipUnless(sys.platform == "win32", "Native Windows process-tree cleanup")
    def test_forced_timeout_terminates_child_and_releases_temporary_files(self):
        import ctypes
        from ctypes import wintypes

        with tempfile.TemporaryDirectory() as directory:
            folder = pathlib.Path(directory)
            pid_file, held_file = folder / "child.pid", folder / "held.txt"
            child = ("import os,pathlib,time; "
                     f"held=open({str(held_file)!r},'w'); "
                     f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                     "time.sleep(60)")
            parent = f"import subprocess,sys; subprocess.Popen([sys.executable,'-c',{child!r}]).wait()"
            with self.assertRaises(subprocess.TimeoutExpired):
                windows.run_fixture([sys.executable, "-c", parent], timeout=3)
            self.assertTrue(pid_file.exists(), "Child must have started before the forced timeout")
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel.OpenProcess.restype = wintypes.HANDLE
            kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
            kernel.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel.OpenProcess(0x00100000, False, int(pid_file.read_text()))
            if handle:
                try:
                    self.assertEqual(kernel.WaitForSingleObject(handle, 5000), 0)
                finally:
                    kernel.CloseHandle(handle)
            else:
                self.assertEqual(ctypes.get_last_error(), 87)  # Process already disappeared.
            held_file.unlink()  # Windows refuses this while the child's handle is open.

    def test_download_rejects_changed_xray_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "core.exe"
            response = io.BytesIO(b"changed release")
            response.url = "https://example.invalid/core.exe"
            with mock.patch.object(windows.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                    windows.download(windows.XRAY_URL, target, windows.XRAY_ZIP_SHA)

    def test_fresh_core_requires_the_built_path_and_checks_its_sha(self):
        with mock.patch.dict(windows.os.environ, {}, clear=True):
            with self.assertRaisesRegex(SystemExit, "Fresh STCVRC build path and SHA are required"):
                windows.fresh_core()

        with tempfile.TemporaryDirectory() as directory:
            core = pathlib.Path(directory) / "fresh-core.exe"
            core.write_bytes(b"fresh source build")
            expected = hashlib.sha256(core.read_bytes()).hexdigest()
            env = {"STCVRC_CORE_PATH": str(core), "STCVRC_CORE_SHA256": expected}
            with mock.patch.dict(windows.os.environ, env, clear=True):
                actual_path, actual_sha = windows.fresh_core()
            self.assertEqual(actual_path, core.resolve())
            self.assertEqual(actual_sha, expected)

            env["STCVRC_CORE_SHA256"] = "0" * 64
            with mock.patch.dict(windows.os.environ, env, clear=True):
                with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                    windows.fresh_core()


    def test_extracts_only_the_known_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = pathlib.Path(directory)
            archive, executable = folder / "xray.zip", folder / "xray.exe"
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("xray.exe", b"reviewed executable")
                bundle.writestr("../outside", b"do not extract")
            self.assertEqual(windows.extract_xray(archive, executable),
                             hashlib.sha256(b"reviewed executable").hexdigest())
            self.assertEqual(sorted(path.name for path in folder.iterdir()), ["xray.exe", "xray.zip"])


if __name__ == "__main__":
    unittest.main()
