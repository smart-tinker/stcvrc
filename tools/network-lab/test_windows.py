import hashlib
import io
import pathlib
import tempfile
import unittest
from unittest import mock
import zipfile

import windows


class WindowsInputsTests(unittest.TestCase):
    def test_download_rejects_changed_release_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / "core.exe"
            response = io.BytesIO(b"changed release")
            response.url = "https://example.invalid/core.exe"
            with mock.patch.object(windows.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                    windows.download(windows.CORE_URL, target, windows.CORE_SHA)

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
