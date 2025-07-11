import subprocess
import sys
from pathlib import Path
import unittest

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "tests" / "data"
PASSINSPECTOR = ROOT_DIR / "passinspector" / "passinspector.py"

BASE_ARGS = [sys.executable, str(PASSINSPECTOR),
             "-d", str(DATA_DIR / "dcsync.txt"),
             "-p", str(DATA_DIR / "cracked.txt"),
             "-fp", "test"]


def run(args):
    return subprocess.run(BASE_ARGS + args, cwd=ROOT_DIR,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


class PassInspectorTests(unittest.TestCase):
    def test_basic(self):
        result = run([])
        self.assertEqual(result.returncode, 0, msg=result.stdout)

    def test_all_options(self):
        result = run([
            "-a", "tests/data/admins.txt",
            "-k", "tests/data/kerberoastable.txt",
            "-e", "tests/data/enabled.txt",
            "-cs", "tests/data/credstuff.txt",
            "-su", "tests/data/spray_users.txt",
            "-sp", "tests/data/spray_passwords.txt",
            "-lh", "tests/data/local_hashes.txt",
            "-s", "tests/data/students.txt",
            "-c", "testword"
        ])
        self.assertEqual(result.returncode, 0, msg=result.stdout)

    def test_prepare_hashes(self):
        result = run(["-ph"])
        self.assertEqual(result.returncode, 0, msg=result.stdout)


if __name__ == "__main__":
    unittest.main()
