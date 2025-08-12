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

    def test_option_variations(self):
        options = [
            ("-a", "tests/data/admins.txt"),
            ("-k", "tests/data/kerberoastable.txt"),
            ("-e", "tests/data/enabled.txt"),
            ("-cs", "tests/data/credstuff.txt"),
            ("-su", "tests/data/spray_users.txt"),
            ("-sp", "tests/data/spray_passwords.txt"),
            ("-lh", "tests/data/local_hashes.txt"),
            ("-s", "tests/data/students.txt"),
            ("-c", "testword"),
        ]

        for flag, value in options:
            result = run([flag, value])
            self.assertEqual(result.returncode, 0, msg=f"{flag}: {result.stdout}")

    def test_json_students_file(self):
        result = run(["-s", "tests/data/students.json"])
        self.assertEqual(result.returncode, 0, msg=result.stdout)
        self.assertIn("Student accounts cracked: 1/1", result.stdout)

    def test_all_option_output(self):
        args = [
            "-a", "tests/data/admins.txt",
            "-k", "tests/data/kerberoastable.txt",
            "-e", "tests/data/enabled.txt",
            "-cs", "tests/data/credstuff.txt",
            "-su", "tests/data/spray_users.txt",
            "-sp", "tests/data/spray_passwords.txt",
            "-lh", "tests/data/local_hashes.txt",
            "-s", "tests/data/students.txt",
            "-c", "testword",
            "--debug",
        ]
        result = run(args)
        self.assertEqual(result.returncode, 0, msg=result.stdout)

        output = result.stdout
        self.assertIn("Total accounts cracked: 10/20", output)
        self.assertIn("There were 1 instance(s) of an administrative user sharing a password", output)
        self.assertIn("Enabled employee accounts cracked: 10/15", output)
        self.assertIn("There were 1 valid credential stuffing password(s)", output)
        self.assertIn("Number of Spray Matches (Enabled Username + Password): 1", output)
        self.assertIn("Number Enabled Accounts with Sprayable Passwords: 1", output)
        self.assertIn("There was 1 account found with a password hash matching a local account", output)
        self.assertIn("Student accounts cracked: 1/1", output)

        import re, ast
        match = re.search(r"DEBUG: Externally found users\n(\[.*?\])", output, re.S)
        self.assertIsNotNone(match, "Spray user debug data missing")
        users = ast.literal_eval(match.group(1))
        self.assertEqual(len(users), 5)

    def test_prepare_hashes(self):
        result = run(["-ph"])
        self.assertEqual(result.returncode, 0, msg=result.stdout)


if __name__ == "__main__":
    unittest.main()
