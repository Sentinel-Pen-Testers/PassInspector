import io
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from passinspector import utils

DATA_DIR = Path(__file__).resolve().parent / "data"


class UtilsJsonTests(unittest.TestCase):
    def test_file_to_userlist_json_variants(self):
        json_file = DATA_DIR / "students.json"
        users = utils.file_to_userlist(str(json_file))
        # The file contains one null entry which should be skipped
        self.assertEqual(len(users), 4)
        usernames = {u["USERNAME"] for u in users}
        self.assertIn("user01", usernames)
        self.assertIn("astudentaccount", usernames)
        self.assertIn("jsmith", usernames)
        self.assertIn("standalone", usernames)

    def test_file_to_userlist_text_emails(self):
        txt_file = DATA_DIR / "emails-unverified.txt"
        buf = io.StringIO()
        with redirect_stdout(buf):
            users = utils.file_to_userlist(str(txt_file))

        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(len(users), 3)
        first = users[0]
        self.assertEqual(first["USERNAME"], "20benjamin.wise")
        self.assertEqual(first["DOMAIN"], "example.com")


if __name__ == "__main__":
    unittest.main()
