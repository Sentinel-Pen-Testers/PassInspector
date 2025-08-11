import unittest
from pathlib import Path
from passinspector import utils

DATA_DIR = Path(__file__).resolve().parent / "data"


class UtilsJsonTests(unittest.TestCase):
    def test_file_to_userlist_json_variants(self):
        json_file = DATA_DIR / "students.json"
        users = utils.file_to_userlist(str(json_file))
        # The file contains one null entry which should be skipped
        self.assertEqual(len(users), 4)
        usernames = {u["USERNAME"] for u in users}
        self.assertIn("user1", usernames)
        self.assertIn("astudentaccount", usernames)
        self.assertIn("jsmith", usernames)
        self.assertIn("standalone", usernames)


if __name__ == "__main__":
    unittest.main()
