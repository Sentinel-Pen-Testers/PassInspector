from passinspector import dehexify

class User:
    def __init__(self, domain, username, lmhash, nthash, password, cracked, has_lm,
                 blank_password, enabled, is_admin, kerberoastable, student, local_pass_repeat, pass_repeat, email,
                 job_title, description, spray_user, spray_password):
        self.domain = domain
        self.username = username
        self.lmhash = lmhash
        self.nthash = nthash
        self.password = password
        self.cracked = cracked
        self.has_lm = has_lm
        self.blank_password = blank_password
        self.enabled = enabled
        self.is_admin = is_admin
        self.kerberoastable = kerberoastable
        self.student = student
        self.local_pass_repeat = local_pass_repeat
        self.pass_repeat = pass_repeat
        self.email = email
        self.job_title = job_title
        self.description = description
        self.spray_user = spray_user
        self.spray_password = spray_password
        self.notable_password = []
        self.lacks_aes = False

    def fix_password(self):
        """Fixes a password if it is in HEX format."""
        if "$HEX[" in self.password:
            try:
                self.password = dehexify.dehexify(self.password)
            except Exception as e:
                print(f"Failed to dehexify password for {self.username}: {e}")

    def check_membership(self, group_members, attribute):
        for group_member in group_members:
            if self.username.lower() == group_member['USERNAME'].lower() and self.domain.lower() == group_member['DOMAIN'].lower():
                setattr(self, attribute, True)

    def check_notable_password(self):
        if not self.password:
            return
        if self.username.lower() in self.password.lower() or self.password.lower() in self.username.lower():
            self.notable_password.append("Username in Password")
        if self.username.lower() == self.password.lower():
            self.notable_password.append("Username is Password")

        seasons = ["spring", "summer", "fall", "autumn", "winter"]
        if any(season in self.password.lower() for season in seasons):
            self.notable_password.append("Season")

        common_keyboard_walks = ["qwerty", "asdf", "qaz", "zxc", "12345", "09876", "jkl", "xcvbn", "1q2w3e", "rewq"]
        if any(walk in self.password.lower() for walk in common_keyboard_walks):
            self.notable_password.append("Keyboard Walk")

        common_terms = ["password", "letmein", "welcome", "abc", "qwertz"]
        if any(common_term in self.password.lower() for common_term in common_terms):
            self.notable_password.append("Common Term")

    def check_blank_password(self):
        if self.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0":
            self.blank_password = True
