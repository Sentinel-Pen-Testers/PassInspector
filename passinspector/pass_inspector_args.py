import re
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path


class PassInspectorArgs:
    def __init__(self, args):
        self.admins_filename = args.admins
        self.admin_users = None
        self.custom_search_terms = args.custom
        self.cred_stuffing_accounts = None
        self.cred_stuffing_filename = args.cred_stuffing
        self.cred_stuffing_domains = args.cred_stuffing_domains
        self.dcsync_filename = args.dcsync
        self.debug = args.debug
        self.duplicate_pass_identifier = args.duplicate_password_identifier
        self.enabled_users = None
        self.enabled_users_filename = args.enabled
        self.file_prefix = args.file_prefix
        self.kerberoastable_users_filename = args.kerberoastable_users
        self.local_hash_filename = args.local_hashes
        self.dehashed = not args.no_dehashed  # Flip the variable for readability
        self.neo4j_url = PassInspectorArgs.format_neo4j_url(args.neo4j_hostname)
        self.neo4j_username = args.neo4j_username
        self.neo4j_password = args.neo4j_password
        self.neo4j_queries = {
            "admins": "MATCH (u:User) "
                      "WHERE COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0' "
                      "RETURN toLower(u.domain) + '\\\\' + toLower(u.samaccountname) AS user",
            "enabled": "MATCH (u:User) WHERE u.enabled=true RETURN tolower(u.domain) + '\\\\' + "
                       "tolower(u.samaccountname) AS user",
            "kerberoastable": "MATCH (u:User)"
                       "WHERE u.hasspn=true"
                       "AND NOT u.objectid ENDS WITH '-502'"
                       "AND NOT COALESCE(u.gmsa, false) = true"
                       "AND NOT COALESCE(u.msa, false) = true"
                       "RETURN tolower(u.domain) + '\\\\' + tolower(u.samaccountname) AS user"
        }
        self.cracked_hash_filename = args.passwords
        self.prepare_hashes_mode = args.prepare_hashes
        self.students_filename = args.students
        self.spray_users_filename = args.spray_users
        self.spray_passwords_filename = args.spray_passwords
        self.threads = args.threads
        self.output_filename = None

    @staticmethod
    def find_file(include=None, exclude=None):
        """
        Search recursively from the current directory for the first file whose
        full path contains all 'include' terms and none of the 'exclude' terms.

        Args:
            include (list of str): Substrings that must be present in the path
            exclude (list of str): Substrings that must NOT be present in the path

        Returns:
            str or None: The matching file path as a string, or None if not found
        """
        include = include or []
        exclude = exclude or []

        for file_path in Path(".").rglob("*"):
            if not file_path.is_file():
                continue

            full_path_str = str(file_path).lower()

            if all(term.lower() in full_path_str for term in include) and \
                    not any(term.lower() in full_path_str for term in exclude):
                return str(file_path)

        return None

    @staticmethod
    def format_neo4j_url(raw_hostname: str) -> str:
        """
        Turn user input into a well‐formed neo4j:// URL.
        - Strips whitespace
        - Removes any existing protocol (neo4j://, bolt://, http://, https://)
        - Preserves optional port (e.g. example.com:7687)
        - Raises ValueError if it’s not a valid host[:port]
        """
        if not raw_hostname:
            raise ValueError("Empty hostname")

        host = raw_hostname.strip()

        # strip any trailing slash
        host = host.rstrip("/")

        # remove any existing scheme
        parsed = urlparse(host if "://" in host else "//" + host)
        hostname = parsed.hostname
        port = parsed.port

        if not hostname:
            raise ValueError(f"Could not parse hostname from '{raw_hostname}'")

        # validate hostname (simple regex for host or IPv4/IPv6)
        # IPv6 must be in [brackets], but we’ll trust urlparse for that.
        if not re.match(r"^[\w\.-]+$", hostname.replace(":", "")):
            raise ValueError(f"Invalid characters in hostname '{hostname}'")

        if port:
            return f"neo4j://{hostname}:{port}"
        else:
            return f"neo4j://{hostname}"


    def get_filenames(self):
        if not self.file_prefix:
            self.file_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
            return

        if not self.dcsync_filename:
            self.dcsync_filename = PassInspectorArgs.find_file([self.file_prefix, "dcsync"])
            if self.dcsync_filename:
                print(f"No DCSync file was provided, but a DCSync file was found: {self.dcsync_filename}")
            else:
                print("ERROR: No DCSync file provided or located automatically. Cannot continue!")
                exit()

        if not self.cracked_hash_filename:
            self.cracked_hash_filename = PassInspectorArgs.find_file([self.file_prefix, "cracked"], ['allcracked'])
            if self.cracked_hash_filename:
                print(f"No cracked file was provided, but a cracked file was found: {self.cracked_hash_filename}")
            else:
                print("ERROR: No cracked file file provided or located automatically. Cannot continue!")
                exit()

        if not self.local_hash_filename:
            self.local_hash_filename = PassInspectorArgs.find_file([self.file_prefix, "lsass"])
            if self.local_hash_filename:
                print(
                    f"No list of local password hashes file was provided, but a file was found: {self.local_hash_filename}")

        if not self.spray_users_filename:
            self.spray_users_filename = PassInspectorArgs.find_file([self.file_prefix, "userlist"])
            if self.spray_users_filename:
                print(f"No list of sprayable users was provided, but a file was found: {self.spray_users_filename}")

        if not self.spray_passwords_filename:
            self.spray_passwords_filename = PassInspectorArgs.find_file([self.file_prefix, "passwords"])
            if self.spray_passwords_filename:
                print(f"No list of sprayable passwords was provided, but a file was found: {self.spray_passwords_filename}")


    def parse_arguments(self):
        if self.cred_stuffing_domains:
            self.cred_stuffing_domains = self.cred_stuffing_domains.split(',')

        if self.custom_search_terms:
            self.custom_search_terms = self.custom_search_terms.split(',')

        if (not self.dcsync_filename or not self.cracked_hash_filename) and not self.file_prefix:
            file_prefix = input('No arguments provided for DCSync or cracked password file. '
                                'What is the file prefix for these files? ')
            self.file_prefix = file_prefix.strip()

        if not self.file_prefix:
            self.file_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.output_filename = f"passinspector_results_{self.file_prefix}.txt"