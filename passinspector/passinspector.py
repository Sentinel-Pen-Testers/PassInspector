#!/usr/bin/env python
import binascii
from neo4j import GraphDatabase
import json
import os
import re
import sys
from tqdm import tqdm
from . import utils
from . import export_xlsx
from .pass_inspector_args import PassInspectorArgs

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

    def fix_password(self):
        """Fixes a password if it is in HEX format."""
        if "$HEX[" in self.password:
            try:
                self.password = dehexify(self.password)
            except Exception as e:
                print(f"Failed to dehexify password for {self.username}: {e}")

    def check_membership(self, group_members, attribute):
        for group_member in group_members:
            if self.username.lower() == group_member['USERNAME'].lower() and self.domain.lower() == group_member['DOMAIN'].lower():
                setattr(self, attribute, True)


def main():
    script_version = 2.5
    print("\n==============================")
    print("PassInspector  -  Version", script_version)
    print("==============================\n")

    pi_data = utils.gather_arguments()
    # Handle user error in the provided variables
    pi_data.parse_arguments()

    # If the user just wants to prepare hashes, just do that and exit
    if pi_data.prepare_hashes_mode:
        prepare_hashes(pi_data)

    # Test Neo4j connectivity, and if it fails, set the password to blank so the script doesn't try to connect later
    pi_data, _ = testNeo4jConnectivity(pi_data)

    pi_data.get_filenames()

    dcsync_results = []  # All results and values
    user_database_cracked = []  # Values for any cracked user credential

    dcsync_file_lines = utils.open_file(pi_data.dcsync_filename, pi_data.debug)
    dcsync_file_lines, cleartext_creds = filter_dcsync_file(dcsync_file_lines)

    password_file_lines = utils.open_file(pi_data.cracked_hash_filename, pi_data.debug)
    password_file_lines = deduplicate_passwords(pi_data, password_file_lines)

    pi_data.cred_stuffing_accounts = get_cred_stuffing(pi_data)

    # Take users from a file, otherwise query neo4j if info was provided, otherwise just assign a blank value
    pi_data.admin_users = utils.group_lookup(pi_data, "admins", pi_data.admins_filename)
    pi_data.enabled_users = utils.group_lookup(pi_data, "enabled", pi_data.enabled_users_filename)
    pi_data.kerberoastable_users = utils.group_lookup(pi_data, "kerberoastable", pi_data.kerberoastable_users_filename)

    # Check on the domains that were found to make sure they match
    pi_data, dcsync_file_lines = check_domains(pi_data, dcsync_file_lines)

    # Create a list of User (see User class) objects
    user_database = create_user_database(dcsync_file_lines, cleartext_creds, password_file_lines)

    user_database = utils.fix_bad_passwords(user_database)
    user_database = utils.check_group_member(user_database, pi_data.kerberoastable_users, "kerberoastable")
    user_database = utils.check_group_member(user_database, pi_data.admin_users, "is_admin")
    user_database = utils.check_group_member(user_database, pi_data.enabled_users, "enabled")
    if cleartext_creds:
        user_database = add_cleartext_creds(user_database, cleartext_creds)
    if pi_data.students_filename:
        user_database = parse_students(user_database, pi_data.students_filename)
    if pi_data.local_hash_filename:
        user_database = parse_local_hashes(user_database, pi_data.local_hash_filename)

    for user in user_database:
        if user.cracked:
            user_database_cracked.append(user)

    # Create a progress bar with eight steps
    pbar = tqdm(total=8, desc="Calculating statistics", ncols=100, leave=False)
    # Step 1: Calculate password lengths for enabled and all users
    stat_enabled_shortest, stat_enabled_longest, result_enabled_shortest_passwords, result_enabled_longest_passwords, \
        stat_all_shortest, stat_all_longest, result_all_shortest_passwords, result_all_longest_passwords = \
        calculate_password_long_short(user_database)
    pbar.update(1)
    # Step 2: Perform password search on cracked users
    (text_blank_passwords, text_terms, text_seasons, text_keyboard_walks, text_custom_search, result_blank_passwords,
     result_common_terms, result_seasons, result_keyboard_walks, result_custom_search) = \
        perform_password_search(user_database_cracked, pi_data.custom_search_terms)
    pbar.update(1)
    # Step 3: Search for usernames used as passwords
    text_username_passwords, result_username_passwords = username_password_search(user_database_cracked)
    pbar.update(1)
    # Step 4: Inspect administrative password reuse
    text_admin_pass_reuse, results_admin_pass_reuse = admin_password_inspection(user_database)
    pbar.update(1)
    # Step 5: Inspect LM hash usage
    text_lm_hashes, result_lm_hash_users = lm_hash_inspection(user_database)
    pbar.update(1)
    # Step 6: Identify enabled accounts with blank passwords
    text_blank_passwords, result_blank_enabled = blank_enabled_search(user_database, text_blank_passwords)
    pbar.update(1)
    # Step 7: Check for credential stuffing matches
    text_cred_stuffing, result_cred_stuffing = cred_stuffing_check(pi_data.cred_stuffing_accounts, user_database)
    pbar.update(1)
    # Step 8: Check for spray matches
    user_database, num_spray_matches, num_pass_spray_matches = check_if_spray(pi_data, user_database)
    pbar.update(1)
    pbar.close()
    # Step 9: Check for password reuse (this takes a while compared to the others, so it gets its own loading bar)
    user_database = count_pass_repeat(user_database)
    if pi_data.duplicate_pass_identifier:
        user_database = calc_duplicate_password_identifier(user_database)

    printed_stats = show_results(stat_enabled_shortest, stat_enabled_longest, stat_all_shortest, stat_all_longest,
                                 text_blank_passwords, text_terms, text_seasons, text_keyboard_walks,
                                 text_custom_search, text_username_passwords, text_admin_pass_reuse, text_lm_hashes,
                                 text_cred_stuffing, num_spray_matches,
                                 num_pass_spray_matches, user_database)

    print("Writing out files")
    write_cracked_file(printed_stats, pi_data.file_prefix, user_database, result_enabled_shortest_passwords,
                       result_enabled_longest_passwords, result_all_shortest_passwords, result_all_longest_passwords,
                       result_blank_passwords, result_common_terms, result_seasons, result_keyboard_walks,
                       result_custom_search, result_username_passwords, results_admin_pass_reuse, result_lm_hash_users,
                       result_blank_enabled, result_cred_stuffing)
    export_xlsx.write_xlsx(pi_data.file_prefix, user_database)
    print("Done!")


def check_if_spray(pi_data, user_database):
    num_spray_matches = 0
    num_pass_spray_matches = 0
    neo4j_connectivity = False
    if pi_data.neo4j_password:
        _, neo4j_connectivity = testNeo4jConnectivity(pi_data)

    # Return default values if no spray files are provided and Neo4j is unavailable
    if not pi_data.spray_users_filename and not pi_data.spray_passwords_filename and not neo4j_connectivity:
        print("No input files provided, and Neo4j connectivity is unavailable. Exiting.")
        return user_database, 123456, 123456  # Tells the printing function not to print these stats

    # Step 1: Fetch emails from Neo4j if Neo4j connectivity is available
    if neo4j_connectivity:
        if pi_data.debug:
            print("Fetching emails from Neo4j...")
        user_database = emails_from_neo4j(pi_data, user_database)

    # Step 2: Import data from external spray users file if provided
    spray_users = []
    if pi_data.spray_users_filename:
        spray_users = utils.file_to_userlist(pi_data.spray_users_filename)
        if pi_data.debug:
            print("DEBUG: Spray users provided")
            print(spray_users)

    # Step 3: Determine which users in the user database were found externally
    externally_found_users = []
    for user in user_database:
        for external_user in spray_users:
            if user in externally_found_users:  # Skip if user is already added
                break

            # Check if username matches
            if user.username.lower() == external_user['USERNAME'].lower():
                # Match domain if provided
                if external_user['DOMAIN'] and user.domain.lower() == external_user['DOMAIN'].lower():
                    externally_found_users.append(user)
                    user.spray_user = True
                    break
                elif not external_user['DOMAIN']:  # Match username only if DOMAIN is None
                    externally_found_users.append(user)
                    user.spray_user = True
                    break

            # Check if spray_user in "username@domain.com" format matches the email
            if external_user['DOMAIN']:  # Check only if DOMAIN is present
                spray_email = f"{external_user['USERNAME']}@{external_user['DOMAIN']}".lower()
                if user.email and user.email.lower() == spray_email:
                    externally_found_users.append(user)
                    user.spray_user = True
                    break

    if pi_data.debug:
        print("DEBUG: Externally found users")
        print([vars(user) for user in externally_found_users])

    # Step 4: Check passwords from spray file if provided
    if pi_data.spray_passwords_filename:
        print("Checking passwords from spray file...")
        with open(pi_data.spray_passwords_filename, 'r') as passwords_file:
            spray_passwords = [password.strip().lower() for password in passwords_file]
            if pi_data.debug:
                print("DEBUG: Provided spray passwords")
                print(spray_passwords)

        for user in user_database:
            if user.spray_user and user.password and user.password.lower() in spray_passwords:
                user.spray_password = True
            else:
                user.spray_password = False

    # Step 5: Calculate stats
    if pi_data.spray_passwords_filename:
        for user in externally_found_users:
            if user.spray_password and user.enabled:
                num_spray_matches += 1
            if user.spray_password and user.enabled:
                num_pass_spray_matches += 1
    elif pi_data.debug:
        print("No spray password file supplied. Cannot calculate stats.")

    return user_database, num_spray_matches, num_pass_spray_matches


def check_domains(pi_data, dcsync_file_lines):
    dcsync_domains = set()  # Domain(s) from the DCSync
    imported_domains = set()  # Domain(s) from Neo4j or provided files for admin and enabled users
    unique_domains_imported = set()
    unique_domains_dcsync = set()

    # Skip this if no admin/enabled/kerberoastable user files or Neo4j creds were provided
    if not pi_data.admin_users and not pi_data.enabled_users and not pi_data.kerberoastable_users and not pi_data.neo4j_password:
        return pi_data, dcsync_file_lines

    # ------------------------------------------------------------
    # Phase 1: Extract domains from DCSync file lines
    # ------------------------------------------------------------
    for line in tqdm(dcsync_file_lines, desc="Extracting domains from DCSync", ncols=80, leave=False):
        try:
            parts = line.split(':')
            domain_user_combined = parts[0].split('\\', 1)
        except IndexError:
            print(f"ERROR: Index error encountered: {IndexError}")
            return None
        # If there is a domain specified, add it to the set
        if len(domain_user_combined) == 2:
            dcsync_domains.add(domain_user_combined[0].lower())

    # ------------------------------------------------------------
    # Phase 2: Extract domains from imported user lists
    # ------------------------------------------------------------
    for user in tqdm(pi_data.admin_users, desc="Processing admin users", ncols=80, leave=False):
        imported_domains.add(user['DOMAIN'].lower())
    for user in tqdm(pi_data.enabled_users, desc="Processing enabled users", ncols=80, leave=False):
        imported_domains.add(user['DOMAIN'].lower())
    for user in tqdm(pi_data.kerberoastable_users, desc="Processing kerberoastable users", ncols=80, leave=False):
        imported_domains.add(user['DOMAIN'].lower())

    if pi_data.debug:
        print(f"DEBUG: imported_domains {imported_domains}")
        print(f"DEBUG: dcsync_domains {dcsync_domains}")

    # ------------------------------------------------------------
    # Phase 3: Compare domains to find uniques
    # ------------------------------------------------------------
    for domain in tqdm(imported_domains, desc="Comparing imported domains", ncols=80, leave=False):
        if domain not in dcsync_domains:
            unique_domains_imported.add(domain)
    for domain in tqdm(dcsync_domains, desc="Comparing DCSync domains", ncols=80, leave=False):
        if domain not in imported_domains:
            unique_domains_dcsync.add(domain)

    # ------------------------------------------------------------
    # Phase 4: Resolve unique domains from imported data
    # ------------------------------------------------------------
    if unique_domains_imported:
        for unique_domain in tqdm(unique_domains_imported, desc="Resolving unique imported domains", ncols=80):
            no_match_text = "DCSync"
            new_domain = ""
            try:
                # Try to use curses TUI if available
                import curses
                new_domain = curses.wrapper(domain_change_tui, unique_domain, no_match_text, dcsync_domains)
            except ImportError:
                # Otherwise, fallback to CLI
                new_domain = domain_change_cli(unique_domain, no_match_text, dcsync_domains)

            if new_domain:
                old_domain = unique_domain
                pi_data.admin_users, pi_data.enabled_users, pi_data.kerberoastable_users = replace_imported_domain(
                    old_domain, new_domain, pi_data.admin_users, pi_data.enabled_users, pi_data.kerberoastable_users)
            else:
                print(f"No changes made for domain {unique_domain}")

    # ------------------------------------------------------------
    # Phase 5: Resolve unique domains from the DCSync file
    # ------------------------------------------------------------
    if unique_domains_dcsync:
        neo4j_status = False
        if pi_data.neo4j_password:
            neo4j_status = testNeo4jConnectivity(pi_data)

        for unique_domain in tqdm(unique_domains_dcsync, desc="Resolving unique DCSync domains", ncols=80):
            no_match_text = "imported data"
            new_domain = ""
            if neo4j_status:
                # Attempt to fix automatically using Neo4j data if possible
                new_domain, resolved_pairs = domain_change_auto(pi_data, unique_domain, dcsync_file_lines)
                if resolved_pairs == "PARTIAL":
                    replace_dcsync_domain_user_specific(pi_data, resolved_pairs, dcsync_file_lines)
            # If auto-resolve failed, prompt the user
            if new_domain == "":
                try:
                    import curses
                    new_domain = curses.wrapper(domain_change_tui, unique_domain, no_match_text, imported_domains)
                except ImportError:
                    new_domain = domain_change_cli(unique_domain, no_match_text, imported_domains)
            if new_domain:
                old_domain = unique_domain
                dcsync_file_lines = replace_dcsync_domain(old_domain, new_domain, dcsync_file_lines)
            else:
                print(f"No changes made for domain {unique_domain}")

    return pi_data, dcsync_file_lines


def domain_change_cli(unique_domain, no_match_text, domain_choices):
    print("============================================================================\n")
    print(f"! The domain {unique_domain} doesn't appear to match the {no_match_text}.\n")
    print("! If it is incorrect, PassInspector cannot correctly determine\n")
    print("! if users are enabled, Kerberoastable, and/or administrative\n")
    print(f"! Please enter the intended domain (from the {no_match_text})\n")
    print("! or press ENTER if no changes should be made.\n")
    print("============================================================================\n")
    print("! Available options: \n")
    if domain_choices:
        for domain_to_print in domain_choices:
            print(f"{domain_to_print}")
    new_domain = input("(Press ENTER for no changes) Matching Domain: ")
    new_domain = new_domain.lower().strip()
    return new_domain


def domain_change_tui(stdscr, unique_domain, no_match_text, domain_choices):
    import curses
    selection_mode = True
    stdscr.clear()
    stdscr.addstr("============================================================================\n")
    stdscr.addstr(f"The domain {unique_domain} doesn't appear to match the {no_match_text}.\n")
    stdscr.addstr("If it is incorrect, PassInspector cannot correctly determine\n")
    stdscr.addstr("if users are enabled, Kerberoastable, and/or administrative\n")
    stdscr.addstr(f"Please enter the intended domain (from the {no_match_text})\n")
    stdscr.addstr("Available options: \n")
    stdscr.addstr("============================================================================\n")

    options = ["No change"] + list(domain_choices)
    selected_index = 0

    while selection_mode:
        for idx, option in enumerate(options):
            if idx == selected_index:
                stdscr.addstr(f"> {option}\n", curses.A_REVERSE)
            else:
                stdscr.addstr(f"  {option}\n")

        key = stdscr.getch()

        if key == curses.KEY_UP and selected_index > 0:
            selected_index -= 1
        elif key == curses.KEY_DOWN and selected_index < len(options) - 1:
            selected_index += 1
        elif key == curses.KEY_ENTER or key in [10, 13]:
            selected_option = options[selected_index]
            selection_mode = False
            break

        stdscr.clear()
        stdscr.addstr("============================================================================\n")
        stdscr.addstr(f"The domain {unique_domain} doesn't appear to match the {no_match_text}.\n")
        stdscr.addstr("If it is incorrect, PassInspector cannot correctly determine\n")
        stdscr.addstr("if users are enabled, Kerberoastable, and/or administrative\n")
        stdscr.addstr(f"Please enter the intended domain (from the {no_match_text})\n")
        stdscr.addstr("Available options: \n")
        stdscr.addstr("============================================================================\n")

    if selected_option in domain_choices:
        new_domain = selected_option
    else:
        new_domain = ""
    return new_domain


def replace_imported_domain(old_domain, new_domain, admin_users, enabled_users, kerberoastable_users):
    print(f"Updating {old_domain} domain in imported data to {new_domain}")

    for user in admin_users:
        if user['DOMAIN'].lower() == old_domain:
            user['DOMAIN'] = new_domain
    for user in enabled_users:
        if user['DOMAIN'].lower() == old_domain:
            user['DOMAIN'] = new_domain
    for user in kerberoastable_users:
        if user['DOMAIN'].lower() == old_domain:
            user['DOMAIN'] = new_domain
    return admin_users, enabled_users, kerberoastable_users


def domain_change_auto(pi_data, old_domain, dcsync_file_lines):
    # This function checks all users matching a unique domain to see if they appear in Neo4j
    # a single time. If so, it will auto "fix" them. Otherwise, it'll skip on to allow a
    # manual adjustment to be made
    if not pi_data.neo4j_password:
        print("Neo4j checks disabled, skipping automatic domain resolution.")
        return "", {}

    # Step 1: Extract all usernames for the unique domain
    usernames = []
    if old_domain.upper() == "NONE":
        # When old_domain is "NONE", parse lines that do not contain a domain (no backslash)
        for line in dcsync_file_lines:
            if "\\" not in line:
                username = line.split(":", 1)[0]  # Extract the username before the first ':'
                usernames.append(username)
    else:
        # Otherwise, parse lines with a domain and match against old_domain
        for line in dcsync_file_lines:
            if "\\" in line:
                domain, rest = line.split("\\", 1)  # Split at the first occurrence of '\'
                if domain.lower() == old_domain.lower():
                    username = rest.split(":", 1)[0]  # Extract the username before the first ':'
                    usernames.append(username)
    if pi_data.debug:
        print(f"Found the following users for the {old_domain} domain:")
        print(usernames)

    if not usernames:
        print(f"No usernames found for the domain '{old_domain}' in the DCSync file. Something must have gone wrong.")
        return "", {}

    # Step 2: Query Neo4j for all users and build a mapping of username to domains
    resolved_domains = set()  # Unique set of domains for matching users
    resolved_pairs = {}  # Mapping of username -> domain (only if exactly one match exists)
    query_string = "MATCH (u:User) RETURN toLower(u.domain) + '\\\\' + toLower(u.samaccountname) AS user"
    neo4j_results = utils.neo4j_query(query_string, pi_data.neo4j_url, pi_data.neo4j_username, pi_data.neo4j_password)

    # Build a dictionary mapping username to a set of domains from Neo4j results
    user_domain_map = {}
    for record in neo4j_results:
        uname = record['USERNAME']
        dom = record['DOMAIN']
        if uname not in user_domain_map:
            user_domain_map[uname] = set()
        user_domain_map[uname].add(dom)

    # For each username from the DCSync file, if there's exactly one matching domain in Neo4j, record the pair
    for username in usernames:
        uname = username.lower()
        if uname in user_domain_map:
            domains = user_domain_map[uname]
            if len(domains) == 1:
                resolved_pairs[uname] = list(domains)[0]
                resolved_domains.add(list(domains)[0])
                if pi_data.debug:
                    print(f"User {uname} resolved to domain {resolved_pairs[uname]}")
            else:
                if pi_data.debug:
                    print(f"User {uname} has multiple domains: {user_domain_map[uname]}")
        else:
            if pi_data.debug:
                print(f"User {uname} not found in Neo4j results")
    resolved_domains = list(resolved_domains)  # Convert to a de-duplicated list
    if pi_data.debug:
        print(f"The following domain(s) were identified for users on the {old_domain} domain: {resolved_domains}")

    # Step 3: Determine if all results point to the same domain
    if len(resolved_domains) == 1:
        # If there was just one domain returned, it successfully figured out the matching domain automatically and can just go fix them
        resolved_domain = resolved_domains.pop()
        return resolved_domain, {}
    elif len(resolved_domains) == 0:
        print(f"No matching domains found in Neo4j for users under '{old_domain}'.")
        return "", {}
    else:
        if list(resolved_pairs):  # If there was more than one domain, but some users had just one domain, fix those at least
            print(f"Only able to fix some users automatically on the {old_domain} domain")
            return "PARTIAL", resolved_pairs
        else:
            print(f"Failed to automatically resolve domain '{old_domain}'")
            return "", {}


def replace_dcsync_domain(old_domain, new_domain, dcsync_file_lines):
    print(f"Updating {old_domain} domain in DCSync to {new_domain}")

    for i in range(len(dcsync_file_lines)):
        if "\\" in dcsync_file_lines[i]:
            domain, rest = dcsync_file_lines[i].split("\\", 1)  # Split only at the first occurrence of '\'
            if domain.lower() == old_domain.lower():  # Case-insensitive comparison
                dcsync_file_lines[i] = f"{new_domain}\\{rest}"

    return dcsync_file_lines


def replace_dcsync_domain_user_specific(pi_data, resolved_pairs, dcsync_file_lines):
    print("Updating specific users in DCSync file using auto resolved domain.")
    if pi_data.debug:
        print(f"Resolved pairs: {resolved_pairs}")

    for i, line in enumerate(dcsync_file_lines):
        if "\\" in line:
            domain, rest = line.split("\\", 1)  # Split at the first occurrence of '\'
            username = rest.split(":", 1)[0].strip().lower()  # Extract username before the first ':'
            if username in resolved_pairs:
                new_domain = resolved_pairs[username]
                old_line = dcsync_file_lines[i]
                dcsync_file_lines[i] = f"{new_domain}\\{rest}"
                if pi_data.debug:
                    print(f"Updated line: {old_line} -> {dcsync_file_lines[i]}")
        else:
            # No domain present; extract username and prepend the resolved domain if available.
            username = line.split(":", 1)[0].strip().lower()
            if username in resolved_pairs:
                new_domain = resolved_pairs[username]
                old_line = dcsync_file_lines[i]
                dcsync_file_lines[i] = f"{new_domain}\\{line}"
                if pi_data.debug:
                    print(f"Updated line (no domain): {old_line} -> {dcsync_file_lines[i]}")
    return dcsync_file_lines


def create_user_database(dcsync_file_lines, cleartext_creds, password_file_lines):
    user_database = []
    skipped_lines = []

    # Wrap the iteration over the DCSync file lines with a tqdm progress bar
    for line in tqdm(dcsync_file_lines, desc="Importing users", leave=False):
        # Split the line into its components (assuming the format: DOMAIN\USERNAME:RID:LMHASH:NTHASH:::)
        try:
            domain_user, rid, lmhash, nthash, *_ = line.split(':')  # Extract and discard RID
            if '\\' in domain_user:
                domain, username = domain_user.split('\\', 1)
            else:
                domain = "NONE"
                username = domain_user
        except ValueError:
            skipped_lines.append(f"Skipping processing for invalid line in dcsync: {line}")
            continue

        # Determine derived attributes
        has_lm = lmhash != "aad3b435b51404eeaad3b435b51404ee"  # Default empty LM hash
        blank_password = nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"  # Default NT hash for blank password
        password, cracked = check_if_cracked(nthash, password_file_lines)
        local_pass_repeat = 0
        pass_repeat = 0
        student = False

        # Create a User object and add it to the database
        user_database.append(
            User(
                domain=domain,
                username=username,
                lmhash=lmhash,
                nthash=nthash,
                password=password,
                cracked=cracked,
                has_lm=has_lm,
                blank_password=blank_password,
                enabled=False,
                is_admin=False,
                kerberoastable=False,
                student=student,
                local_pass_repeat=local_pass_repeat,
                pass_repeat=pass_repeat,
                email=None,
                job_title=None,
                description=None,
                spray_user=False,
                spray_password=False
            )
        )

    if skipped_lines:
        for skipped in skipped_lines:
            print(skipped)

    return user_database


def deduplicate_passwords(pi_data, password_file_lines):
    if pi_data.debug:
        print("De-duplicating passwords")
    unique_lines = set()
    for line in password_file_lines:
        unique_lines.add(line)
    return unique_lines


def check_if_cracked(nt_hash, password_file_lines):
    for line in password_file_lines:
        try:
            stored_nt_hash, password = line.strip().split(':', 1)
        except ValueError:
            continue
        if stored_nt_hash == nt_hash:
            if '$HEX[' in password:
                password = dehexify(password)
            return password, True
    # If this code is running, no password was found, so return false
    return "", False


def dehexify(password):
    dehexed_password = "ERROR DECODING HEX"
    try:
        # Remove the "$HEX[" prefix and "]" suffix
        hex_string = password[len("$HEX["):-1]
        dehexed_password = binascii.unhexlify(hex_string).decode(
            'latin-1')  # Using latin-1 to account for other languages like German
        # dehexed_password = binascii.unhexlify(hex_string).decode('latin-1', 'replace') # Will stop errors,
        # but only by replacing problematic characters
    except binascii.Error:
        # Handle the case where the hex conversion fails
        print("ERROR: Could not dehexify the following value: ", password)
    return dehexed_password


def check_if_admin(user, domain, admin_users):
    for user_to_check in admin_users:
        if domain:
            # If a domain was supplied, use it when comparing
            if ((user.lower() == user_to_check['USERNAME'].lower()) and (
                    domain.lower() == user_to_check['DOMAIN'].lower())):
                return True
        else:
            # If the domain is blank, just compare usernames
            if user.lower() == user_to_check['USERNAME'].lower():
                return True
    return False


def calculate_password_long_short(user_database):
    def find_password_lengths(users):
        shortest_length = float('inf')  # Start with infinity for shortest length
        longest_length = 0  # Start with 0 for longest length
        shortest_passwords = []
        longest_passwords = []

        for user in users:
            password = user.password
            if password and len(password) > 0:  # Skip blank passwords
                length = len(password)
                if length < shortest_length:
                    shortest_length = length
                    shortest_passwords = [password]
                elif length == shortest_length:
                    shortest_passwords.append(password)

                if length > longest_length:
                    longest_length = length
                    longest_passwords = [password]
                elif length == longest_length:
                    longest_passwords.append(password)

        return shortest_length, longest_length, shortest_passwords, longest_passwords

    # Separate enabled and all users
    enabled_users = [user for user in user_database if user.enabled]
    all_users = user_database

    # Calculate for enabled users
    enabled_shortest, enabled_longest, enabled_shortest_passwords, enabled_longest_passwords = find_password_lengths(
        enabled_users)

    # Calculate for all users
    all_shortest, all_longest, all_shortest_passwords, all_longest_passwords = find_password_lengths(all_users)

    return enabled_shortest, enabled_longest, enabled_shortest_passwords, enabled_longest_passwords, all_shortest, all_longest, all_shortest_passwords, all_longest_passwords


def perform_password_search(user_database_cracked, search_terms):
    common_terms = ["password", "letmein", "welcome", "abc", "qwertz"]
    common_seasons = ["spring", "summer", "fall", "autumn", "winter"]
    common_keyboard_walks = ["qwerty", "asdf", "qaz", "zxc", "12345", "09876", "jkl", "xcvbn", "1q2w3e", "rewq"]
    result_blank_passwords = []
    result_common_terms = []
    result_seasons = []
    result_keyboard_walks = []
    result_custom_search = []
    stats = {
        "blank_passwords": "",
        "terms": "",
        "seasons": "",
        "keyboard_walks": "",
        "custom_search": "",
    }
    counts = {
        "blank_passwords": 0,
        "terms": 0,
        "seasons": 0,
        "keyboard_walks": 0,
        "custom_search": 0,
    }
    enabled_counts = {
        "blank_passwords": 0,
        "terms": 0,
        "seasons": 0,
        "keyboard_walks": 0,
        "custom_search": 0,
    }

    def inner_search(terms, users):
        normal_count = 0
        leet_count = 0
        leet_text = ""
        result_records = []

        for term in terms:
            for user in users:
                if term.lower() in user.password.lower():
                    normal_count += 1
                    result_records.append(user)
            leet_terms = convert_to_leetspeak(term)
            for leet_term in leet_terms:
                for user in users:
                    if leet_term.lower() in user.password.lower():
                        leet_count += 1
                        result_records.append(user)

        if leet_count > 0:
            leet_text = f" ({leet_count} contained leetspeech)"
            normal_count += leet_count

        return normal_count, leet_text, result_records

    # Blank passwords
    for user in user_database_cracked:
        if user.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0":
            counts["blank_passwords"] += 1
            result_blank_passwords.append(user)
            if user.enabled:
                enabled_counts["blank_passwords"] += 1

    if counts["blank_passwords"] > 0:
        stats[
            "blank_passwords"] = f"There were {counts['blank_passwords']} account(s) found with blank passwords. {enabled_counts['blank_passwords']} of these belonged to enabled users."

    # Common terms
    counts["terms"], leet_text, result_common_terms = inner_search(common_terms, user_database_cracked)
    enabled_counts["terms"] = sum(1 for user in result_common_terms if user.enabled)
    if counts["terms"] > 0:
        stats["terms"] = (f"There were {counts['terms']} password(s) found to contain common terms such as 'password', "
                          f"'welcome', or 'letmein'{leet_text}. {enabled_counts['terms']} of these belonged to enabled users.")

    # Seasons
    counts["seasons"], leet_text, result_seasons = inner_search(common_seasons, user_database_cracked)
    enabled_counts["seasons"] = sum(1 for user in result_seasons if user.enabled)
    if counts["seasons"] > 0:
        stats["seasons"] = (f"There were {counts['seasons']} password(s) found to contain seasons of the year "
                            f"(Spring, Summer, Fall, Autumn, Winter){leet_text}. {enabled_counts['seasons']} of these belonged to enabled users.")

    # Keyboard walks
    counts["keyboard_walks"], leet_text, result_keyboard_walks = inner_search(common_keyboard_walks,
                                                                              user_database_cracked)
    enabled_counts["keyboard_walks"] = sum(1 for user in result_keyboard_walks if user.enabled)
    if counts["keyboard_walks"] > 0:
        stats["keyboard_walks"] = (f"There were {counts['keyboard_walks']} password(s) found to be keyboard walks, "
                                   f"such as 'qwerty', 'zxc', or 'asdf'{leet_text}. {enabled_counts['keyboard_walks']} of these belonged to enabled users.")

    # Custom search
    if search_terms:
        for term in search_terms:
            count, leet_text, results = inner_search([term], user_database_cracked)
            counts["custom_search"] += count
            result_custom_search.extend(results)

        enabled_counts["custom_search"] = sum(1 for user in result_custom_search if user.enabled)
        if counts["custom_search"] > 0:
            stats["custom_search"] = (f"There were {counts['custom_search']} result(s) for the custom search terms "
                                      f"{', '.join(search_terms)}{leet_text}. {enabled_counts['custom_search']} of these belonged to enabled users.")

    return (
        stats["blank_passwords"],
        stats["terms"],
        stats["seasons"],
        stats["keyboard_walks"],
        stats["custom_search"],
        result_blank_passwords,
        result_common_terms,
        result_seasons,
        result_keyboard_walks,
        result_custom_search,
    )


def username_password_search(user_database_cracked):
    text_username_passwords = ""
    result_username_passwords = []
    count_username_password = 0
    count_username_password_exact = 0
    count_enabled_users = 0
    count_enabled_users_exact = 0

    for user in user_database_cracked:
        username = user.username.lower()
        password = user.password.lower() if user.password else ""

        if username in password or password in username:
            count_username_password += 1
            result_username_passwords.append(user)
            if user.enabled:
                count_enabled_users += 1
            if username == password:
                count_username_password_exact += 1
                if user.enabled:
                    count_enabled_users_exact += 1

    if count_username_password > 0:
        text_username_passwords = (f"There were {count_username_password} account(s) using their username as part "
                                   f"of their password. {count_enabled_users} of these belonged to enabled users.")
        if count_username_password_exact > 0:
            text_username_passwords += (f" {count_username_password_exact} of these account(s) used their username "
                                        f"as their password without any additional complexity, and "
                                        f"{count_enabled_users_exact} of these belonged to enabled users.")

    return text_username_passwords, result_username_passwords


def admin_password_inspection(user_database):
    admin_password_matches = []
    text_password_matches = ""

    # Filter admin and non-admin users
    admin_users = [user for user in user_database if user.is_admin]
    non_admin_users = [user for user in user_database if not user.is_admin]

    enabled_admin_matches = 0

    for admin in admin_users:
        admin_hash = admin.nthash
        matching_users = []
        enabled_matching_users = 0

        for non_admin in non_admin_users:
            if non_admin.nthash == admin_hash:
                matching_users.append(non_admin.username)
                if non_admin.enabled:
                    enabled_matching_users += 1

        if matching_users:
            if admin.enabled:
                enabled_admin_matches += 1
            admin_password_matches.append({
                'ADMIN_USER': admin.username,
                'NTHASH': admin_hash,
                'NON_ADMIN_USERS': matching_users,
                'ENABLED_NON_ADMIN_USERS': enabled_matching_users,
            })

    if admin_password_matches:
        text_password_matches = (f"There were {len(admin_password_matches)} instance(s) of an administrative user "
                                 f"sharing a password with non-administrative accounts. "
                                 f"{enabled_admin_matches} of these administrative accounts were enabled.")

    return text_password_matches, admin_password_matches


def lm_hash_inspection(user_database):
    lm_hash_users = []
    text_results = ""
    enabled_lm_hash_users = 0

    for user in user_database:
        if user.has_lm:
            lm_hash_users.append(user)
            if user.enabled:
                enabled_lm_hash_users += 1

    if len(lm_hash_users) > 0:
        text_results = (f"LM hashes were found to be stored for {len(lm_hash_users)} account(s). "
                        f"{enabled_lm_hash_users} of these accounts are enabled.")

    return text_results, lm_hash_users


def blank_enabled_search(user_database, text_blank_passwords):
    # Returns additional text for the blank password line and user accounts with blank passwords
    blank_enabled_users = []
    text_results = ""

    for user in user_database:
        if user.blank_password and user.enabled:
            blank_enabled_users.append(user)

    if len(blank_enabled_users) > 0:
        text_results = f" ({len(blank_enabled_users)} of these accounts were enabled)"
    text_blank_passwords += text_results

    return text_blank_passwords, blank_enabled_users


def cred_stuffing_check(cred_stuffing_accounts, user_database):
    cred_stuffing_matches = []
    text_results = ""
    enabled_matches_count = 0

    for cred_stuffing_account in cred_stuffing_accounts:
        for user in user_database:
            if (cred_stuffing_account['USERNAME'].lower() == user.username.lower() and
                    cred_stuffing_account['PASSWORD'] == user.password):
                cred_stuffing_matches.append(f"{cred_stuffing_account['USERNAME']}:{cred_stuffing_account['PASSWORD']}")
                if user.enabled:
                    enabled_matches_count += 1

    if len(cred_stuffing_matches) > 0:
        text_results = (
            f"There were {len(cred_stuffing_matches)} valid credential stuffing password(s) found to be valid. "
            f"{enabled_matches_count} of these accounts were enabled.")

    return text_results, cred_stuffing_matches


def average_pass_length(user_database):
    employee_total = 0
    employee_count = 0
    enabled_total = 0
    enabled_count = 0
    student_total = 0
    student_count = 0

    for user in user_database:
        if user.password:  # Ignoring blank and uncracked passwords in calculation
            if not user.student:
                employee_total += len(user.password)
                employee_count += 1
            else:
                student_total += len(user.password)
                student_count += 1
            if user.enabled and not user.student:
                enabled_total += len(user.password)
                enabled_count += 1

    employee_average = round(employee_total / employee_count, 2) if employee_count > 0 else 0
    student_average = round(student_total / student_count, 2) if student_count > 0 else 0
    enabled_average = round(enabled_total / enabled_count, 2) if enabled_count > 0 else 0

    return employee_average, student_average, enabled_average


def calc_da_cracked(user_database):
    da_cracked = 0
    da_total = 0
    unique_users = set()

    for user in user_database:
        user_key = (user.domain, user.username)
        if user_key not in unique_users:
            unique_users.add(user_key)
            if user.is_admin:
                da_total += 1
                if user.cracked:
                    da_cracked += 1

    return da_cracked, da_total


def calculate_unique_hashes(user_database):
    unique_hashes = []
    cracked_unique_hashes = 0
    unique_users = set()

    for user in user_database:
        user_key = (user.domain, user.username)
        if user_key not in unique_users:
            unique_users.add(user_key)
            if user.nthash not in unique_hashes:
                unique_hashes.append(user.nthash)
                if user.cracked:
                    cracked_unique_hashes += 1

    if unique_hashes:
        uniq_cracked_percent = (cracked_unique_hashes / len(unique_hashes)) * 100
    else:
        uniq_cracked_percent = 0

    return len(unique_hashes), f"({uniq_cracked_percent:.2f}%)", cracked_unique_hashes


def calculate_cracked(user_database):
    all_cracked = 0
    employee_cracked = 0
    employee_total = 0
    enabled_cracked = 0
    enabled_total = 0
    student_cracked = 0
    student_total = 0

    unique_users = set()

    for user in user_database:
        user_key = (user.domain, user.username)
        if user_key not in unique_users:
            unique_users.add(user_key)
            if user.cracked:
                all_cracked += 1

            if user.student:
                student_total += 1
                if user.cracked:
                    student_cracked += 1
            else:
                employee_total += 1
                if user.cracked:
                    employee_cracked += 1

            if user.enabled:
                enabled_total += 1
                if user.cracked:
                    enabled_cracked += 1

    student_crack_percent = f"({(student_cracked / student_total * 100):.2f}%)" if student_total != 0 else "0%"
    employee_crack_percent = f"({(employee_cracked / employee_total * 100):.2f}%)" if employee_total != 0 else "0%"
    enabled_crack_percent = f"({(enabled_cracked / enabled_total * 100):.2f}%)" if enabled_total != 0 else "0%"
    all_crack_percent = f"({(all_cracked / len(user_database) * 100):.2f}%)" if len(user_database) != 0 else "0%"

    return (employee_cracked, employee_total, employee_crack_percent, student_cracked, student_total,
            student_crack_percent, enabled_cracked, enabled_total, enabled_crack_percent, all_cracked,
            len(user_database), all_crack_percent)


def show_results(stat_enabled_shortest, stat_enabled_longest, stat_all_shortest, stat_all_longest, text_blank_passwords,
                 text_terms, text_seasons, text_keyboard_walks,
                 text_custom_search, text_username_passwords, text_admin_pass_reuse, text_lm_hashes, text_cred_stuffing,
                 stat_spray_matches,
                 stat_spray_pass_matches, user_database):
    da_cracked, da_total = calc_da_cracked(user_database)
    stat_total_uniq, uniq_cracked_percent, stat_cracked_uniq = calculate_unique_hashes(user_database)
    avg_pass_len, student_avg_pass_len, enabled_avg_pass_len = average_pass_length(user_database)
    (employee_cracked, employee_total, employee_crack_percent, student_cracked, student_total, student_crack_percent,
     enabled_cracked, enabled_total, enabled_crack_percent, all_cracked, all_total,
     all_crack_percent) = calculate_cracked(user_database)

    results_text = ""

    print("")
    print("")
    print("")
    print("=============================")
    print("========== RESULTS ==========")
    print("=============================")
    results_text += utils.print_and_log(
        f"Unique passwords cracked: {stat_cracked_uniq}/{stat_total_uniq} {uniq_cracked_percent}", results_text)
    results_text += utils.print_and_log(f"Total accounts cracked: {all_cracked}/{all_total} {all_crack_percent}",
                                        results_text)
    results_text += utils.print_and_log(
        f"Enabled employee accounts cracked: {enabled_cracked}/{enabled_total} {enabled_crack_percent}", results_text)
    if student_cracked:
        results_text += utils.print_and_log(
            f"Total employee accounts cracked: {employee_cracked}/{employee_total} {employee_crack_percent}",
            results_text)
        results_text += utils.print_and_log(
            f"Student accounts cracked: {student_cracked}/{student_total} {student_crack_percent}",
            results_text)
    if da_total > 0:
        results_text += utils.print_and_log(
            f"DA accounts cracked: {da_cracked}/{da_total} ({((da_cracked / da_total) * 100):.2f}%)", results_text)
    results_text += utils.print_and_log(f"Average employee password length: {avg_pass_len}", results_text)
    results_text += utils.print_and_log(f"Average enabled employee password length: {enabled_avg_pass_len}",
                                        results_text)
    if student_avg_pass_len:
        results_text += utils.print_and_log(f"Student average password length: {student_avg_pass_len}", results_text)
    results_text += utils.print_and_log(f"Shortest password length (not counting blank passwords): {stat_all_shortest}",
                                        results_text)
    results_text += utils.print_and_log(
        f"Shortest password length for an enabled account (not counting blank passwords): {stat_enabled_shortest}",
        results_text)
    results_text += utils.print_and_log(f"Longest password length: {stat_all_longest}", results_text)
    results_text += utils.print_and_log(f"Longest password length for an enabled account: {stat_enabled_longest}",
                                        results_text)
    results_text += utils.print_and_log(text_blank_passwords, results_text) if text_blank_passwords else ""
    local_pass_repeated = count_local_hash(user_database)
    if local_pass_repeated > 0:
        results_text += utils.print_and_log(f"There {'were' if local_pass_repeated > 1 else 'was'} "
                                            f"{local_pass_repeated} account{'s' if local_pass_repeated > 1 else ''} found "
                                            f"with a password hash matching a local account.", results_text)
    results_text += utils.print_and_log(text_terms, results_text) if text_terms else ""
    results_text += utils.print_and_log(text_seasons, results_text) if text_seasons else ""
    results_text += utils.print_and_log(text_keyboard_walks, results_text) if text_keyboard_walks else ""
    results_text += utils.print_and_log(text_custom_search, results_text) if text_custom_search else ""
    results_text += utils.print_and_log(text_username_passwords, results_text) if text_username_passwords else ""
    results_text += utils.print_and_log(text_admin_pass_reuse, results_text) if text_admin_pass_reuse else ""
    results_text += utils.print_and_log(text_lm_hashes, results_text) if text_lm_hashes else ""
    results_text += utils.print_and_log(text_cred_stuffing, results_text) if text_cred_stuffing else ""
    if stat_spray_matches != 123456:
        utils.print_and_log(f"Number of Spray Matches (Enabled Username + Password): {stat_spray_matches}",
                            results_text)
    if stat_spray_pass_matches != 123456:
        utils.print_and_log(f"Number Enabled Accounts with Sprayable Passwords: {stat_spray_pass_matches}",
                            results_text)
    print("")
    print("")
    print("")

    return results_text


def write_cracked_file(printed_stats, file_datetime, user_database, result_enabled_shortest_passwords,
                       result_enabled_longest_passwords, result_all_shortest_passwords, result_all_longest_passwords,
                       result_blank_passwords, result_common_terms, result_seasons, result_keyboard_walks,
                       result_custom_search, result_username_passwords, results_admin_pass_reuse, result_lm_hash_users,
                       result_blank_enabled, result_cred_stuffing):
    output_filename = f"passinspector_allcracked_{file_datetime}.txt"
    print(f"Writing all cracked passwords to {output_filename}")
    results = ["USERNAME,PASSWORD,ENABLED,ADMIN,STUDENT"]
    for user in user_database:
        if user.cracked:
            result = f"{user.username},{user.password},{user.enabled},{user.is_admin},{user.student}"
            results.append(result)
    with open(output_filename, 'w') as outfile:
        for result in results:
            outfile.write(result + '\n')

    output_filename = f"passinspector_results_{file_datetime}.txt"
    print(f"Writing each of the results to {output_filename}")
    results = []
    results.append("=======================")
    results.append("RESULTS SUMMARY")
    results.append("=======================")
    results.append(printed_stats)
    results.append("=======================")
    results.append("SHORTEST PASSWORD(S) FOR ENABLED ACCOUNTS")
    results.append("=======================")
    for record in result_enabled_shortest_passwords:
        results.append(record)
    results.append("=======================")
    results.append("LONGEST PASSWORD(S) FOR ENABLED ACCOUNTS")
    results.append("=======================")
    for record in result_enabled_longest_passwords:
        results.append(record)
    results.append("=======================")
    results.append("SHORTEST PASSWORD(S) FOR ALL ACCOUNTS")
    results.append("=======================")
    for record in result_all_shortest_passwords:
        results.append(record)
    results.append("=======================")
    results.append("LONGEST PASSWORD(S) FOR ALL ACCOUNTS")
    results.append("=======================")
    for record in result_all_longest_passwords:
        results.append(record)
    if result_blank_passwords:
        results.append("")
        results.append("=======================")
        results.append("ACCOUNTS WITH BLANK PASSWORDS")
        results.append("=======================")
        for record in result_blank_passwords:
            results.append(record.username)
    if result_blank_enabled:
        results.append("")
        results.append("=======================")
        results.append("ENABLED ACCOUNTS WITH BLANK PASSWORDS")
        results.append("=======================")
        for user in result_blank_enabled:
            results.append(user.username)
    if result_common_terms:
        results.append("")
        results.append("=======================")
        results.append("COMMON TERM PASSWORDS")
        results.append("=======================")
        for record in result_common_terms:
            result = f"{record.username},{record.password}"
            results.append(result)
    if result_seasons:
        results.append("")
        results.append("=======================")
        results.append("SEASON PASSWORDS")
        results.append("=======================")
        for record in result_seasons:
            result = f"{record.username},{record.password}"
            results.append(result)
    if result_keyboard_walks:
        results.append("")
        results.append("=======================")
        results.append("KEYBOARD WALK PASSWORDS")
        results.append("=======================")
        for record in result_keyboard_walks:
            result = f"{record.username},{record.password}"
            results.append(result)
    if result_custom_search:
        results.append("")
        results.append("=======================")
        results.append("CUSTOM SEARCH TERM PASSWORDS")
        results.append("=======================")
        for record in result_custom_search:
            result = f"{record.username},{record.password}"
            results.append(result)
    if result_username_passwords:
        results.append("")
        results.append("=======================")
        results.append("USERNAMES AS PASSWORDS")
        results.append("=======================")
        for record in result_username_passwords:
            result = f"{record.username},{record.password}"
            results.append(result)
    if results_admin_pass_reuse:
        results.append("")
        results.append("=======================")
        results.append("ADMIN PASSWORD REUSE")
        results.append("=======================")
        for record in results_admin_pass_reuse:
            result = f"The administrative user {record['ADMIN_USER']} shares a password (NT Hash: {record['NTHASH']}) with the non-administrative user(s): {', '.join(record['NON_ADMIN_USERS'])}"
            results.append(result)
    if result_lm_hash_users:
        results.append("")
        results.append("=======================")
        results.append("USERS WITH LM HASHES")
        results.append("=======================")
        for record in result_lm_hash_users:
            result = f"{record.username},{record.lmhash}"
            results.append(result)
    if result_cred_stuffing:
        results.append("")
        results.append("=======================")
        results.append("VALID CREDENTIAL STUFFING RESULTS")
        results.append("=======================")
        for account in result_cred_stuffing:
            results.append(account)
    with open(output_filename, 'w') as outfile:
        for result in results:
            outfile.write(f"{result}\n")


def parse_admin_file(l_admins_filename):
    l_admin_users = []
    try:
        with open(l_admins_filename, 'r') as file:
            for line in file:
                line = line.rstrip('\n').strip('"')  # Remove newline character and quotes from the line
                if '\\' in line:  # If there is a backslash on the line
                    parts = line.split('\\')  # Split the line on backslash
                    # Add the second part (to the right of backslash) to the admin_users list
                    l_admin_users.append(parts[1])
                else:
                    l_admin_users.append(line)  # If no backslash, add the entire line to the admin_users list
    except FileNotFoundError:
        print("ERROR: Could not find admins file:", l_admins_filename)
        exit()
    return l_admin_users


def convert_to_leetspeak(term):
    leetspeak_mapping = {
        'a': '@',
        'e': '3',
        'i': '!',
        'o': '0',
        's': '5',
        't': '7'
    }

    leetspeak_variations = [term]

    for i, char in enumerate(term):
        lowercase_char = char.lower()

        if lowercase_char in leetspeak_mapping:
            leet_chars = leetspeak_mapping[lowercase_char]
            new_variations = []
            for variation in leetspeak_variations:
                for leet_char in leet_chars:
                    new_variation = variation[:i] + leet_char + variation[i + 1:]
                    new_variations.append(new_variation)
            leetspeak_variations.extend(new_variations)
    # Remove the first entry of the variations, which is just the original search term
    leetspeak_variations.pop(0)

    return leetspeak_variations


def split_username(raw_username):
    l_username = raw_username.split("\\")
    if len(l_username) == 2:
        l_domain = l_username[0]
        l_username = l_username[1]
    else:
        l_domain = ""
        l_username = l_username[0]

    return l_domain, l_username


def filter_cleartext(dcsync_lines):
    cleartext_creds = []
    for line in dcsync_lines[:]:
        if "CLEARTEXT" in line:
            dcsync_lines.remove(line)
            line = line.split(":")
            domain, username = split_username(line[0])
            cleartext_creds.append({"Domain": domain, "Username": username, "Password": line[2]})

    if cleartext_creds:
        print(f"Cleartext Credentials Found: {len(cleartext_creds)}")
    return dcsync_lines, cleartext_creds


def filter_nonntlm(dcsync):
    dcsync_filtered = []
    for line in dcsync:
        if ":::" in line:
            dcsync_filtered.append(line)

    return dcsync_filtered


def filter_machines(l_dcsync):
    filtered_dcsync = []
    machine_count = 0
    for line in l_dcsync:
        if "$" not in line:
            filtered_dcsync.append(line)
        else:
            machine_count += 1

    print(f"Machine Accounts: {machine_count}")  # TODO: Move to results section
    return filtered_dcsync


def filter_dcsync_file(dcsync_file_lines):
    dcsync_file_lines, cleartext_creds = filter_cleartext(dcsync_file_lines)  # Extract cleartext credentials
    dcsync_file_lines = filter_nonntlm(dcsync_file_lines)  # Filter out lines without NTLM Hashes
    dcsync_file_lines = filter_machines(dcsync_file_lines)  # Filter out machine accounts
    return dcsync_file_lines, cleartext_creds


def calc_duplicate_password_identifier(user_database):
    password_identifier_key = 0
    password_identifiers = []

    for user in user_database:
        for password_identifier in password_identifiers:
            if user.nthash == password_identifier['NTHASH']:
                user.pass_identifier = password_identifier['PASS_IDENTIFIER']
                break
        else:
            password_identifiers.append({'NTHASH': user.nthash, 'PASS_IDENTIFIER': password_identifier_key})
            user.pass_identifier = password_identifier_key
            password_identifier_key += 1

    return user_database


def add_cleartext_creds(user_database, cleartext_creds):
    for clear_cred in cleartext_creds:
        for user in user_database:
            if user.domain == clear_cred['Domain'] and user.username == clear_cred['Username']:
                if user.password == "":  # Only overwrite the password if it doesn't exist
                    user.password = clear_cred['Password']
                    # We don't mark the password as cracked since it comes from the clear text file
    return user_database


def count_pass_repeat(user_database):
    for user in tqdm(user_database, desc="Counting password repeats (May take a while)", ncols=80, file=sys.stdout, leave=False):
        pass_repeat_count = sum(1 for other_user in user_database if user.nthash == other_user.nthash)
        user.pass_repeat = pass_repeat_count
    return user_database


def prepare_hashes(pi_data):
    machine_count = 0
    ntlm_hashes = []

    dcsync_lines = utils.open_file(pi_data.dcsync_filename, pi_data.debug)
    dcsync_lines, cleartext_hashes = filter_cleartext(dcsync_lines)
    dcsync_lines = filter_nonntlm(dcsync_lines)
    dcsync_lines = filter_machines(dcsync_lines)

    for line in dcsync_lines:
        line = line.split(":")
        domain, username = split_username(line[0])
        ntlm_hashes.append({"Domain": domain, "Username": username, "SID": line[1], "LM_Hash": line[2],
                            "NT_Hash": line[3]})

    # Remove Cleartext Passwords From NTLM Hashes
    for cleartext_hash in cleartext_hashes[:]:
        for ntlm_hash in ntlm_hashes[:]:
            if cleartext_hash['Username'] == ntlm_hash['Username']:
                ntlm_hashes.remove(ntlm_hash)
                break

    # Extract Just NT Hashes, Then Remove Duplicates
    just_nt_hashes = []
    for ntlm_hash in ntlm_hashes:
        just_nt_hashes.append(ntlm_hash["NT_Hash"])
    just_nt_hashes = list(set(just_nt_hashes))

    # Print Results
    if machine_count:
        print(f"Number of Machine Accounts: {machine_count}")
    if cleartext_hashes:
        print(f"Number of Cleartext Hashes: {len(cleartext_hashes)}")
    if ntlm_hashes:
        print(f"Number of NTLM Hashes: {len(ntlm_hashes)}")
        print(f"Number of Unique NT Hashes: {len(just_nt_hashes)}")

        # Output Results to File
        filename = f"{pi_data.file_prefix}-NT_Hashes.txt"
        with open(filename, 'w') as file:
            for nt_hash in just_nt_hashes:
                file.write(nt_hash + "\n")
        print(f"\nUnique NT Hashes Written To: {filename}")

    exit()


def parse_students(user_database, students_filename):
    print("Parsing students")
    students = utils.file_to_userlist(students_filename)
    for user in user_database:
        for student in students:
            if user.username.lower() == student['USERNAME'].lower():
                user.student = True
                break
    return user_database


def emails_from_neo4j(pi_data, user_database):
    if not pi_data.neo4j_password:
        print("Neo4j checks disabled, skipping email lookup.")
        return user_database
    try:
        with GraphDatabase.driver(pi_data.neo4j_url, auth=(pi_data.neo4j_username, pi_data.neo4j_password)) as driver:
            with driver.session() as session:
                # Run one big query to fetch user email, job title, and description info from Neo4j
                query = (
                    "MATCH (u:User) "
                    "RETURN toUpper(u.samaccountname) AS username, "
                    "toUpper(u.domain) AS domain, "
                    "u.email AS email, "
                    "u.title AS title, "
                    "u.description AS description"
                )
                results = session.run(query)
                # Build a mapping: (username, domain) -> {email, title, description}
                user_info_map = {}
                for record in results:
                    uname = record["username"]
                    dom = record["domain"] if record["domain"] is not None else "NONE"
                    email = record["email"]
                    title = record["title"]
                    description = record["description"]
                    user_info_map[(uname, dom)] = {
                        "email": email,
                        "title": title,
                        "description": description,
                    }

                # Update each user in the database using the mapping
                for user in user_database:
                    uname = user.username.upper()
                    dom = user.domain.upper() if user.domain else "NONE"
                    info = user_info_map.get((uname, dom), {})
                    user.email = info.get("email")
                    user.job_title = info.get("title")
                    user.description = info.get("description")
            return user_database
    except Exception as e:
        print(f"ERROR: Neo4j query failed, unable to pull user emails - {e}")
        return user_database


def testNeo4jConnectivity(pi_data):
    try:
        with GraphDatabase.driver(pi_data.neo4j_url, auth=(pi_data.neo4j_username, pi_data.neo4j_password)) as driver:
            driver.verify_connectivity()
            return pi_data, True
    except Exception as e:
        pi_data.neo4j_url, pi_data.neo4j_username, pi_data.neo4j_password = None, None, None
        return pi_data, False


def retrieve_cred_stuffing_results(pi_data):
    # Checks to see if BreachCreds.py is available, and if so, it will search DeHashed for credential stuffing accounts
    try:
        import BreachCreds
    except ImportError:
        print("Unable to find BreachCreds.py in the current directory, skipping credential stuffing checks")
        return []

    cred_stuffing_accounts = []
    if not pi_data.neo4j_password and not pi_data.cred_stuffing_domains:
        print("Neo4j checks disabled, skipping DeHashed search")
        return []
    if pi_data.cred_stuffing_domains:
        # If a credential-stuffing domain was specified, use that
        print("Searching DeHashed for credential stuffing results (This may take some time)")
        dehashed_results = BreachCreds.main(pi_data.cred_stuffing_domains.split(','), display=False, write_files=False)
        if dehashed_results:
            dehashed_results_with_passwords = [entry for entry in dehashed_results if 'Password' in entry]
            if dehashed_results_with_passwords:
                print(f"Found {len(dehashed_results_with_passwords)} result(s) from DeHashed with passwords")
                for result in dehashed_results_with_passwords:
                    username = result["Username"]
                    password = result["Password"]
                    cred_stuffing_accounts.append({'USERNAME': username, 'PASSWORD': password})
            else:
                print("No DeHashed results with passwords returned for credential stuffing checks")
                return []
        else:
            print("No DeHashed results returned for credential stuffing checks")
            return []
    elif pi_data.neo4j_password:
        # If a Neo4j password was specified, use that
        try:
            with GraphDatabase.driver(pi_data.neo4j_url, auth=(pi_data.neo4j_username, pi_data.neo4j_password)) as driver:
                session = driver.session()
                results = session.run(
                    "MATCH (u:User) WHERE u.email IS NOT NULL RETURN distinct(split(u.email, '@')[1]) as DOMAIN")
                domains = []
                for result in results:
                    match = re.search(r"'([^']*)'", str(result))
                    if match:
                        domains.append(match.group(1))
        except Exception as e:
            print(f"ERROR: Neo4j query failed, unable to search for domains - {e}")
            return []
        if domains:
            print(f"Retrieved {len(domains)} domain(s) from Neo4j, searching DeHashed (This may take some time)")
            dehashed_results = BreachCreds.main(domains, display=False, write_files=False)
            # dehashed_results = [{'Username': 'user1@example.com'},{'Username': 'user2@example.com', 'Password': 'Password123'},{'Username': 'user3@example.com'},{'Username': 'user4@example.com', 'Password': 'Password456'}]
            if dehashed_results:
                dehashed_results_with_passwords = [entry for entry in dehashed_results if 'Password' in entry]
                if dehashed_results_with_passwords:
                    print(f"Found {len(dehashed_results_with_passwords)} result(s) from DeHashed with passwords")
                    for result in dehashed_results_with_passwords:
                        username = result["Username"]
                        password = result["Password"]
                        cred_stuffing_accounts.append({'USERNAME': username, 'PASSWORD': password})
                else:
                    print("No DeHashed results with passwords returned for credential stuffing checks")
                    return []
            else:
                print("No DeHashed results returned for credential stuffing checks")
                return []
        else:
            print("No domains returned from Neo4j for DeHashed search. Moving on.")
            return []
    else:
        # This should never happen, but just to be safe...
        print("ERROR: Unknown credential stuffing search error, skipping")
        return []

    # If DeHashed results returned, write the DeHashed results to a file
    if cred_stuffing_accounts:
        write_dehashed_file(cred_stuffing_accounts)

    return cred_stuffing_accounts


def get_cred_stuffing(pi_data):
    if pi_data.cred_stuffing_filename:
        lines = utils.open_file(pi_data.cred_stuffing_filename, pi_data.debug)
        cred_stuffing_accounts = []

        with tqdm(total=len(lines), desc="Processing cred stuffing lines", ncols=100, leave=False) as pbar:
            for line in lines:
                if ':' in line:
                    username, password = line.split(':', 1)
                else:
                    parts = line.split()
                    if len(parts) == 2:
                        username, password = parts
                    else:
                        if pi_data.debug:
                            print(f"Skipping malformed credential stuffing line: {line}")
                        pbar.update(1)
                        continue

                cred_stuffing_accounts.append({'USERNAME': username, 'PASSWORD': password})
                pbar.update(1)

    elif os.path.isfile("passinspector_dehashed_results.txt"):
        cred_stuffing_accounts = import_dehashed_file()
    elif (pi_data.cred_stuffing_domains or pi_data.neo4j_password) and pi_data.dehashed:
        cred_stuffing_accounts = retrieve_cred_stuffing_results(pi_data)
    else:
        cred_stuffing_accounts = []

    return cred_stuffing_accounts


def write_dehashed_file(cred_stuffing_accounts):
    output_filename = f"passinspector_dehashed_results.txt"
    print(f"Writing DeHashed results locally to {output_filename}")
    results = []
    for record in cred_stuffing_accounts:
        results.append(record)
    with open(output_filename, 'w') as outfile:
        outfile.write(json.dumps(cred_stuffing_accounts))
        # for result in results:
        #     outfile.write(result + '\n')


def import_dehashed_file():
    # If a local DeHashed file exists, read from that
    import_filename = f"passinspector_dehashed_results.txt"
    print("Importing DeHashed results from local file")
    file = open(import_filename)
    data = json.load(file)
    cred_stuffing_accounts = []
    for i in data:
        cred_stuffing_accounts.append(i)
    file.close()
    print(f"{len(cred_stuffing_accounts)} DeHashed result(s) imported from local file")
    return cred_stuffing_accounts


def process_hashes(hash_filename):
    with open(hash_filename) as file:
        lines = []
        for line in file:
            lines.append(line.rstrip('\n'))

    nt_hashes = []
    for line in lines:
        if ":::" in line and "31d6cfe0d16ae931b73c59d7e0c089c0" not in line:
            line = line.rstrip(":::")
            line = line.split(":")[-1]
            nt_hashes.append(line)

    return nt_hashes


def parse_local_hashes(user_database, local_hash_filename):
    local_hashes = process_hashes(local_hash_filename)

    for user in user_database:
        for comparison_hash in local_hashes:
            if comparison_hash == user.nthash:
                user.local_pass_repeat += 1
    return user_database


def count_local_hash(user_database):
    local_hash_count = 0
    for user in user_database:
        if user.local_pass_repeat > 0:
            local_hash_count += 1
    return local_hash_count


if __name__ == '__main__':
    main()
