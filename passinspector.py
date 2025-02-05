#!/usr/bin/env python
import argparse
import binascii
import datetime
import json
from neo4j import GraphDatabase
import os
import re
import sys
import xlsxwriter
from tqdm import tqdm

"""This script is created to parse through cracked passwords to find weak patterns that can be added to the report."""

NEO4J_PASSWORD = "bloodhoundcommunityedition"
NEO4J_QUERIES = {
    "admins": "MATCH (u:User)-[:MemberOf]->(g:Group) WHERE toUpper(g.name) CONTAINS 'DOMAIN ADMINS' OR "
              "g.name CONTAINS 'ENTERPRISE ADMINS' OR g.name STARTS WITH 'ADMINISTRATORS@' RETURN "
              "DISTINCT toLower(u.domain) + '\\\\' + toLower(u.samaccountname) AS user",
    "enabled": "MATCH (u:User) WHERE u.enabled=true RETURN tolower(u.domain) + '\\\\' + "
               "tolower(u.samaccountname) AS user",
    "kerberoastable": "MATCH (u:User)WHERE u.hasspn=true RETURN tolower(u.domain) + '\\\\' + "
                      "tolower(u.samaccountname) AS user"}
NEO4J_URI = f"neo4j://localhost"
NEO4J_USERNAME = "neo4j"

class User:
    def __init__(self, domain, username, lmhash, nthash, password, cracked, has_lm,
                 blank_password, enabled, is_admin, kerberoastable, student, local_pass_repeat, pass_repeat, email, spray_user, spray_password):
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
        self.spray_user = spray_user
        self.spray_password = spray_password



def central_station(search_terms, admin_users, enabled_users, dcsync_filename, passwords_filename, students_filename,
                    spray_users_filename, spray_passwords_filename, cred_stuffing_filename, cred_stuffing_domains,
                    kerberoastable_users, duplicate_password_identifier, file_datetime, local_hash_filename, search_dehashed):
    # Designed to figure out what actions will need to take place depending on the file types provided
    file_datetime, dcsync_filename, passwords_filename = get_filenames(file_datetime, dcsync_filename, passwords_filename)
    dcsync_results = []  # All results and values
    user_database_cracked = []  # Values for any cracked user credential

    dcsync_file_lines = open_file(dcsync_filename)
    dcsync_file_lines, cleartext_creds = filter_dcsync_file(dcsync_file_lines)

    password_file_lines = open_file(passwords_filename)
    password_file_lines = deduplicate_passwords(password_file_lines)

    cred_stuffing_accounts = get_cred_stuffing(cred_stuffing_filename, cred_stuffing_domains, search_dehashed)

    # Take users from a file, otherwise query neo4j if info was provided, otherwise just assign a blank value
    admin_users = group_lookup("admins", admin_users)
    enabled_users = group_lookup("enabled", enabled_users)
    kerberoastable_users = group_lookup("kerberoastable", kerberoastable_users)

    # Check on the domains that were found to make sure they match
    dcsync_file_lines, admin_users, enabled_users, kerberoastable_users = check_domains(dcsync_file_lines, admin_users,
                                                                                        enabled_users,
                                                                                        kerberoastable_users)

    # Create a list of User (see User class) objects
    user_database = create_user_database(dcsync_file_lines, cleartext_creds, admin_users, enabled_users,
                                         kerberoastable_users, password_file_lines)

    user_database = fix_bad_passwords(user_database)
    if cleartext_creds:
        user_database = add_cleartext_creds(user_database, cleartext_creds)
    if students_filename:
        user_database = parse_students(user_database, students_filename)
    if local_hash_filename:
        user_database = parse_local_hashes(user_database, local_hash_filename)

    for user in user_database:
        if user.cracked:
            user_database_cracked.append(user)

    print("Calculating statistics")
    # Create a progress bar with eight steps
    pbar = tqdm(total=8, desc="Calculating statistics", ncols=100)
    # Step 1: Calculate password lengths for enabled and all users
    stat_enabled_shortest, stat_enabled_longest, result_enabled_shortest_passwords, result_enabled_longest_passwords, \
        stat_all_shortest, stat_all_longest, result_all_shortest_passwords, result_all_longest_passwords = \
        calculate_password_long_short(user_database)
    pbar.update(1)
    # Step 2: Perform password search on cracked users
    (text_blank_passwords, text_terms, text_seasons, text_keyboard_walks, text_custom_search, result_blank_passwords,
     result_common_terms, result_seasons, result_keyboard_walks, result_custom_search) = \
        perform_password_search(user_database_cracked, search_terms)
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
    text_cred_stuffing, result_cred_stuffing = cred_stuffing_check(cred_stuffing_accounts, dcsync_results)
    pbar.update(1)
    # Step 8: Check for spray matches
    user_database, num_spray_matches, num_pass_spray_matches = check_if_spray(user_database, spray_users_filename,
                                                                              spray_passwords_filename)
    pbar.update(1)
    pbar.close()
    # Step 9: Check for password reuse (this takes a while compared to the others, so it gets its own loading bar)
    user_database = count_pass_repeat(user_database)
    if duplicate_password_identifier:
        user_database = calc_duplicate_password_identifier(user_database)

    printed_stats = show_results(stat_enabled_shortest, stat_enabled_longest, stat_all_shortest, stat_all_longest, text_blank_passwords, text_terms, text_seasons, text_keyboard_walks,
                 text_custom_search, text_username_passwords, text_admin_pass_reuse, text_lm_hashes, text_cred_stuffing, num_spray_matches,
                 num_pass_spray_matches, user_database)

    print("Writing out files")
    write_cracked_file(printed_stats, file_datetime, user_database, result_enabled_shortest_passwords, result_enabled_longest_passwords, result_all_shortest_passwords, result_all_longest_passwords,
                       result_blank_passwords, result_common_terms, result_seasons, result_keyboard_walks,
                       result_custom_search, result_username_passwords, results_admin_pass_reuse, result_lm_hash_users, result_blank_enabled, result_cred_stuffing)
    write_xlsx(file_datetime, user_database)
    print("Done!")


def print_and_log(message, log):
    print(message)
    log = message + "\n"
    return log


def group_lookup(query, group_filename):
    if group_filename:
        group = file_to_userlist(group_filename)
    elif NEO4J_PASSWORD:
        group = neo4j_query(NEO4J_QUERIES[query])
    else:
        group = []

    return group


def fix_bad_passwords(user_database):
    for user in user_database:
        if '$HEX[' in user.password:
            try:
                user.password = dehexify(user.password)
            except Exception as e:
                print(f"Failed to dehexify password for {user.username} with password {user.password}: {e}")

    return user_database


def open_file(l_filename):
    print(f"Opening {l_filename}")
    lines = []
    try:
        with open(l_filename, 'r') as file:
            for line in file:
                if line:
                    lines.append(line.strip())
    except FileNotFoundError:
        print(f"ERROR: Could not find file using the filename provided: {l_filename}")
        exit(1)
    return lines


def check_if_spray(user_database, spray_users_filename, spray_passwords_filename):
    num_spray_matches = 0
    num_pass_spray_matches = 0
    neo4j_connectivity = testNeo4jConnectivity()

    # Return default values if no spray files are provided and Neo4j is unavailable
    if not spray_users_filename and not spray_passwords_filename and not neo4j_connectivity:
        print("No input files provided, and Neo4j connectivity is unavailable. Exiting.")
        return user_database, 123456, 123456  # Tells the printing function not to print these stats

    # Step 1: Fetch emails from Neo4j if Neo4j connectivity is available
    if neo4j_connectivity:
        print("Fetching emails from Neo4j...")
        user_database = emails_from_neo4j(user_database)

    # Step 2: Import data from external spray users file if provided
    spray_users = []
    if spray_users_filename:
        spray_users = file_to_userlist(spray_users_filename)
        if DEBUG_MODE:
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

    if DEBUG_MODE:
        print("DEBUG: Externally found users")
        print([vars(user) for user in externally_found_users])

    # Step 4: Check passwords from spray file if provided
    if spray_passwords_filename:
        print("Checking passwords from spray file...")
        with open(spray_passwords_filename, 'r') as passwords_file:
            spray_passwords = [password.strip().lower() for password in passwords_file]
            if DEBUG_MODE:
                print("DEBUG: Provided spray passwords")
                print(spray_passwords)

        for user in user_database:
            if user.spray_user and user.password and user.password.lower() in spray_passwords:
                user.spray_password = True
            else:
                user.spray_password = False

    # Step 5: Calculate stats
    if spray_passwords_filename:
        for user in externally_found_users:
            if user.spray_password and user.enabled:
                num_spray_matches += 1
            if user.spray_password and user.enabled:
                num_pass_spray_matches += 1
    else:
        print("No spray password file supplied. Cannot calculate stats.")

    return user_database, num_spray_matches, num_pass_spray_matches



def write_xlsx(file_date, user_database):
    out_filename = f"passinspector_results_{file_date}.xlsx"
    print(f"Writing results in Excel format to {out_filename}")
    # Create Workbook
    workbook = xlsxwriter.Workbook(out_filename)
    worksheet = workbook.add_worksheet()
    cell_format = workbook.add_format()
    cell_format.set_align('top')
    cell_format.set_align('left')
    # cell_format.set_font_name('Barlow')  # If we pasted data into the report, this would help.
    cell_format.set_font_size('10')
    header_format = workbook.add_format()
    header_format.set_align('top')
    header_format.set_align('left')
    header_format.set_font_name('Barlow')
    header_format.set_font_size('11')
    header_format.set_bg_color('#D9D9D9')

    # Define headers
    headers = [
        'DOMAIN', 'USERNAME', 'LMHASH', 'NTHASH', 'PASSWORD', 'CRACKED', 'HAS_LM',
        'BLANK_PASSWORD', 'ENABLED', 'IS_ADMIN', 'KERBEROASTABLE', 'STUDENT',
        'LOCAL_PASS_REPEAT', 'PASS_REPEAT_COUNT', 'SPRAY_USER', 'SPRAY_PASSWORD'
    ]
    worksheet.freeze_panes(1, 0)  # Freeze the top row

    # Write headers to the first row
    for col_count, header in enumerate(headers):
        worksheet.write(0, col_count, header, header_format)

    # Prepare the data for writing and track column widths
    column_widths = [len(header) for header in headers]
    data = []
    hide_columns = {'LMHASH', 'NTHASH'}  # Columns to hide initially
    conditional_hide_columns = {'ENABLED', 'IS_ADMIN', 'KERBEROASTABLE', 'STUDENT', 'LOCAL_PASS_REPEAT', 'SPRAY_USER', 'SPRAY_PASSWORD'}
    conditional_false_counts = {key: 0 for key in conditional_hide_columns}
    total_rows = len(user_database)

    for user in user_database:
        values = [
            user.domain,
            user.username,
            user.lmhash,
            user.nthash,
            user.password if user.password else "",
            "True" if user.cracked else "False",
            "True" if user.has_lm else "False",
            "True" if user.blank_password else "False",
            "True" if user.enabled else "False",
            "True" if user.is_admin else "False",
            "True" if user.kerberoastable else "False",
            "True" if user.student else "False",
            user.local_pass_repeat,
            user.pass_repeat,
            user.spray_user,
            user.spray_password
        ]
        data.append(values)

        # Update column widths and count "False" values for conditional columns
        for col_index, value in enumerate(values):
            column_widths[col_index] = max(column_widths[col_index], len(str(value)))
            if headers[col_index] in conditional_hide_columns and value == "False":
                conditional_false_counts[headers[col_index]] += 1

    # Write data rows
    for row_index, row in enumerate(data, start=1):
        for col_index, value in enumerate(row):
            worksheet.write(row_index, col_index, value, cell_format)

    # Adjust column widths
    for col_index, width in enumerate(column_widths):
        worksheet.set_column(col_index, col_index, width)

    # Hide specified columns
    for col_index, header in enumerate(headers):
        if header in hide_columns or (header in conditional_hide_columns and conditional_false_counts[header] == total_rows):
            worksheet.set_column(col_index, col_index, None, None, {'hidden': True})

    worksheet.autofilter(0, 0, len(user_database), len(headers) - 1)  # Allow the headers to be filtered
    workbook.close()



def read_json_file(file_path):
    try:
        with open(file_path, 'r', encoding="UTF-8") as file:
            json_data = json.load(file)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON in file '{file_path}'.")
        return None

    formatted_usernames = []
    for username in json_data['data']['nodes'].values():
        username_parts = username["label"].split('@')
        if len(username_parts) == 2:
            domain = username_parts[1]
            username = username_parts[0]
            formatted_usernames.append({"USERNAME": username, "DOMAIN": domain})
        else:
            formatted_usernames.append({"USERNAME": username_parts[0]})

    return formatted_usernames


def check_if_kerberoastable(user, domain, krb_users):
    for user_to_check in krb_users:
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


def check_domains(dcsync_file_lines, admin_users, enabled_users, kerberoastable_users):
    dcsync_domains = set()  # Domain(s) from the DCSync
    imported_domains = set()  # Domain(s) from Neo4j or provided files for admin and enabled users
    unique_domains_imported = set()
    unique_domains_dcsync = set()

    # Skip this if no admin/enabled/kerberoastable user files or Neo4j creds were provided
    if not admin_users and not enabled_users and not kerberoastable_users:
        return dcsync_file_lines, admin_users, enabled_users, kerberoastable_users

    # ------------------------------------------------------------
    # Phase 1: Extract domains from DCSync file lines
    # ------------------------------------------------------------
    for line in tqdm(dcsync_file_lines, desc="Extracting domains from DCSync", ncols=80):
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
    for user in tqdm(admin_users, desc="Processing admin users", ncols=80):
        imported_domains.add(user['DOMAIN'].lower())
    for user in tqdm(enabled_users, desc="Processing enabled users", ncols=80):
        imported_domains.add(user['DOMAIN'].lower())
    for user in tqdm(kerberoastable_users, desc="Processing kerberoastable users", ncols=80):
        imported_domains.add(user['DOMAIN'].lower())

    if DEBUG_MODE:
        print(f"DEBUG: imported_domains {imported_domains}")
        print(f"DEBUG: dcsync_domains {dcsync_domains}")

    # ------------------------------------------------------------
    # Phase 3: Compare domains to find uniques
    # ------------------------------------------------------------
    for domain in tqdm(imported_domains, desc="Comparing imported domains", ncols=80):
        if domain not in dcsync_domains:
            unique_domains_imported.add(domain)
    for domain in tqdm(dcsync_domains, desc="Comparing DCSync domains", ncols=80):
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
                admin_users, enabled_users, kerberoastable_users = replace_imported_domain(
                    old_domain, new_domain, admin_users, enabled_users, kerberoastable_users)
            else:
                print(f"No changes made for domain {unique_domain}")

    # ------------------------------------------------------------
    # Phase 5: Resolve unique domains from the DCSync file
    # ------------------------------------------------------------
    if unique_domains_dcsync:
        neo4j_status = testNeo4jConnectivity()

        for unique_domain in tqdm(unique_domains_dcsync, desc="Resolving unique DCSync domains", ncols=80):
            no_match_text = "imported data"
            new_domain = ""
            if neo4j_status:
                # Attempt to fix automatically using Neo4j data if possible
                new_domain = domain_change_auto(unique_domain, dcsync_file_lines)

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

    return dcsync_file_lines, admin_users, enabled_users, kerberoastable_users


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

def domain_change_auto(old_domain, dcsync_file_lines):
    # This function checks all users matching a unique domain to see if they appear in Neo4j
    # a single time. If so, it will auto "fix" them. Otherwise, it'll skip on to allow a
    # manual adjustment to be made

    # Step 1: Extract all usernames for the unique domain
    usernames = []
    for line in dcsync_file_lines:
        if "\\" in line:
            domain, rest = line.split("\\", 1)  # Split at the first occurrence of '\'
            if domain.lower() == old_domain.lower():
                username = rest.split(":", 1)[0]  # Extract the username before the first ':'
                usernames.append(username)
    if DEBUG_MODE:
        print(f"Found the following users for the {old_domain} domain:")
        print(usernames)

    if not usernames:
        print(f"No usernames found for the domain '{old_domain}' in the DCSync file. Something must have gone wrong.")
        return ""

    # Step 2: Search Neo4j for each username and collect associated domains
    resolved_domains = set()
    for username in usernames:
        query_string = f"MATCH (u:User) WHERE u.name contains toUpper('{username}') RETURN DISTINCT toLower(u.domain) + '\\\\' + toLower(u.samaccountname) AS user"
        results = neo4j_query(query_string)

        for result in results:
            resolved_domains.add(result['DOMAIN'].lower())
            if DEBUG_MODE:
                print(f"User {username} found in Neo4j with domain of {result['DOMAIN'].lower()}")

    # Step 3: Determine if all results point to the same domain
    if DEBUG_MODE:
        print(f"When searching DCSync users with {old_domain} domain, the following domains were found: {resolved_domains}")
    if len(resolved_domains) == 1:
        # If there was just one domain returned, it successfully figured out the matching domain automatically
        resolved_domain = resolved_domains.pop()
        return resolved_domain
    elif len(resolved_domains) == 0:
        print(f"No matching domains found in Neo4j for users under '{old_domain}'.")
        return ""
    else:
        print(f"Failed to automatically resolve domain '{old_domain}'")
        return ""

def replace_dcsync_domain(old_domain, new_domain, dcsync_file_lines):
    print(f"Updating {old_domain} domain in DCSync to {new_domain}")

    for i in range(len(dcsync_file_lines)):
        if "\\" in dcsync_file_lines[i]:
            domain, rest = dcsync_file_lines[i].split("\\", 1)  # Split only at the first occurrence of '\'
            if domain.lower() == old_domain.lower():  # Case-insensitive comparison
                dcsync_file_lines[i] = f"{new_domain}\\{rest}"

    return dcsync_file_lines


def create_user_database(dcsync_file_lines, cleartext_creds, admin_users, enabled_users, kerberoastable_users, password_file_lines):
    user_database = []
    skipped_lines = []

    # Wrap the iteration over the DCSync file lines with a tqdm progress bar
    for line in tqdm(dcsync_file_lines, desc="Importing users"):
        # Split the line into its components (assuming the format: DOMAIN\USERNAME:RID:LMHASH:NTHASH:::)
        try:
            domain_user, rid, lmhash, nthash, *_ = line.split(':')  # Extract and discard RID
            domain, username = domain_user.split('\\')
        except ValueError:
            # Handle improperly formatted lines
            skipped_lines.append(f"Skipping processing for invalid line in dcsync. Likely no domain or other format issue: {line}")
            continue

        # Determine derived attributes
        has_lm = lmhash != "aad3b435b51404eeaad3b435b51404ee"  # Default empty LM hash
        blank_password = nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"  # Default NT hash for blank password
        password, cracked = check_if_cracked(nthash, password_file_lines)
        enabled = check_if_enabled(username, domain, enabled_users)
        is_admin = check_if_admin(username, domain, admin_users)
        kerberoastable = check_if_kerberoastable(username, domain, kerberoastable_users)
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
                enabled=enabled,
                is_admin=is_admin,
                kerberoastable=kerberoastable,
                student=student,
                local_pass_repeat=local_pass_repeat,
                pass_repeat=pass_repeat,
                email=None,
                spray_user=False,
                spray_password=False
            )
        )

    if skipped_lines:
        for skipped in skipped_lines:
            print(skipped)

    return user_database


def deduplicate_passwords(password_file_lines):
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


def check_if_enabled(user, domain, enabled_users):
    for user_to_compare in enabled_users:
        if domain:
            # If a domain was supplied, use it when comparing
            if ((user.lower() == user_to_compare['USERNAME'].lower()) and (
                    domain.lower() == user_to_compare['DOMAIN'].lower())):
                return True
        else:
            # If the domain is blank, just compare usernames
            if user.lower() == user_to_compare['USERNAME'].lower():
                return True
    return False


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
    enabled_shortest, enabled_longest, enabled_shortest_passwords, enabled_longest_passwords = find_password_lengths(enabled_users)

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
        stats["blank_passwords"] = f"There were {counts['blank_passwords']} account(s) found with blank passwords. {enabled_counts['blank_passwords']} of these belonged to enabled users."

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
    counts["keyboard_walks"], leet_text, result_keyboard_walks = inner_search(common_keyboard_walks, user_database_cracked)
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
        text_results = (f"There were {len(cred_stuffing_matches)} valid credential stuffing password(s) found to be valid. "
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


def show_results(stat_enabled_shortest, stat_enabled_longest, stat_all_shortest, stat_all_longest, text_blank_passwords, text_terms, text_seasons, text_keyboard_walks,
                 text_custom_search, text_username_passwords, text_admin_pass_reuse, text_lm_hashes, text_cred_stuffing, stat_spray_matches,
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
    results_text += print_and_log(f"Unique passwords cracked: {stat_cracked_uniq}/{stat_total_uniq} {uniq_cracked_percent}", results_text)
    results_text += print_and_log(f"Total accounts cracked: {all_cracked}/{all_total} {all_crack_percent}", results_text)
    results_text += print_and_log(f"Enabled employee accounts cracked: {enabled_cracked}/{enabled_total} {enabled_crack_percent}", results_text)
    if student_cracked:
        results_text += print_and_log(f"Total employee accounts cracked: {employee_cracked}/{employee_total} {employee_crack_percent}",
                      results_text)
        results_text += print_and_log(f"Student accounts cracked: {student_cracked}/{student_total} {student_crack_percent}",
                      results_text)
    if da_total > 0:
        results_text += print_and_log(f"DA accounts cracked: {da_cracked}/{da_total} ({((da_cracked / da_total) * 100):.2f}%)", results_text)
    results_text += print_and_log(f"Average employee password length: {avg_pass_len}", results_text)
    results_text += print_and_log(f"Average enabled employee password length: {enabled_avg_pass_len}", results_text)
    if student_avg_pass_len:
        results_text += print_and_log(f"Student average password length: {student_avg_pass_len}", results_text)
    results_text += print_and_log(f"Shortest password length (not counting blank passwords): {stat_all_shortest}", results_text)
    results_text += print_and_log(f"Shortest password length for an enabled account (not counting blank passwords): {stat_enabled_shortest}",
                                  results_text)
    results_text += print_and_log(f"Longest password length: {stat_all_longest}", results_text)
    results_text += print_and_log(f"Longest password length for an enabled account: {stat_enabled_longest}", results_text)
    results_text += print_and_log(text_blank_passwords, results_text) if text_blank_passwords else ""
    local_pass_repeated = count_local_hash(user_database)
    if local_pass_repeated > 0:
        results_text += print_and_log(f"There {'were' if local_pass_repeated > 1 else 'was'} "
                                      f"{local_pass_repeated} account{'s' if local_pass_repeated > 1 else ''} found "
                                      f"with a password hash matching a local account.", results_text)
    results_text += print_and_log(text_terms, results_text) if text_terms else ""
    results_text += print_and_log(text_seasons, results_text) if text_seasons else ""
    results_text += print_and_log(text_keyboard_walks, results_text) if text_keyboard_walks else ""
    results_text += print_and_log(text_custom_search, results_text) if text_custom_search else ""
    results_text += print_and_log(text_username_passwords, results_text) if text_username_passwords else ""
    results_text += print_and_log(text_admin_pass_reuse, results_text) if text_admin_pass_reuse else ""
    results_text += print_and_log(text_lm_hashes, results_text) if text_lm_hashes else ""
    results_text += print_and_log(text_cred_stuffing, results_text) if text_cred_stuffing else ""
    if stat_spray_matches != 123456:
        print_and_log(f"Number of Spray Matches (Enabled Username + Password): {stat_spray_matches}", results_text)
    if stat_spray_pass_matches != 123456:
        print_and_log(f"Number Enabled Accounts with Sprayable Passwords: {stat_spray_pass_matches}", results_text)
    print("")
    print("")
    print("")

    return results_text


def write_cracked_file(printed_stats, file_datetime, user_database, result_enabled_shortest_passwords, result_enabled_longest_passwords, result_all_shortest_passwords, result_all_longest_passwords,
                       result_blank_passwords, result_common_terms, result_seasons, result_keyboard_walks,
                       result_custom_search, result_username_passwords, results_admin_pass_reuse, result_lm_hash_users, result_blank_enabled, result_cred_stuffing):
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


def file_to_userlist(filename=None):
    if not filename:
        return []
    filename = filename.strip().lower()
    if filename.endswith('.json'):  # Handle Bloodhound CE JSON exports
        users = read_json_file(filename)
    elif filename.endswith('.txt'):
        users = []
        with open(filename, 'r') as file:
            for line in file:
                line = line.rstrip('\n')
                if '@' in line:
                    parts = line.split('@')
                    users.append({'USERNAME': parts[0], 'DOMAIN': parts[1]})
                elif '\\' in line:
                    parts = line.split('\\')
                    users.append({'USERNAME': parts[1], 'DOMAIN': parts[0]})
                elif '/' in line:
                    parts = line.split('/')
                    users.append({'USERNAME': parts[1], 'DOMAIN': parts[0]})
                else:
                    # Handle lines with only the username and no domain
                    users.append({'USERNAME': line, 'DOMAIN': None})
    elif filename.endswith('.csv'):  # Handle Neo4J CSV Exports:
        users = []
        with open(filename, 'r', encoding='utf-8') as file:
            lines = file.readlines()[1:]  # Read all lines and skip the first one
            for line in lines:
                line = line.rstrip('\n')
                line = line.replace('"', '')

                if "@" in line:
                    line = line.split("@")
                    users.append({'USERNAME': line[0], 'DOMAIN': line[1]})
                elif "," in line:
                    line = line.split(",")
                    users.append({'USERNAME': line[0], 'DOMAIN': line[1]})
                else:
                    users.append({'USERNAME': line, 'DOMAIN': None})
    else:
        print("ERROR: Do not recognize file extension: ", filename)
        return []

    return users



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
    for user in tqdm(user_database, desc="Counting password repeats (May take a while)", ncols=80, file=sys.stdout):
        pass_repeat_count = sum(1 for other_user in user_database if user.nthash == other_user.nthash)
        user.pass_repeat = pass_repeat_count
    return user_database


def prepare_hashes(l_dcsync_filename, l_file_prefix):
    if not l_file_prefix:
        l_file_prefix = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    machine_count = 0
    ntlm_hashes = []

    dcsync_lines = open_file(l_dcsync_filename)
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
        filename = f"{l_file_prefix}-NT_Hashes.txt"
        with open(filename, 'w') as file:
            for nt_hash in just_nt_hashes:
                file.write(nt_hash + "\n")
        print(f"\nUnique NT Hashes Written To: {filename}")

    exit()


def parse_students(user_database, students_filename):
    print("Parsing students")
    students = file_to_userlist(students_filename)
    for user in user_database:
        for student in students:
            if user.username.lower() == student['USERNAME'].lower():
                user.student = True
                break
    return user_database


def neo4j_query(query_string):
    try:
        with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD)) as driver:
            session = driver.session()
            results = session.run(query_string)
            users = []
            for result in results:
                # Results should be returned in the format of domain\username, which needs parsed
                match = re.search(r"'([^\\]+)\\\\([^']+)'", str(result))
                if match:
                    domain = match.group(1)
                    username = match.group(2)
                    users.append({'USERNAME': username, 'DOMAIN': domain})
            return users
    except Exception as e:
        print(f"ERROR: Neo4j query failed, unable to pull users - {e}")
        return []

def emails_from_neo4j(user_database):
    try:
        with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD)) as driver:
            with driver.session() as session:  # Open a single session for the entire operation
                for user in user_database:
                    if user.domain:  # If domain is provided, include it in the query
                        query = (
                            "MATCH (u:User) "
                            "WHERE toUpper(u.samaccountname) = $username "
                            "AND toUpper(u.domain) = $domain "
                            "RETURN u.email"
                        )
                        parameters = {
                            "username": user.username.upper(),
                            "domain": user.domain.upper()
                        }
                    else:  # If no domain, search by username only
                        query = (
                            "MATCH (u:User) "
                            "WHERE toUpper(u.samaccountname) = $username "
                            "RETURN u.email"
                        )
                        parameters = {
                            "username": user.username.upper()
                        }

                    result = session.run(query, parameters)
                    email = None
                    for record in result:
                        email = record["u.email"]
                        break  # Retrieve the first email match and exit the loop
                    user.email = email if email else None  # Assign email or None if not found
            return user_database
    except Exception as e:
        print(f"ERROR: Neo4j query failed, unable to pull user emails - {e}")
        return user_database




def testNeo4jConnectivity():
    try:
        with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD)) as driver:
            driver.verify_connectivity()
            print("Successfully connected to Neo4j database")
            return True
    except Exception as e:
        print("ERROR: Could not connect to Neo4j. If Neo4j information was provided, please check it is accurate.")
        print(e)
        return False


def retrieve_cred_stuffing_results(cred_stuffing_domains):
    # Checks to see if BreachCreds.py is available, and if so, it will search DeHashed for credential stuffing accounts
    try:
        import BreachCreds
    except ImportError:
        print("Unable to find BreachCreds.py in the current directory, skipping credential stuffing checks")
        return []

    cred_stuffing_accounts = []
    if cred_stuffing_domains:
        # If a credential-stuffing domain was specified, use that
        print("Searching DeHashed for credential stuffing results (This may take some time)")
        dehashed_results = BreachCreds.main(cred_stuffing_domains.split(','), display=False, write_files=False)
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
    elif NEO4J_PASSWORD:
        # If a Neo4j password was specified, use that
        try:
            with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD)) as driver:
                session = driver.session()
                results = session.run("MATCH (u:User) WHERE u.email IS NOT NULL RETURN distinct(split(u.email, '@')[1]) as DOMAIN")
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
            #dehashed_results = [{'Username': 'user1@example.com'},{'Username': 'user2@example.com', 'Password': 'Password123'},{'Username': 'user3@example.com'},{'Username': 'user4@example.com', 'Password': 'Password456'}]
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


def get_cred_stuffing(cred_stuffing_filename, cred_stuffing_domains, search_dehashed):
    if cred_stuffing_filename:
        cred_stuffing_accounts = open_file(cred_stuffing_filename)
    elif os.path.isfile("passinspector_dehashed_results.txt"):
        cred_stuffing_accounts = import_dehashed_file()
    elif (cred_stuffing_domains or NEO4J_PASSWORD) and search_dehashed:
        # If a credential_stuffing domain is provided, search with DeHashed
        # If a password for Neo4j was provided, it will try to pull the email domain from AD
        # MATCH (u:User) WHERE u.email IS NOT NULL RETURN distinct(split(u.email, '@')[1]) as DOMAIN
        cred_stuffing_accounts = retrieve_cred_stuffing_results(cred_stuffing_domains)
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


def find_file(include=None, exclude=None):
    # include and exclude should be lists

    if not include:
        include = []
    if not exclude:
        exclude = []

    file_list = list_files_recursive()
    for file_name in file_list:
        complete_match = len(include)
        for arg in include:
            if arg.lower() in file_name.lower():
                complete_match -= 1
        for arg in exclude:
            if arg.lower() in file_name.lower():
                complete_match += 1
        if complete_match == 0:
            return file_name


def get_filenames(file_datetime, dcsync_filename, passwords_filename):
    if not file_datetime:
        file_datetime = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if not dcsync_filename:
        dcsync_filename = find_file([file_datetime, "dcsync"])
        if dcsync_filename:
            print(f"No DCSync file was provided, but a DCSync file was found: {dcsync_filename}")
        else:
            print("ERROR: No DCSync file provided or located automatically. Cannot continue!")
            exit()
    if not passwords_filename:
        passwords_filename = find_file([file_datetime, "cracked"], ['allcracked'])
        if passwords_filename:
            print(f"No cracked file was provided, but a cracked file was found: {passwords_filename}")
        else:
            print("ERROR: No cracked file file provided or located automatically. Cannot continue!")
            exit()

    return file_datetime, dcsync_filename, passwords_filename


def list_files_recursive(directory='.'):
    import os
    files_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            files_list.append(os.path.join(root, file))
    return files_list


if __name__ == '__main__':
    script_version = 2.5
    print("\n==============================")
    print("PassInspector  -  Version", script_version)
    print("==============================\n")

    # Create an argument parser
    parser = argparse.ArgumentParser(
        description='This script is built to search through DCSync results to help highlight weak password patterns')

    # Add the optional -a flag for a list of administrative users
    parser.add_argument('-a', '--admins', help='(OPTIONAL) A file containing a list of domain '
                                               'administrative users. The script will check if the passwords for these '
                                               'users are used on other accounts by using hashes. The format should be '
                                               'DOMAIN\\USERNAME or USERNAME. BloodHound JSON files are also accepted.'
                                               'DOMAIN\\USERNAME or USERNAME. BloodHound JSON files are also accepted. '
                                               'Overrides automatic Neo4j queries.')

    # Add the optional -c flag for comma-separated custom passwords to search for
    parser.add_argument('-c', '--custom', help='(OPTIONAL) Comma-separated terms you would like searched '
                                               'for, such as the organization\'s name or acronym in lowercase')

    # Add the optional -cs flag for colon-separated credential stuffing file to override or replace BreachCreds results
    parser.add_argument('-cs', '--cred-stuffing', help='(OPTIONAL) Only required if BreachCreds.py is not '
                                                'in the same directory. Colon-separated file containing '
                                                'credential stuffing accounts in the format of email:password')

    # Add the optional -csd flag for specifying the domain to search DeHashed with if DeHashed is in the same directory
    parser.add_argument('-csd', '--cred-stuffing-domains', help='(OPTIONAL) If BreachCreds.py is in the same '
                                               'directory, these comma-separated domains will be used to search DeHashed '
                                               'for credential stuffing credentials')

    # Add the -d flag for the DCSync file
    parser.add_argument('-d', '--dcsync', help='(OPTIONAL) A file containing the output of a DCSync in the '
                                               'format of DOMAIN\\USER:RID:LMHASH:NTHASH:::')

    parser.add_argument('-db', '--debug', help='(OPTIONAL) Turn on debug messages', action='store_true')

    parser.add_argument('-dpi', '--duplicate-password-identifier', action="store_true",
                        help='(OPTIONAL) Add a unique identifier for each password, so the customer can identify'
                             'password reuse without needing the passwords.')

    # Add the optional -e flag for a file containing enabled users
    parser.add_argument('-e', '--enabled', help='(OPTIONAL) A file containing a list of enabled domain '
                                                'users. If specified, it will specify enabled users in the output. '
                                                'The format should be DOMAIN\\USERNAME or USERNAME. BloodHound JSON or '
                                                'NEO4J CSV files are also accepted. Overrides automatic Neo4j queries.')

    parser.add_argument('-fp', '--file-prefix', help='(OPTIONAL) File output prefix (if none is provided,'
                                                     'datetime will be used instead.')

    parser.add_argument('-k', '--kerberoastable-users', help='(OPTIONAL) A file containing all of the '
                                                             'Kerberoastable users. Overrides automatic Neo4j queries.')

    parser.add_argument('-lh', '--local-hashes', help='(OPTIONAL) A file containing LSASS dumps. The '
                                                      'script will determine if any of the domain accounts reuse local'
                                                      'account passwords.')

    parser.add_argument('-nd', '--no-dehashed', action='store_false', help='(OPTIONAL) Skip DeHashed search')

    parser.add_argument('-nh', '--neo4j-hostname', help='(OPTIONAL) Neo4j hostname or IP (Default: localhost)')

    parser.add_argument('-nu', '--neo4j-username', help='(OPTIONAL) Neo4j username for automatic queries '
                                                        '(Default: neo4j)')

    parser.add_argument('-np', '--neo4j-password', help='(OPTIONAL) Neo4j password for automatic queries. '
                                                        'Must be specified for automatic queries to be attempted')

    # Add the -p flag for a file containing cracked passwords
    parser.add_argument('-p', '--passwords', help='(OPTIONAL) A file containing all of the cracked '
                                                  'passwords from Hashtopolis in the form of NTHASH:PASSWORD')

    parser.add_argument('-ph', '--prepare-hashes',
                        action="store_true",
                        help='(OPTIONAL) Prepare hashes for cracking on Hashtopolis. A list of unique NT hashes will be'
                             ' output, with any accounts that have a cleartext password removed.')

    parser.add_argument('-s', '--students', help='(OPTIONAL) A file containing a list of students or any '
                                                 'other list of users. If specified, it will specify enabled users in '
                                                 'the output. The format should be DOMAIN\\USERNAME or USERNAME. '
                                                 'BloodHound JSON files are also accepted.')

    parser.add_argument('-sp', '--spray-passwords', help='(OPTIONAL) Match cracked passwords to passwords '
                                                         'in the spray list.')

    parser.add_argument('-su', '--spray-users', help='(OPTIONAL) Match cracked users to list of usernames '
                                                     'that will be sprayed.')

    # Parse the command-line arguments
    args = parser.parse_args()

    # Handle situation where no arguments were provided.
    if not args.file_prefix and not args.dcsync or not args.file_prefix and not args.passwords:
        file_prefix = input('No arguments provided for DCSync or cracked password file. '
                            'What is the file prefix for these files? ')
        file_prefix = file_prefix.strip()
    else:
        file_prefix = args.file_prefix

    # Access the values of the arguments
    dcsync_filename = args.dcsync
    passwords_filename = args.passwords
    spray_users_filename = args.spray_users
    spray_passwords_filename = args.spray_passwords
    duplicate_password_identifier = args.duplicate_password_identifier

    search_dehashed = args.no_dehashed

    DEBUG_MODE = args.debug

    # Parse Neo4j arguments if provided
    if args.neo4j_hostname:
        NEO4J_URI = f"neo4j://{args.neo4j_hostname}"
    if args.neo4j_username:
        NEO4J_USERNAME = args.neo4j_username
    if args.neo4j_username:
        NEO4J_PASSWORD = args.neo4j_password

    # Test Neo4j connectivity, and if it fails, set the password to blank so the script doesn't try to connect later
    if not testNeo4jConnectivity():
        NEO4J_PASSWORD = ""

    if args.custom:  # Only parse the custom passwords if they were provided
        search_terms = args.custom.split(',')
    else:
        search_terms = []

    if args.cred_stuffing_domains:
        cred_stuffing_domains = args.cred_stuffing_domains.split(',')
    else:
        cred_stuffing_domains = []

    if args.prepare_hashes:
        prepare_hashes(dcsync_filename, file_prefix)

    central_station(search_terms, args.admins, args.enabled, dcsync_filename, passwords_filename, args.students,
                    spray_users_filename, spray_passwords_filename, args.cred_stuffing, args.cred_stuffing_domains,
                    args.kerberoastable_users, duplicate_password_identifier, file_prefix, args.local_hashes, search_dehashed)
