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

"""This script is created to parse through cracked passwords to find weak patterns that can be added to the report."""

NEO4J_PASSWORD = "bloodhoundcommunityedition"
NEO4J_QUIRIES = {"admins": "MATCH (u:User)-[:MemberOf]->(g:Group) WHERE toUpper(g.name) CONTAINS 'DOMAIN ADMINS' OR "
                           "g.name CONTAINS 'ENTERPRISE ADMINS' OR g.name STARTS WITH 'ADMINISTRATORS@' RETURN "
                           "DISTINCT toLower(u.domain) + '\\\\' + toLower(u.samaccountname) AS user",
                 "enabled": "MATCH (u:User) WHERE u.enabled=true RETURN tolower(u.domain) + '\\\\' + "
                            "tolower(u.samaccountname) AS user",
                 "kerberoastable": "MATCH (u:User)WHERE u.hasspn=true RETURN tolower(u.domain) + '\\\\' + "
                                   "tolower(u.samaccountname) AS user"}
NEO4J_URI = f"neo4j://localhost"
NEO4J_USERNAME = "neo4j"


def central_station(search_terms, admin_users, enabled_users, dcsync_filename, passwords_filename, students_filename,
                    spray_users_filename, spray_passwords_filename, cred_stuffing_filename, cred_stuffing_domains,
                    kerberoastable_users, duplicate_password_identifier, file_datetime, local_hash_filename):
    # Designed to figure out what actions will need to take place depending on the file types provided
    file_datetime, dcsync_filename, passwords_filename = get_filenames(file_datetime, dcsync_filename, passwords_filename)
    dcsync_results = []  # All results and values
    dcsync_results_cracked = []  # Values for any cracked user credential

    dcsync_file_lines = open_file(dcsync_filename)
    dcsync_file_lines, cleartext_creds = filter_dcsync_file(dcsync_file_lines)

    password_file_lines = open_file(passwords_filename)
    password_file_lines = deduplicate_passwords(password_file_lines)

    cred_stuffing_accounts = get_cred_stuffing(cred_stuffing_filename, cred_stuffing_domains)

    # Take users from a file, otherwise query neo4j if info was provided, otherwise just assign a blank value
    admin_users = group_lookup("admins", admin_users)
    enabled_users = group_lookup("enabled", enabled_users)
    kerberoastable_users = group_lookup("kerberoastable", kerberoastable_users)

    # Check on the domains that were found to make sure they match
    dcsync_file_lines, admin_users, enabled_users, kerberoastable_users = check_domains(dcsync_file_lines, admin_users,
                                                                                        enabled_users,
                                                                                        kerberoastable_users)

    print("Parsing results")
    for line in dcsync_file_lines:
        result = parse_dcsync_line(line, password_file_lines, admin_users, enabled_users, kerberoastable_users)
        if result:
            dcsync_results.append(result)  # Add the DCSync line to the DCSync array

    dcsync_results = fix_bad_passwords(dcsync_results)
    dcsync_results = add_cleartext_creds(dcsync_results, cleartext_creds)
    dcsync_results = parse_students(dcsync_results, students_filename)
    dcsync_results = parse_local_hashes(dcsync_results, local_hash_filename)

    for record in dcsync_results:
        if record['CRACKED']:
            dcsync_results_cracked.append(record)

    print("Calculating statistics")
    stat_shortest, stat_longest, result_shortest_passwords, result_longest_passwords = calculate_password_long_short(
        dcsync_results)
    (text_blank_passwords, text_terms, text_seasons, text_keyboard_walks, text_custom_search, result_blank_passwords,
     result_common_terms, result_seasons, result_keyboard_walks, result_custom_search) = perform_password_search(
        dcsync_results_cracked, search_terms)
    text_username_passwords, result_username_passwords = username_password_search(dcsync_results_cracked)
    text_admin_pass_reuse, results_admin_pass_reuse = admin_password_inspection(dcsync_results, admin_users)
    text_lm_hashes, result_lm_hash_users = lm_hash_inspection(dcsync_results)
    text_blank_passwords, result_blank_enabled = blank_enabled_search(dcsync_results, text_blank_passwords) # Updates the blank password text with enabled account count
    text_cred_stuffing, result_cred_stuffing = cred_stuffing_check(cred_stuffing_accounts, dcsync_results)
    dcsync_results, num_spray_matches, num_pass_spray_matches = check_if_spray(dcsync_results, spray_users_filename,
                                                                               spray_passwords_filename)
    dcsync_results = count_pass_repeat(dcsync_results)
    if duplicate_password_identifier:
        dcsync_results = calc_duplicate_password_identifier(dcsync_results)

    printed_stats = show_results(stat_shortest, stat_longest, text_blank_passwords, text_terms, text_seasons, text_keyboard_walks,
                 text_custom_search, text_username_passwords, text_admin_pass_reuse, text_lm_hashes, text_cred_stuffing, num_spray_matches,
                 num_pass_spray_matches, dcsync_results)

    print("Writing out files")
    write_cracked_file(printed_stats, file_datetime, dcsync_results, result_shortest_passwords, result_longest_passwords,
                       result_blank_passwords, result_common_terms, result_seasons, result_keyboard_walks,
                       result_custom_search, result_username_passwords, results_admin_pass_reuse, result_lm_hash_users, result_blank_enabled, result_cred_stuffing)
    write_xlsx(file_datetime, dcsync_results)
    print("Done!")


def print_and_log(message, log):
    print(message)
    log = message + "\n"
    return log


def group_lookup(query, group_filename):
    if group_filename:
        group = file_to_userlist(group_filename)
    elif NEO4J_PASSWORD:
        group = neo4j_query(NEO4J_QUIRIES[query])
    else:
        group = []

    return group


def fix_bad_passwords(dcsync_results):
    i = 0
    while i < len(dcsync_results):
        if '$HEX[' in dcsync_results[i]["PASSWORD"]:
            dcsync_results[i]["password"] = dehexify(dcsync_results[i]["password"])

        i += 1

    return dcsync_results


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


def check_if_spray(l_dcsync_results, l_spray_users_filename, l_spray_passwords_filename):
    l_num_spray_matches = 0
    l_num_pass_spray_matches = 0

    # Return default values if no spray files have been provided
    if not l_spray_users_filename and not l_spray_passwords_filename:
        return l_dcsync_results, 123456, 123456  # Tells the printing function not to print these stats

    # Check for username match
    if l_spray_users_filename:
        spray_users = file_to_userlist(l_spray_users_filename)

        i = 0
        while i < len(l_dcsync_results):
            for user_to_compare in spray_users:
                if l_dcsync_results[i]['USERNAME'].lower() == user_to_compare['USERNAME'].lower():
                    l_dcsync_results[i]['SPRAY USERNAME'] = True
                    i += 1
                    continue
            l_dcsync_results[i]['SPRAY USERNAME'] = False
            i += 1

    # Check for password matches
    if l_spray_passwords_filename:
        spray_passwords = []
        with open(l_spray_passwords_filename, 'r') as passwords_file:
            for password in passwords_file:
                password = password.rstrip()  # Get rid of the newline
                spray_passwords.append(password)

        i = 0
        while i < len(l_dcsync_results):
            for pass_to_compare in spray_passwords:
                if l_dcsync_results[i]['PASSWORD'].lower() == pass_to_compare:
                    l_dcsync_results[i]['SPRAY PASSWORD'] = True
                    i += 1
                    continue
            l_dcsync_results[i]['SPRAY PASSWORD'] = False
            i += 1

    # Calculate number of matches
    for entry in l_dcsync_results:
        username = entry.get('SPRAY USERNAME')  # It's ineffecient to have these in memory, but avoids having to catch
        password = entry.get('SPRAY PASSWORD')  # an error if these values don't exist
        enabled = entry.get('ENABLED')
        if username and password and enabled:
            l_num_spray_matches += 1
        if password and enabled:
            l_num_pass_spray_matches += 1

    return l_dcsync_results, l_num_spray_matches, l_num_pass_spray_matches


def write_xlsx(file_date, database):
    out_filename = f"passinspector_results_{file_date}.xlsx"
    print(f"Writing results in Excel format to {out_filename}")
    # Create Workbook
    workbook = xlsxwriter.Workbook(out_filename)
    worksheet = workbook.add_worksheet()
    cell_format = workbook.add_format()
    cell_format.set_text_wrap()
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

    worksheet.set_column('C:D', None, None, {'hidden': True})

    # Write Headers
    col_count = 0
    for key in database[0]:
        worksheet.write(0, col_count, key, header_format)
        col_count += 1
    worksheet.write(0, col_count, "PASS LENGTH", header_format)  # Add Pass Length Header

    # Hide any columns that don't have valid entries
    col_count = 0
    for key in database[0]:
        key_found = False
        for entry in database[1:]:
            if entry[key]:
                key_found = True
        if not key_found:
            col_letter = chr(ord('A') + col_count)
            worksheet.set_column(f"{col_letter}:{col_letter}", None, None, {'hidden': True})
        col_count += 1

    worksheet.freeze_panes(1, 0)  # Freeze the top row

    # Write output to file
    row_count = 0
    while row_count < len(database):
        col_count = 0
        for value in database[row_count].values():
            worksheet.write((row_count + 1), col_count, value, cell_format)
            col_count += 1
        # Add length of password
        if len(database[row_count]['PASSWORD']):
            worksheet.write((row_count + 1), col_count, len(database[row_count]['PASSWORD']), cell_format)
        row_count += 1
    worksheet.autofilter('A1:Z1')  # Allow the headers to be filtered
    worksheet.autofit()  # Autofit the columns
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
    dcsync_domains = set() # Domain(s) from the DCSync
    imported_domains = set() # Domain(s) from Neo4j or provided files for admin and enabled users
    unique_domains_imported = set()
    unique_domains_dcsync = set()

    # Skip this if no admin/enabled/kerberoastable user files or Neo4j creds were provided
    if not admin_users and not enabled_users and not kerberoastable_users:
        return dcsync_file_lines, admin_users, enabled_users, kerberoastable_users

    # Get domain(s) from DCSync file
    for line in dcsync_file_lines:
        try:
            parts = line.split(':')
            domain_user_combined = parts[0].split('\\', 1)
        except IndexError:
            print(f"ERROR: Index error encountered: {IndexError}")
            return None
        # If there is a domain specified, get the domain
        if len(domain_user_combined) == 2:
            dcsync_domains.add(domain_user_combined[0].lower())

    # Get domain(s) from imported files or from Neo4j
    for user in admin_users:
        imported_domains.add(user['DOMAIN'].lower())
    for user in enabled_users:
        imported_domains.add(user['DOMAIN'].lower())
    for user in kerberoastable_users:
        imported_domains.add(user['DOMAIN'].lower())

    # Compare to see if any domains are just in the DCSync or provided docs/Neo4j
    if DEBUG_MODE:
        print(f"DEBUG: imported_domains {imported_domains}")
        print(f"DEBUG: dcsync_domains {dcsync_domains}")
    for domain in imported_domains:
        if domain not in dcsync_domains:
            unique_domains_imported.add(domain)
    for domain in dcsync_domains:
        if domain not in imported_domains:
            unique_domains_dcsync.add(domain)

    # See if the user wants to fix any unique domains if they were found in the imported data
    if unique_domains_imported:
        for unique_domain in unique_domains_imported:
            no_match_text = "DCSync"
            new_domain = ""
            try:
                # If curses exists, use the TUI
                import curses
                new_domain = curses.wrapper(domain_change_tui, unique_domain, no_match_text, dcsync_domains)
            except ImportError:
                # If curses is not available, use the CLI
                new_domain = domain_change_cli(unique_domain, no_match_text, dcsync_domains)

            if new_domain:
                old_domain = unique_domain
                admin_users, enabled_users, kerberoastable_users = replace_imported_domain(old_domain, new_domain,
                                                                                           admin_users, enabled_users,
                                                                                           kerberoastable_users)
            else:
                print(f"No changes made for domain {unique_domain}")

    if unique_domains_dcsync:
        for unique_domain in unique_domains_dcsync:
            no_match_text = "imported data"
            new_domain = ""
            try:
                # If curses exists, use the TUI
                import curses
                new_domain = curses.wrapper(domain_change_tui, unique_domain, no_match_text, imported_domains)
            except ImportError:
                # If curses is not available, use the CLI
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


def replace_dcsync_domain(old_domain, new_domain, dcsync_file_lines):
    print(f"Updating {old_domain} domain in DCSync to {new_domain}")

    i = 0
    while i < len(dcsync_file_lines):
        dcsync_file_lines[i] = dcsync_file_lines[i].split("\\")
        dcsync_file_lines[i][0] = new_domain
        dcsync_file_lines[i] = "\\".join(dcsync_file_lines[i])
        i += 1

    return dcsync_file_lines

def parse_dcsync_line(line, password_file_lines, admin_users, enabled_users, kerberoastable_users):
    # Used to parse lines from DCSync file into different variables. The structure of the data will be:
    # DOMAIN: string
    # USERNAME: string
    # LMHASH: string
    # NTHASH: string
    # PASSWORD: string
    # CRACKED: boolean
    # HAS_LM: boolean
    # BLANK_PASSWORD: boolean
    # ENABLED: boolean
    # IS_ADMIN: boolean
    # KERBEROASTABLE: boolean
    # STUDENT: boolean
    # LOCAL_PASS_REPEAT: integer

    try:
        parts = line.split(':')
        lm_hash, nt_hash = parts[2], parts[3]
        domain_user_combined = parts[0].split('\\', 1)
    except IndexError:
        return None
    # If there is a domain specified, assign the user and domain. Otherwise, assign the value to the user set the
    # domain property as blank
    if len(domain_user_combined) == 2:
        domain, user = domain_user_combined
    else:
        domain, user = "", domain_user_combined[0]
    # Check if the LM hash represents an actual password
    if "aad3b435b51404eeaad3b435b51404ee" in lm_hash:
        has_lm = False  # LM hash is NULL
    else:
        has_lm = True  # LM hash represents an actual password
    # Check if the NT hash represents an actual password
    if "31d6cfe0d16ae931b73c59d7e0c089c0" in nt_hash:
        blank_password = True  # NT hash is NULL
    else:
        blank_password = False  # NT hash represents an actual password
    password, cracked = check_if_cracked(nt_hash, password_file_lines)
    enabled = check_if_enabled(user, domain, enabled_users)
    is_admin = check_if_admin(user, domain, admin_users)
    is_krb = check_if_kerberoastable(user, domain, kerberoastable_users)

    return {
        'DOMAIN': domain,
        'USERNAME': user,
        'LMHASH': lm_hash,
        'NTHASH': nt_hash,
        'PASSWORD': password,
        'CRACKED': cracked,
        'HAS_LM': has_lm,
        'BLANK_PASSWORD': blank_password,
        'ENABLED': enabled,
        'IS_ADMIN': is_admin,
        'KERBEROASTABLE': is_krb,
        'STUDENT': False,
        'LOCAL_PASS_REPEAT': 0
    }


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


def calculate_cracked_deprecated(dcsync_results):
    if DEBUG_MODE:
        print("DEBUG: WHY AM I HERE?")
    unique_nt_hashes = set()
    cracked_accounts = []
    for record in dcsync_results:
        if record['CRACKED']:
            unique_nt_hashes.add(record['NTHASH'])
            cracked_accounts.append(record)
    return len(unique_nt_hashes), len(cracked_accounts)


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
    shortest_length = 1000000  # High starting value, so it can be used to initially compare
    longest_length = 0  # Low starting value, so it can be used to initially compare
    shortest_passwords = set()
    longest_passwords = set()

    unique_users = set()

    for user in user_database:
        user_key = (user['DOMAIN'], user['USERNAME'])
        if user_key not in unique_users:
            unique_users.add(user_key)
            # Get rid of disabled users
            if not user['ENABLED']:
                continue
            password = user['PASSWORD']
            length = len(password)
            if length > 0:  # Don't count blank passwords
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


def perform_password_search(dcsync_results_cracked, search_terms):
    common_terms = ["password", "letmein", "welcome", "abc", "qwertz"]
    common_seasons = ["spring", "summer", "fall", "autumn", "winter"]
    common_keyboard_walks = ["qwerty", "asdf", "qaz", "zxc", "12345", "09876", "jkl", "xcvbn"]
    result_blank_passwords = []
    result_common_terms = []
    result_seasons = []
    result_keyboard_walks = []
    result_custom_search = []
    stat_blank_passwords = ""
    stat_terms = ""
    stat_seasons = ""
    stat_keyboard_walks = ""
    stat_custom_search = ""
    count_blank_passwords = 0
    count_terms = 0
    count_seasons = 0
    count_keyboard_walks = 0
    count_custom_search = 0

    def inner_search(terms, dcsync_results_cracked):
        normal_count = 0
        leet_count = 0
        leet_text = ""
        result_records = []
        for term in terms:
            for record in dcsync_results_cracked:
                if term.lower() in record['PASSWORD'].lower():
                    normal_count += 1
                    result_records.append(record)
            leet_terms = convert_to_leetspeak(term)
            for leet_term in leet_terms:
                for record in dcsync_results_cracked:
                    if leet_term.lower() in record['PASSWORD'].lower():
                        leet_count += 1
                        result_records.append(record)
        if leet_count > 0:
            leet_text = " (" + str(leet_count) + " contained leetspeech)"
            normal_count += leet_count
        return normal_count, leet_text, result_records

    for record in dcsync_results_cracked:
        if record['NTHASH'] == "31d6cfe0d16ae931b73c59d7e0c089c0":
            count_blank_passwords += 1
            result_blank_passwords.append(record)
    if count_blank_passwords > 0:
        stat_blank_passwords = (f"There were {str(count_blank_passwords)} account(s) found with blank passwords")

    count_terms, leet_text, result_common_terms = inner_search(common_terms, dcsync_results_cracked)
    if count_terms > 0:
        stat_terms = (f"There were {str(count_terms)} password(s) found to contain common terms such as password, "
                      f"welcome, or letmein{leet_text}")
    count_seasons, leet_text, result_seasons = inner_search(common_seasons, dcsync_results_cracked)
    if count_seasons > 0:
        stat_seasons = (f"There were {str(count_seasons)} password(s) found to contain seasons of the year (Spring, "
                        f"Summer, Fall, Autumn, Winter){leet_text}")
    count_keyboard_walks, leet_text, result_keyboard_walks = inner_search(common_keyboard_walks, dcsync_results_cracked)
    if count_keyboard_walks > 0:
        stat_keyboard_walks = (f"There were {str(count_keyboard_walks)} password(s) found to keyboard walks, which are "
                               f"commonly chosen sequential keys on the keyboard such as qwerty, zxc, or asdf "
                               f"{leet_text}")
    if len(search_terms) > 0:
        for term in search_terms:
            count_custom_search, leet_text, result_custom_search = inner_search([term], dcsync_results_cracked)
            if count_custom_search > 0:
                stat_custom_search = "There were " + str(
                    count_custom_search) + " result(s) for the password " + term + leet_text
        count_custom_search, _, result_custom_search = inner_search(search_terms, dcsync_results_cracked)

    # print("DEBUG")
    # print("stat_blank_passwords: ", stat_blank_passwords)
    # print("stat_terms: ", stat_terms)
    # print("stat_seasons: ", stat_seasons)
    # print("stat_keyboard_walks: ", stat_keyboard_walks)
    # print("stat_custom_search: ", stat_custom_search)
    return (stat_blank_passwords, stat_terms, stat_seasons, stat_keyboard_walks, stat_custom_search,
            result_blank_passwords, result_common_terms, result_seasons, result_keyboard_walks, result_custom_search)


def username_password_search(dcsync_results_cracked):
    text_username_passwords = ""
    result_username_passwords = []
    count_username_password = 0
    count_username_password_exact = 0
    for account in dcsync_results_cracked:
        username = account['USERNAME'].lower()
        password = account['PASSWORD'].lower()
        if username in password or password in username and password:
            count_username_password += 1
            result_username_passwords.append(account)
            if username == password:
                count_username_password_exact += 1
    if count_username_password > 0:
        text_username_passwords = "There were " + str(
            count_username_password) + " account(s) using their username as part of their password"
        if count_username_password_exact > 0:
            text_username_passwords = (f"{text_username_passwords}. {str(count_username_password_exact)} of these "
                                       f"account(s) used their username as their password without any additional "
                                       f"complexity")
    return text_username_passwords, result_username_passwords


def admin_password_inspection(dcsync_results, admins):
    # This could probably be done much more efficiently by someone more familiar with Python
    admin_password_matches = []
    text_password_matches = ""

    unique_users = set()

    for record in dcsync_results:
        if record['USERNAME'] in admins:
            admin_username = record['USERNAME']
            admin_hash = record['NTHASH']
            matching_users = []
            for user in dcsync_results:
                user_key = (user['DOMAIN'], user['USERNAME'])
                if user_key not in unique_users:
                    unique_users.add(user_key)
                    # Make sure we don't report matches on the same user:
                    if user['NTHASH'] == admin_hash and user['USERNAME'] not in admins:
                        # print("The user ", record['USERNAME'], " shares a password with ", user['USERNAME'])
                        matching_users.append(user['USERNAME'])
            if len(matching_users) > 0:
                admin_password_matches.append(
                    {'ADMIN_USER': admin_username, 'NTHASH': admin_hash, 'NON_ADMIN_USERS': matching_users})
    # print(admin_password_matches)
    if len(admin_password_matches) > 0:
        text_password_matches = "There were " + str(
            len(admin_password_matches)) + (" instance(s) of an administrative user sharing a password with a "
                                            "non-administrative account")
    return text_password_matches, admin_password_matches


def lm_hash_inspection(dcsync_results):
    lm_hash_users = []
    text_results = ""
    for record in dcsync_results:
        if record['HAS_LM']:
            lm_hash_users.append(record)
    if len(lm_hash_users) > 0:
        text_results = "LM hashes were found to be stored for " + str(len(lm_hash_users)) + " account(s)"
    return text_results, lm_hash_users

def blank_enabled_search(dcsync_results, text_blank_passwords):
    # Returns additional text for the blank password line and user accounts with blank passwords
    blank_enabled_users = []
    text_results = ""
    for record in dcsync_results:
        if record['BLANK_PASSWORD'] and record['ENABLED']:
            blank_enabled_users.append(record)
    if len(blank_enabled_users) > 0:
        text_results = f" ({len(blank_enabled_users)} of these accounts were enabled)"
    text_blank_passwords += text_results
    return text_blank_passwords, blank_enabled_users

def cred_stuffing_check(cred_stuffing_accounts, dcsync_results):
    cred_stuffing_matches = []
    text_results = ""
    for cred_stuffing_account in cred_stuffing_accounts:
        for dcsync_account in dcsync_results:
            if cred_stuffing_account['USERNAME'].lower() == dcsync_account['USERNAME'].lower() and cred_stuffing_account['PASSWORD'] == dcsync_account['PASSWORD']:
                cred_stuffing_matches.append(f"{cred_stuffing_account["USERNAME"]}:{cred_stuffing_account['PASSWORD']}")
    if len(cred_stuffing_matches) > 0:
        text_results = f"There were {len(cred_stuffing_matches)} valid credential stuffing password(s) found to be valid"
    return text_results, cred_stuffing_matches

def average_pass_length(dcsync_results):
    employee_total = 0
    employee_count = 0
    enabled_total = 0
    enabled_count = 0
    student_total = 0
    student_count = 0

    for result in dcsync_results:
        if result['PASSWORD']:  # Ignoring blank and uncracked passwords in calculation
            if not result['STUDENT']:
                employee_total += len(result['PASSWORD'])
                employee_count += 1
            else:
                student_total += len(result['PASSWORD'])
                student_count += 1
            if result['ENABLED'] and not result['STUDENT']:
                enabled_total += len(result['PASSWORD'])
                enabled_count += 1

    if employee_count > 0:
        employee_average = round(employee_total / employee_count, 2)  # Round the average to two decimal points
    else:
        employee_average = 0

    if student_count > 0:
        student_average = round(student_total / student_count, 2)
    else:
        student_average = 0

    if enabled_count:
        enabled_average = round(enabled_total / enabled_count, 2)
    else:
        enabled_average = 0

    return employee_average, student_average, enabled_average


def calc_da_cracked(user_database=None):
    da_cracked = 0
    da_total = 0
    unique_users = set()
    for user in user_database:
        user_key = (user['DOMAIN'], user['USERNAME'])
        if user_key not in unique_users:
            unique_users.add(user_key)
            if user['IS_ADMIN']:
                da_total += 1
                if user['CRACKED']:
                    da_cracked += 1

    return da_cracked, da_total


def calculate_unique_hashes(user_database):
    unique_hashes = []
    cracked_unique_hashes = 0
    unique_users = set()

    for user in user_database:
        user_key = (user['DOMAIN'], user['USERNAME'])
        if user_key not in unique_users:
            unique_users.add(user_key)
            if user['NTHASH'] not in unique_hashes:
                unique_hashes.append(user['NTHASH'])
                if user['CRACKED']:
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
        user_key = (user['DOMAIN'], user['USERNAME'])
        if user_key not in unique_users:
            unique_users.add(user_key)
            if user['CRACKED']:
                all_cracked += 1

            if user['STUDENT'] and user['CRACKED']:
                student_cracked += 1
                student_total += 1
            elif user['STUDENT'] and not user['CRACKED']:
                student_total += 1
            elif not user['STUDENT'] and user['CRACKED']:
                employee_cracked += 1
                employee_total += 1
            elif not user['STUDENT'] and not user['CRACKED']:
                employee_total += 1

            if user['ENABLED'] and user['CRACKED']:
                enabled_cracked += 1
                enabled_total += 1
            elif user['ENABLED'] and not user['CRACKED']:
                enabled_total += 1

    student_crack_percent = f"({round((student_cracked / student_total), 2) * 100}%)" if student_total != 0 else "0%"
    employee_crack_percent = f"({round((employee_cracked / employee_total), 2) * 100}%)" if employee_total != 0 else "0%"
    enabled_crack_percent = f"({(enabled_cracked / enabled_total * 100):.2f}%)" if enabled_total != 0 else "0%"
    all_crack_percent = f"({round(all_cracked / len(user_database), 2) * 100}%)" if len(user_database) != 0 else "0%"

    return (employee_cracked, employee_total, employee_crack_percent, student_cracked, student_total,
            student_crack_percent, enabled_cracked, enabled_total, enabled_crack_percent, all_cracked,
            len(user_database), all_crack_percent)


def show_results(stat_shortest, stat_longest, text_blank_passwords, text_terms, text_seasons, text_keyboard_walks,
                 text_custom_search, text_username_passwords, text_admin_pass_reuse, text_lm_hashes, text_cred_stuffing, stat_spray_matches,
                 stat_spray_pass_matches, user_database):
    da_cracked, da_total = calc_da_cracked(user_database=user_database)
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
    results_text += print_and_log(f"Shortest password length (not counting blank passwords): {stat_shortest}", results_text)
    results_text += print_and_log(f"Longest password length: {stat_longest}", results_text)
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


def write_cracked_file(printed_stats, file_datetime, dcsync_results, result_shortest_passwords, result_longest_passwords,
                       result_blank_passwords, result_common_terms, result_seasons, result_keyboard_walks,
                       result_custom_search, result_username_passwords, results_admin_pass_reuse, result_lm_hash_users, result_blank_enabled, result_cred_stuffing):
    output_filename = f"passinspector_allcracked_{file_datetime}.txt"
    print(f"Writing all cracked passwords to {output_filename}")
    results = ["USERNAME,PASSWORD,ENABLED,ADMIN,STUDENT"]
    for record in dcsync_results:
        if record['CRACKED']:
            result = (f"{record['USERNAME']},{record['PASSWORD']},{record['ENABLED']},{record['IS_ADMIN']},"
                      f"{record['STUDENT']}")
            results.append(result)
    with open(output_filename, 'w') as outfile:
        for result in results:
            outfile.write(result + '\n')

    output_filename = f"passinspector_results_{file_datetime}.txt"
    print(f"Writing each of the results {output_filename}")
    results = []
    results.append("=======================")
    results.append("RESULTS SUMMARY")
    results.append("=======================")
    results.append(printed_stats)
    results.append("=======================")
    results.append("SHORTEST PASSWORD(S)")
    results.append("=======================")
    for record in result_shortest_passwords:
        results.append(record)
    results.append("")
    results.append("=======================")
    results.append("LONGEST PASSWORD(S)")
    results.append("=======================")
    for record in result_longest_passwords:
        results.append(record)
    if result_blank_passwords:
        results.append("")
        results.append("=======================")
        results.append("ACCOUNTS WITH BLANK PASSWORDS")
        results.append("=======================")
        for record in result_blank_passwords:
            results.append(record['USERNAME'])
    if result_blank_enabled:
        results.append("")
        results.append("=======================")
        results.append("ENABLED ACCOUNTS WITH BLANK PASSWORDS")
        results.append("=======================")
        unique_users = set()
        for user in result_blank_enabled:
            user_key = (user['DOMAIN'], user['USERNAME'])
            if user_key not in unique_users:
                unique_users.add(user_key)
                results.append(user)
    if result_common_terms:
        results.append("")
        results.append("=======================")
        results.append("COMMON TERM PASSWORDS")
        results.append("=======================")
        for record in result_common_terms:
            result = record['USERNAME'] + "," + record['PASSWORD']
            results.append(result)
    if result_seasons:
        results.append("")
        results.append("=======================")
        results.append("SEASON PASSWORDS")
        results.append("=======================")
        for record in result_seasons:
            result = record['USERNAME'] + "," + record['PASSWORD']
            results.append(result)
    if result_keyboard_walks:
        results.append("")
        results.append("=======================")
        results.append("KEYBOARD WALK PASSWORDS")
        results.append("=======================")
        for record in result_keyboard_walks:
            result = record['USERNAME'] + "," + record['PASSWORD']
            results.append(result)
    if result_custom_search:
        results.append("")
        results.append("=======================")
        results.append("CUSTOM SEARCH TERM PASSWORDS")
        results.append("=======================")
        for record in result_custom_search:
            result = record['USERNAME'] + "," + record['PASSWORD']
            results.append(result)
    if result_username_passwords:
        results.append("")
        results.append("=======================")
        results.append("USERNAMES AS PASSWORDS")
        results.append("=======================")
        for record in result_username_passwords:
            result = record['USERNAME'] + "," + record['PASSWORD']
            results.append(result)
    if results_admin_pass_reuse:
        results.append("")
        results.append("=======================")
        results.append("ADMIN PASSWORD REUSE")
        results.append("=======================")
        for record in results_admin_pass_reuse:
            result = "The administrative user " + record['ADMIN_USER'] + " shares a password (NT Hash: " + record[
                'NTHASH'] + ") with the non-administrative user(s): "
            for user in record['NON_ADMIN_USERS']:
                result = result + user + " "
            results.append(result)
    if result_lm_hash_users:
        results.append("")
        results.append("=======================")
        results.append("USERS WITH LM HASHES")
        results.append("=======================")
        for record in result_lm_hash_users:
            result = record['USERNAME'] + "," + record['LMHASH']
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
                    users.append({'USERNAME': line[0]})
    else:
        print("ERROR: Do not recognize file extension: ", filename)
        return

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


def calc_duplicate_password_identifier(dcsync):
    password_identifier_key = 0
    password_identifiers = []
    i = 0
    while i < len(dcsync):
        for password_identifier in password_identifiers:
            if dcsync[i]['NTHASH'] == password_identifier['NTHASH']:
                dcsync[i]['PASS_IDENTIFIER'] = password_identifier['PASS_IDENTIFIER']
                break
        if 'PASS_IDENTIFIER' not in dcsync[i].keys():
            password_identifiers.append({'NTHASH': dcsync[i]['NTHASH'], 'PASS_IDENTIFIER': password_identifier_key})
            dcsync[i]['PASS_IDENTIFIER'] = password_identifier_key
            password_identifier_key += 1

        i += 1

    return dcsync


def add_cleartext_creds(user_database, clear_creds):
    for clear_cred in clear_creds:
        i = 0
        while i < len(user_database):
            if (user_database[i]['DOMAIN'] == clear_cred['Domain'] and
                    user_database[i]['USERNAME'] == clear_cred['Username']):
                user_database[i]['PASSWORD'] = clear_cred['Password']
            i += 1

    return user_database


def count_pass_repeat(dcsync):
    i = 0
    while i < len(dcsync):
        pass_repeat_count = 0
        for dcsync_result in dcsync:
            if dcsync[i]['NTHASH'] == dcsync_result['NTHASH']:
                pass_repeat_count += 1
        dcsync[i]['PASS_REPEAT_COUNT'] = pass_repeat_count
        i += 1

    return dcsync


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


def parse_students(dcsync, students_filename):
    if not students_filename:
        return dcsync

    print("Parsing students")

    students = file_to_userlist(students_filename)
    i = 0
    while i < len(dcsync):
        for student in students:
            if dcsync[i]['USERNAME'].lower() == student['USERNAME'].lower():
                dcsync[i]['STUDENT'] = True
                break
        i += 1

    return dcsync


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


def get_cred_stuffing(cred_stuffing_filename, cred_stuffing_domains):
    if cred_stuffing_filename:
        cred_stuffing_accounts = open_file(cred_stuffing_filename)
    elif os.path.isfile("passinspector_dehashed_results.txt"):
        cred_stuffing_accounts = import_dehashed_file()
    elif cred_stuffing_domains or NEO4J_PASSWORD:
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


def parse_local_hashes(dcsync, local_hash_filename):
    if not local_hash_filename:
        return dcsync

    local_hashes = process_hashes(local_hash_filename)

    i = 0
    while i < len(dcsync):
        nt_hash = dcsync[i]['NTHASH']
        for comparison_hash in local_hashes:
            if comparison_hash == nt_hash:
                dcsync[i]['LOCAL_PASS_REPEAT'] += 1
        i += 1

    return dcsync


def count_local_hash(dcsync):
    local_hash_count = 0
    for user in dcsync:
        if user['LOCAL_PASS_REPEAT'] > 0:
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
    script_version = 2.4
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

    parser.add_argument('-db', '--debug', help='(OPTIONAL) Turn on debug messages')

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

    if args.debug:
        DEBUG_MODE = True
    else:
        DEBUG_MODE = False

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
                    args.kerberoastable_users, duplicate_password_identifier, file_prefix, args.local_hashes)
