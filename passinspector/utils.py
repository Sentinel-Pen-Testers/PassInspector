import argparse
import json
from neo4j import GraphDatabase
import re
from datetime import datetime
from pathlib import Path

# default debug mode value; updated by gather_arguments
DEBUG_MODE = False


def fix_bad_passwords(user_database):
    for user in user_database:
        user.fix_password()
    return user_database


def check_group_member(user_database, group_members, attribute):
    for user in user_database:
        user.check_membership(group_members, attribute)
    return user_database


def file_to_userlist(filename=None):
    """Return a list of users from a variety of file formats.

    The function will attempt to detect the file type automatically. Supported
    structures include JSON exports (such as from BloodHound), comma separated
    values, or plain newline separated text files containing users.
    """

    if not filename:
        return []

    filename = filename.strip()

    # Try JSON first since json.load will raise an error if it's not JSON
    users = read_json_file(filename)
    if users is not None:
        if DEBUG_MODE:
            print(f"[DEBUG] {filename} detected as JSON")
        return users

    # Otherwise treat as a text based file
    try:
        with open(filename, 'r', encoding='utf-8-sig') as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(f"ERROR: Could not find file: {filename}")
        return []

    detected_type = "text"
    # Skip header row if one exists and mark as CSV
    if lines and any(key in lines[0].lower() for key in ["username", "samaccount", "domain"]):
        lines = lines[1:]
        detected_type = "CSV"
    elif any(',' in l for l in lines[:5]):
        detected_type = "CSV"

    if DEBUG_MODE:
        print(f"[DEBUG] {filename} detected as {detected_type}")

    users = []
    for line in lines:
        line = line.rstrip('\n').replace('"', '')
        if not line:
            continue

        if '@' in line:
            parts = line.split('@', 1)
            users.append({'USERNAME': parts[0], 'DOMAIN': parts[1]})
        elif ',' in line:
            parts = line.split(',', 1)
            users.append({'USERNAME': parts[0], 'DOMAIN': parts[1]})
        elif '\\' in line:
            parts = line.split('\\', 1)
            users.append({'USERNAME': parts[1], 'DOMAIN': parts[0]})
        elif '/' in line:
            parts = line.split('/', 1)
            users.append({'USERNAME': parts[1], 'DOMAIN': parts[0]})
        else:
            users.append({'USERNAME': line, 'DOMAIN': None})

    return users


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


def gather_arguments():
    # Create an argument parser
    parser = argparse.ArgumentParser(
        description='This script is built to search through DCSync results to help highlight weak password patterns')

    # Add the optional -a flag for a list of administrative users
    parser.add_argument('-a', '--admins', help='(OPTIONAL) A file containing a list of domain '
                                               'administrative users. The script will check if the passwords for these '
                                               'users are used on other accounts by using hashes. The format should be '
                                               'DOMAIN\\USERNAME or USERNAME. BloodHound JSON files are also accepted. '
                                               'Overrides automatic Neo4j queries.')

    # Add the optional -c flag for comma-separated custom passwords to search for
    parser.add_argument('-c', '--custom', help='(OPTIONAL) Comma-separated terms you would like searched '
                                               'for in passwords, such as the organization\'s name or acronym in lowercase')

    # Add the optional -cs flag for colon-separated credential stuffing file to override or replace BreachCreds results
    parser.add_argument('-cs', '--cred-stuffing', help='(OPTIONAL) Only required if BreachCreds.py is not '
                                                       'in the same directory. Colon-separated file containing '
                                                       'credential stuffing accounts in the format of email:password')

    # Add the optional -csd flag for specifying the domain to search DeHashed with if DeHashed is in the same directory
    parser.add_argument('-csd', '--cred-stuffing-domains', default=[],
                        help='(OPTIONAL) If BreachCreds.py is in the same directory, these comma-separated domains will'
                             ' be used to search DeHashed for credential stuffing credentials')

    # Add the -d flag for the DCSync file
    parser.add_argument('-d', '--dcsync', help='(REQUIRED) A file containing the output of a DCSync in the '
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
                                                     'datetime will be used instead.)')

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
    parser.add_argument('-p', '--passwords', help='(REQUIRED) A file containing all of the cracked '
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

    parser.add_argument('-nn', '--no-neo4j', action='store_true',
                        help='(OPTIONAL) Disable all Neo4j checks')

    # Parse the command-line arguments
    args = parser.parse_args()

    global DEBUG_MODE
    DEBUG_MODE = args.debug

    return (args.dcsync, args.passwords, args.spray_users, args.spray_passwords, args.duplicate_password_identifier,
            args.no_dehashed, args.cred_stuffing_domains, args.prepare_hashes, args.custom, args.neo4j_hostname, args.neo4j_username,
            args.neo4j_password, args.students, args.local_hashes, args.cred_stuffing, args.admins, args.enabled,
            args.kerberoastable_users, args.no_neo4j, args.file_prefix)


def get_filenames(file_datetime, dcsync_filename, passwords_filename, local_hash_filename, spray_users_filename, spray_passwords_filename):
    if not file_datetime:
        file_datetime = datetime.now().strftime("%Y%m%d_%H%M%S")

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

    if not local_hash_filename:
        local_hash_filename = find_file([file_datetime, "lsass"])
        if local_hash_filename:
            print(f"No list of local password hashes file was provided, but a file was found: {local_hash_filename}")

    if not spray_users_filename:
        spray_users_filename = find_file([file_datetime, "userlist"])
        if spray_users_filename:
            print(f"No list of sprayable users was provided, but a file was found: {spray_users_filename}")

    if not spray_passwords_filename:
        spray_passwords_filename = find_file([file_datetime, "passwords"])
        if spray_users_filename:
            print(f"No list of sprayable passwords was provided, but a file was found: {spray_users_filename}")


    return file_datetime, dcsync_filename, passwords_filename, local_hash_filename, spray_users_filename, spray_passwords_filename


def group_lookup(query, group_filename, neo4j_uri, neo4j_user, neo4j_pass, neo4j_queries, no_neo4j=False):
    if group_filename:
        group = file_to_userlist(group_filename)
    elif neo4j_pass and not no_neo4j:
        group = neo4j_query(neo4j_queries[query], neo4j_uri, neo4j_user, neo4j_pass)
    else:
        group = []

    return group


def parse_arguments(cred_stuffing_domains, custom):
    if cred_stuffing_domains:
        cred_stuffing_domains = cred_stuffing_domains.split(',')

    if custom:  # Only parse the custom passwords if they were provided
        search_terms = custom.split(',')
    else:
        search_terms = []

    return cred_stuffing_domains, search_terms


def list_files_recursive(directory='.'):
    import os
    files_list = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            files_list.append(os.path.join(root, file))
    return files_list


def neo4j_query(query_string, neo4j_uri, neo4j_user, neo4j_pass):
    try:
        with GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass)) as driver:
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


def print_and_log(message, log):
    print(message)
    log = message + "\n"
    return log


def open_file(l_filename, debug_mode=False):
    if debug_mode:
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


def read_json_file(file_path):
    try:
        # use utf-8-sig to strip BOM if present
        with open(file_path, 'r', encoding="utf-8-sig") as file:
            json_data = json.load(file)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Failed to decode JSON in file '{file_path}': {e}")
        return None

    # decide which structure we're dealing with
    if isinstance(json_data, dict) and 'data' in json_data and 'nodes' in json_data['data']:
        records = json_data['data']['nodes'].values()
    elif isinstance(json_data, list):
        records = json_data
    else:
        print(f"Error: Unexpected JSON structure (got {type(json_data)}).")
        return None

    formatted_usernames = []
    for entry in records:
        # pick the right field
        if isinstance(entry, dict) and 'label' in entry:
            raw = entry['label']
        elif isinstance(entry, dict) and 'u.samaccountname' in entry:
            raw = entry['u.samaccountname']
        else:
            print(f"Warning: skipping unrecognized entry: {entry}")
            continue

        parts = raw.split('@', 1)
        if len(parts) == 2:
            formatted_usernames.append({"USERNAME": parts[0], "DOMAIN": parts[1]})
        else:
            formatted_usernames.append({"USERNAME": parts[0]})

    return formatted_usernames
