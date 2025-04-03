import argparse


def gather_arguments():
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

    # Parse the command-line arguments
    args = parser.parse_args()

    global DEBUG_MODE
    DEBUG_MODE = args.debug

    return (args.dcsync, args.passwords, args.spray_users, args.spray_passwords, args.duplicate_password_identifier,
            args.no_dehashed, args.cred_stuffing_domains, args.prepare_hashes, args.custom, args.neo4j_hostname, args.neo4j_username,
            args.neo4j_password, args.students, args.local_hashes, args.cred_stuffing, args.admins, args.enabled, args.kerberoastable_users)


def parse_arguments(cred_stuffing_domains, custom):
    if cred_stuffing_domains:
        cred_stuffing_domains = cred_stuffing_domains.split(',')

    if custom:  # Only parse the custom passwords if they were provided
        search_terms = custom.split(',')
    else:
        search_terms = []

    return cred_stuffing_domains, search_terms


def print_and_log(message, log):
    print(message)
    log = message + "\n"
    return log


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


def fix_bad_passwords(user_database):
    for user in user_database:
        user.fix_password()
    return user_database
