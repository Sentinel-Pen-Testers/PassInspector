from itertools import product

def log_message(filename, message):
    print(message)

    with open(filename, "a", encoding = "utf-8") as f:
        f.write(message + "\n")


def generate_leetspeak_variants(words):
    """
    Given a list of words, return the original words plus all leetspeak variants.
    """
    leetspeak_mapping = {
        'a': ['@', '4'],
        'b': ['8'],
        'e': ['3'],
        'g': ['9'],
        'i': ['1', '!'],
        'l': ['1', '|'],
        'o': ['0'],
        's': ['5', '$'],
        't': ['7', '+'],
        'z': ['2']
    }

    all_variants = set(words)  # Use a set to automatically deduplicate

    for term in words:
        # Build possible substitutions for each character
        char_options = [
            [char, *leetspeak_mapping.get(char.lower(), [])]
            for char in term
        ]

        # Generate all possible combinations
        variants = {''.join(chars) for chars in product(*char_options)}

        # Add to the total set
        all_variants.update(variants)

    return list(all_variants)


def print_statistics(user_database, output_filename):
    notable_users = [user for user in user_database if user.notable_password]

    print_username_passwords(notable_users, output_filename)
    print_common_passwords(notable_users, output_filename)

def print_username_passwords(notable_users, output_filename):
    count_user_in_pass = 0
    count_user_in_pass_enabled = 0
    count_user_in_pass_exact = 0
    count_user_in_pass_exact_enabled = 0

    for user in notable_users:
        if "Username in Password" in user.notable_password:
            count_user_in_pass += 1
            if user.enabled:
                count_user_in_pass += 1
        if "Username is Password" in user.notable_password:
            count_user_in_pass_exact += 1
            if user.enabled:
                count_user_in_pass_exact += 1

    if count_user_in_pass > 0:
        log_message(output_filename, f"{count_user_in_pass} account(s) using their username as part of their password. "
         f"{count_user_in_pass_enabled} of these belonged to enabled users.")

    if count_user_in_pass_exact > 0:
        log_message(output_filename, f"{count_user_in_pass_exact} account(s) using their username as part of their password. "
              f"{count_user_in_pass_exact_enabled} of these belonged to enabled users.")


def print_common_passwords(notable_users, output_filename):
    count_season_passwords = 0
    count_season_passwords_enabled = 0
    count_keyboard_walks = 0
    count_keyboard_walks_enabled = 0
    count_common_pass = 0
    count_common_pass_enabled = 0

    for user in notable_users:
        if "Season" in user.notable_password:
            count_season_passwords += 1
            if user.enabled:
                count_season_passwords_enabled += 1
        if "Keyboard Walk" in user.notable_password:
            count_keyboard_walks += 1
            if user.enabled:
                count_keyboard_walks_enabled += 1
        if "Common Term" in user.notable_password:
            count_common_pass += 1
            if user.enabled:
                count_common_pass_enabled += 1

    if count_season_passwords > 0:
        log_message(output_filename, f"{count_season_passwords} account(s) with a season in their password. {count_season_passwords_enabled} of these belonged to enabled users.")
    if count_keyboard_walks > 0:
        log_message(output_filename, f"{count_keyboard_walks} account(s) with a keyboard walk in their password (such as 'qwerty', 'zxc', or 'asdf'). {count_keyboard_walks_enabled} of these belonged to enabled users.")
    if count_common_pass > 0:
        log_message(output_filename, f"{count_common_pass} accounts(s) with a common term in their password (such as 'password', 'welcome', or 'letmein'). {count_common_pass_enabled} of these belonged to enabled users.")


def print_blank_passwords(user_database, output_filename):
    count_blank_password_enabled = sum(
        1 for user in user_database if user.enabled and user.blank_password
    )

    if count_blank_password_enabled > 0:
        log_message(output_filename, f"{count_blank_password_enabled} enabled users with blank passwords were found. ")