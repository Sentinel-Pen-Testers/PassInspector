def _split_domain_username(raw_user):
    if "\\" in raw_user:
        domain, username = raw_user.split("\\", 1)
        return domain.lower(), username.lower()
    return "none", raw_user.lower()


def check_for_no_aes(dcsync_filename, user_database):
    user_hash_types = {}
    aes_hash_types = {"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96"}
    saw_any_aes_hash = False

    with open(dcsync_filename, "r", encoding="utf-8") as dcsync_file:
        for raw_line in dcsync_file:
            line = raw_line.strip()
            if not line:
                continue

            parts = line.split(":")
            if len(parts) < 2:
                continue

            domain, username = _split_domain_username(parts[0].strip())
            hash_type = parts[1].strip().lower()
            if hash_type in aes_hash_types:
                saw_any_aes_hash = True
            user_key = (domain, username)
            user_hash_types.setdefault(user_key, set()).add(hash_type)

    if not saw_any_aes_hash:
        return user_database

    no_aes_users = {
        user_key
        for user_key, hash_types in user_hash_types.items()
        if "aes256-cts-hmac-sha1-96" not in hash_types and "aes128-cts-hmac-sha1-96" not in hash_types
    }

    for user in user_database:
        user_domain = (user.domain or "NONE").lower()
        user_key = (user_domain, user.username.lower())
        user.lacks_aes = user_key in no_aes_users

    return user_database
