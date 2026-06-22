"""Helpers for optionally cracking uncracked LM hashes with hashcat."""

import subprocess
from dataclasses import dataclass
from pathlib import Path

try:
    from passinspector.user import User
except ModuleNotFoundError:
    from user import User

HASHCAT_LM_MODE = "3000"
HASHCAT_NTLM_MODE = "1000"
HASHCAT_DICTIONARY_ATTACK_MODE = "0"
HASHCAT_MASK_ATTACK_MODE = "3"
LM_HALF_MASK = "?a?a?a?a?a?a?a"
DEFAULT_OUTPUT_DIR = "lm_hashcat_results"


@dataclass
class LmCrackResult:
    output_dir: Path
    lm_process: subprocess.CompletedProcess
    lm_show_process: subprocess.CompletedProcess
    nt_process: subprocess.CompletedProcess = None
    nt_show_process: subprocess.CompletedProcess = None
    cracked_lm_passwords: dict = None
    cracked_nt_passwords: dict = None


def count_uncracked_lm_hashes(users):
    """Count users with LM hashes whose passwords have not been cracked."""
    return sum(
        1
        for user in users
        if getattr(user, "has_lm", False) and not getattr(user, "cracked", False)
    )


def get_uncracked_lm_hashes(users):
    """Return unique LM hashes for users whose passwords have not been cracked."""
    return sorted(
        {
            getattr(user, "lmhash")
            for user in users
            if getattr(user, "has_lm", False)
            and not getattr(user, "cracked", False)
            and getattr(user, "lmhash", None)
        }
    )


def normalize_hashcat_path(hashcat_binary):
    """Return a normalized path object for a user-provided hashcat path."""
    return Path(hashcat_binary.strip().strip('"')).expanduser()


def is_valid_hashcat_binary(hashcat_binary):
    """Return True when the provided hashcat path points to a file."""
    return normalize_hashcat_path(hashcat_binary).is_file()


def get_associated_nt_hashes(users, cracked_lm_passwords):
    """Return unique NT hashes for users with successfully reassembled LM passwords."""
    cracked_lm_hashes = {lmhash.lower() for lmhash in cracked_lm_passwords}
    return sorted(
        {
            getattr(user, "nthash").lower()
            for user in users
            if getattr(user, "nthash", None)
            and getattr(user, "lmhash", "").lower() in cracked_lm_hashes
        }
    )


def decode_hashcat_plaintext(plaintext):
    """Decode hashcat $HEX[...] plaintext values when present."""
    if plaintext.startswith("$HEX[") and plaintext.endswith("]"):
        hex_string = plaintext[len("$HEX["):-1]
    elif plaintext.startswith("HEX[") and plaintext.endswith("]"):
        hex_string = plaintext[len("HEX["):-1]
    else:
        return plaintext

    try:
        return bytes.fromhex(hex_string).decode("latin-1")
    except ValueError:
        return plaintext


def parse_hashcat_outfile(outfile):
    """Parse hashcat hash:plaintext output into a normalized hash lookup."""
    output_path = Path(outfile)
    if not output_path.is_file():
        return {}

    cracked_hashes = {}
    for line in output_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue

        hash_value, plaintext = line.split(":", 1)
        if "[notfound]" in plaintext:
            continue

        cracked_hashes[hash_value.lower()] = decode_hashcat_plaintext(plaintext)

    return cracked_hashes


def generate_case_variants(password):
    """Generate all ASCII upper/lowercase variants for an LM-derived password."""
    variants = [""]

    for character in password:
        if "a" <= character.lower() <= "z":
            lower_character = character.lower()
            upper_character = character.upper()
            if lower_character == upper_character:
                options = [lower_character]
            else:
                options = [lower_character, upper_character]
        else:
            options = [character]

        variants = [prefix + option for prefix in variants for option in options]

    return variants


def format_wordlist_candidate(candidate):
    """Return a hashcat-safe wordlist line, using $HEX[] when needed."""
    needs_hex = (
        candidate.startswith("$HEX[")
        or any(character in "\r\n" or ord(character) < 32 or ord(character) > 126 for character in candidate)
    )

    if not needs_hex:
        return candidate

    try:
        encoded_candidate = candidate.encode("latin-1")
    except UnicodeEncodeError:
        encoded_candidate = candidate.encode("utf-8")

    return f"$HEX[{encoded_candidate.hex()}]"


def write_nt_case_wordlist(lm_passwords, wordlist_path):
    """Write case variants of reassembled LM passwords for NTLM cracking."""
    seen_candidates = set()

    with Path(wordlist_path).open("w", encoding="utf-8", newline="\n") as wordlist:
        for password in lm_passwords:
            for variant in generate_case_variants(password):
                candidate = format_wordlist_candidate(variant)
                if candidate in seen_candidates:
                    continue

                wordlist.write(candidate + "\n")
                seen_candidates.add(candidate)

    return len(seen_candidates)


def apply_nt_cracks_to_users(users, cracked_nt_passwords):
    """Update associated user objects with passwords cracked from their NT hashes."""
    cracked_count = 0
    for user in users:
        nthash = getattr(user, "nthash", "").lower()
        if nthash not in cracked_nt_passwords:
            continue

        user.password = cracked_nt_passwords[nthash]
        user.cracked = True
        cracked_count += 1

    return cracked_count


def crack_lm_hashes(users, hashcat_binary, output_dir=None):
    """Crack LM hashes, reassemble LM passwords, then use them against NT hashes."""
    hashcat_path = normalize_hashcat_path(hashcat_binary)

    if not hashcat_path.is_file():
        raise FileNotFoundError(f"Hashcat binary not found: {hashcat_binary}")

    hashcat_path = hashcat_path.resolve()

    lm_hashes = get_uncracked_lm_hashes(users)
    if not lm_hashes:
        return None

    output_path = Path(output_dir or DEFAULT_OUTPUT_DIR).expanduser().resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    lm_hash_file = output_path / "uncracked_lm_hashes.txt"
    lm_parts_outfile = output_path / "cracked_lm_parts.txt"
    lm_reassembled_outfile = output_path / "reassembled_lm_hashes.txt"
    lm_potfile = output_path / "lm_hashcat.potfile"
    nt_hash_file = output_path / "associated_nt_hashes.txt"
    nt_wordlist = output_path / "lm_case_candidates.txt"
    nt_outfile = output_path / "cracked_nt_hashes.txt"
    nt_potfile = output_path / "nt_hashcat.potfile"

    lm_hash_file.write_text("\n".join(lm_hashes) + "\n", encoding="utf-8")

    lm_process = subprocess.run(
        [
            str(hashcat_path),
            "-m",
            HASHCAT_LM_MODE,
            "-a",
            HASHCAT_MASK_ATTACK_MODE,
            "--increment",
            "--potfile-path",
            str(lm_potfile),
            "-o",
            str(lm_parts_outfile),
            str(lm_hash_file),
            LM_HALF_MASK,
        ],
        check=False,
        cwd=hashcat_path.parent,
    )

    lm_show_process = subprocess.run(
        [
            str(hashcat_path),
            "-m",
            HASHCAT_LM_MODE,
            "--show",
            "--quiet",
            "--potfile-path",
            str(lm_potfile),
            "-o",
            str(lm_reassembled_outfile),
            str(lm_hash_file),
        ],
        check=False,
        cwd=hashcat_path.parent,
    )

    cracked_lm_passwords = parse_hashcat_outfile(lm_reassembled_outfile)
    nt_hashes = get_associated_nt_hashes(users, cracked_lm_passwords)

    nt_process = None
    nt_show_process = None
    cracked_nt_passwords = {}

    if nt_hashes:
        nt_hash_file.write_text("\n".join(nt_hashes) + "\n", encoding="utf-8")
        wordlist_count = write_nt_case_wordlist(cracked_lm_passwords.values(), nt_wordlist)

        if wordlist_count:
            nt_process = subprocess.run(
                [
                    str(hashcat_path),
                    "-m",
                    HASHCAT_NTLM_MODE,
                    "-a",
                    HASHCAT_DICTIONARY_ATTACK_MODE,
                    "--potfile-path",
                    str(nt_potfile),
                    str(nt_hash_file),
                    str(nt_wordlist),
                ],
                check=False,
                cwd=hashcat_path.parent,
            )

            nt_show_process = subprocess.run(
                [
                    str(hashcat_path),
                    "-m",
                    HASHCAT_NTLM_MODE,
                    "--show",
                    "--quiet",
                    "--potfile-path",
                    str(nt_potfile),
                    "-o",
                    str(nt_outfile),
                    str(nt_hash_file),
                ],
                check=False,
                cwd=hashcat_path.parent,
            )

            cracked_nt_passwords = parse_hashcat_outfile(nt_outfile)
            apply_nt_cracks_to_users(users, cracked_nt_passwords)

    return LmCrackResult(
        output_dir=output_path,
        lm_process=lm_process,
        lm_show_process=lm_show_process,
        nt_process=nt_process,
        nt_show_process=nt_show_process,
        cracked_lm_passwords=cracked_lm_passwords,
        cracked_nt_passwords=cracked_nt_passwords,
    )


def prompt_for_hashcat_binary(users):
    """
    Prompt for hashcat when uncracked LM hashes are present.

    Returns LmCrackResult when cracking is attempted. Returns None when there
    are no uncracked LM hashes, when the user skips, or when the supplied
    hashcat path is invalid.
    """
    uncracked_lm_count = count_uncracked_lm_hashes(users)

    if uncracked_lm_count == 0:
        return None

    hashcat_binary = input(
        f"{uncracked_lm_count} uncracked LM hashes found. "
        "Enter the path to your hashcat binary (leave blank to skip): "
    )

    if not hashcat_binary.strip():
        print("Skipping hashcat LM cracking.")
        return None

    if not is_valid_hashcat_binary(hashcat_binary):
        print(f"Invalid hashcat binary path: {hashcat_binary}")
        return None

    result = crack_lm_hashes(users, hashcat_binary)
    if result and getattr(result, "output_dir", None):
        print(f"Hashcat results written to: {result.output_dir}")

    return result


def print_crack_result(result, users):
    """Print a concise direct-run summary for manual testing."""
    if result is None:
        print("No cracking result was produced.")
        return

    print("\nLM hashcat test summary")
    print(f"Output directory: {result.output_dir}")
    print(f"LM crack return code: {getattr(result.lm_process, 'returncode', 'unknown')}")
    print(f"LM show return code: {getattr(result.lm_show_process, 'returncode', 'unknown')}")
    print(f"NT crack return code: {getattr(result.nt_process, 'returncode', 'not run')}")
    print(f"NT show return code: {getattr(result.nt_show_process, 'returncode', 'not run')}")

    print("\nReassembled LM passwords:")
    if result.cracked_lm_passwords:
        for lmhash, password in result.cracked_lm_passwords.items():
            print(f"{lmhash}:{password}")
    else:
        print("None")

    print("\nCracked NT passwords:")
    if result.cracked_nt_passwords:
        for nthash, password in result.cracked_nt_passwords.items():
            print(f"{nthash}:{password}")
    else:
        print("None")

    print("\nUser objects:")
    for user in users:
        print(
            f"{user.domain}\\{user.username} "
            f"lmhash={user.lmhash} nthash={user.nthash} "
            f"cracked={user.cracked} password={user.password}"
        )


if __name__ == "__main__":
    dummy_user = User(
        domain="example.local",
        username="dummy.user",
        lmhash="e52cac67419a9a224a3b108f3fa6cb6d",
        nthash="2CE2EA4FCBEB32407DB5DB2E21E19B67",
        password="",
        cracked=False,
        has_lm=True,
        blank_password=False,
        enabled=True,
        is_admin=False,
        kerberoastable=False,
        student=False,
        local_pass_repeat=0,
        pass_repeat=0,
        pass_repeat_accounts=[],
        email="dummy.user@example.local",
        job_title="Test User",
        description="Dummy user for lm_hash_cracker direct execution.",
        spray_user=False,
        spray_password=False,
    )

    dummy_users = [dummy_user]
    print_crack_result(prompt_for_hashcat_binary(dummy_users), dummy_users)
