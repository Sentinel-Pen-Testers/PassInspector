## Description 
PassInspector is built to parse through a list of cracked passwords to identify patterns that could indicate a weak password policy. This script is intended to be used on passwords that have been cracked from the domain's NTDS.dit file using something like a DCSync attack.

If Neo4j credentials are supplied (recommended), PassInspector can automatically pull the following from the BloodHound data:
* Enabled users
* Administrative users (from "Administrators", "Domain Admins", and "Enterprise Admins" groups)
* Kerberoastable users

## Features

PassInspector searches for the following security weaknesses:

* Password Lengths: Finds the shortest and longest passwords cracked (excluding blank passwords).
* Blank Passwords: Identifies accounts with blank passwords and flags enabled accounts.
* Common Passwords: Detects passwords containing common words such as "password" or "welcome".
* Keyboard Walks: Detects passwords containing sequential keyboard patterns such as "qwerty" or "asdf".
* Season-based Passwords: Identifies passwords containing seasons of the year (e.g., "Winter2024").
* Custom Word Search: Allows searching for custom terms (e.g., company names or abbreviations).
* Administrative Password Reuse: Detects if an administrative password is reused in non-administrative accounts using NT hash matching, so it is not dependant on the administrative passwords being cracked
* Username in Password: Flags accounts where the username is part of the password.
* Credential Stuffing Validation:
  * Checks credential stuffing results against cracked passwords.
  * Automatically searches DeHashed if BreachCreds.py is in the same directory and a domain or Neo4j credentials are provided.
* Spray Attack Analysis:
  * Matches cracked passwords to password spray lists.
  * Matches cracked usernames to lists of sprayed users.
* Local Hash Matching: Checks if domain accounts reuse local account passwords (e.g., from LSASS dumps).
* Duplicate Password Identification: Assigns a unique identifier for each password to detect reuse without exposing plaintext passwords.
* HEX Password Correction: Automatically fixes any HEX-formatted passwords.
* LM Hash Detection: Identifies if LM hashes are stored for any accounts.

## Required Files

PassInspector requires at least one of the following input files:

* DCSync Output: A file containing the results of a DCSync attack, in the format:
  
`DOMAIN\USER:RID:LMHASH:NTHASH:::`

(If not provided, PassInspector will attempt to find it automatically.)

* Cracked Passwords: A file containing cracked NTLM hashes in the format:
  
`NTHASH:PASSWORD`

(If not provided, PassInspector will attempt to find it automatically.)

## Output Files

PassInspector generates three output files:
* allcracked.txt – Contains all cracked passwords, their usernames, whether the account is enabled (if provided), and whether the account is administrative (if provided).
* results.txt – Includes key findings such as shortest/longest passwords, administrative password reuse, and more.
* Excel Report – An .xlsx file with various columns for manual investigation.

## Installation
`virtualenv -p python3 venv-passinspector`

`source venv-passinspector/bin/activate`

`pip install -r requirements.txt`

`python3 PassInspector.py`


## Usage

```bash
python PassInspector.py -d <dcsync-file> -p <password-file> [-a <admin-users-file> -c <custom-search-terms> -e <enabled-users-file> -sp <spray-passwords-file> -su <spray-users-file> -lh <local-hashes-file> -cs <credential-stuffing-file> -csd <cred-stuffing-domains> -db -nd -dpi -fp <file-prefix>]
```

**Example**
Just running the script will return the shortest, longest, and most used password. Also, common passwords such as "password" and "qwerty" will be checked. The file should be a list of passwords. If there are hashes and/or usernames in the list, they should be separated from the passwords by a colon `:` and the password should be the last item on the line.
```bash
┌──(twilson㉿kali)-[~/]
└─$ python PassInspector.py -d dcsync.txt -p cracked.txt

==============================
PassInspector  -  Version 2.3
==============================

Opening DCSync file
Opening cracked passwords file
De-duplicating passwords
Parsing results
Calculating statistics



=============================
========== RESULTS ==========
=============================
Unique passwords cracked:  3502
Total accounts:  5102
Cracked percentage:  18.65 %
Shortest password length (not counting blank passwords):  7
Longest password length:  25
There were 569 account(s) found with blank passwords (some or all of these may be administratively disabled)
There were 1147 password(s) found to contain common terms such as password, welcome, or letmein (59 contained leetspeech)
There were 91 password(s) found to contain seasons of the year (Spring, Summer, Fall, Autumn, Winter)
There were 1546 password(s) found to keyboard walks which are commonly chosen sequential keys on the keyboard such as qwerty, zxc, or asdf
There were 4 account(s) using their username as part of their password



Writing out files
Done!
```

If you want to search for terms related to the organization or similar, add terms with the `-c` option as comma separated words, no spaces.
```bash
┌──(twilson㉿kali)-[~/]
└─$ python PassInspector.py -d dcsync.txt -p cracked.txt -c citrix -np neo4j

==============================
PassInspector  -  Version 2.3
==============================

Successfully connected to Neo4j database
Opening DCSync file
Opening cracked passwords file
De-duplicating passwords
Parsing results
Calculating statistics



=============================
========== RESULTS ==========
=============================
Unique passwords cracked:  3502
Total accounts:  5102
Cracked percentage:  18.65 %
Shortest password length (not counting blank passwords):  7
Longest password length:  25
There were 569 account(s) found with blank passwords (some or all of these may be administratively disabled)
There were 1147 password(s) found to contain common terms such as password, welcome, or letmein (59 contained leetspeech)
There were 91 password(s) found to contain seasons of the year (Spring, Summer, Fall, Autumn, Winter)
There were 1546 password(s) found to keyboard walks which are commonly chosen sequential keys on the keyboard such as qwerty, zxc, or asdf
There were 1 result(s) for the password citrix
There were 4 account(s) using their username as part of their password



Writing out files
Done!
```

## All Options

Parameter | Description
----- | ----- 
-a, --admins | (Optional) File containing administrative users (DOMAIN\USERNAME or USERNAME). BloodHound JSON files are also accepted. Overrides automatic Neo4j queries.
-c, --custom | (Optional) Comma-separated list of custom terms to search for in passwords.
-cs, --cred-stuffing | (Optional) File containing credential stuffing accounts in email:password format. Used if BreachCreds.py is not present.
-csd, --cred-stuffing-domains | (Optional) If BreachCreds.py is present, specify comma-separated domains to search DeHashed for credential stuffing.
-d, --dcsync | (Optional) File containing the output of a DCSync attack (DOMAIN\USER:RID:LMHASH:NTHASH:::).
-db, --debug | (Optional) Enable debug messages.
-dpi, --duplicate-password-identifier | (Optional) Assigns unique identifiers to passwords for detecting reuse without exposing plaintext.
-e, --enabled | (Optional) File containing enabled domain users (DOMAIN\USERNAME or USERNAME). BloodHound JSON, Neo4j CSV, or automatic Neo4j queries are also supported.
-fp, --file-prefix | (Optional) Custom file output prefix (default: timestamp).
-k, --kerberoastable-users | (Optional) File containing Kerberoastable users. Overrides automatic Neo4j queries.
-lh, --local-hashes | (Optional) LSASS dump file to check for local account password reuse.
-nd, --no-dehashed | (Optional) Skip DeHashed search.
-nh, --neo4j-hostname | (Optional) Neo4j hostname or IP (default: localhost).
-nu, --neo4j-username | (Optional) Neo4j username (default: neo4j).
-np, --neo4j-password | (Optional) Neo4j password (required for automatic queries).
-p, --passwords	(Optional) | File containing cracked passwords from Hashtopolis (NTHASH:PASSWORD).
-ph, --prepare-hashes | (Optional) Prepare hashes for Hashtopolis by outputting unique NT hashes, removing accounts with cleartext passwords.
-s, --students | (Optional) File containing students (DOMAIN\USERNAME or USERNAME). BloodHound JSON files are also accepted.
-sp, --spray-passwords | (Optional) File containing password spray lists to match against cracked passwords.
-su, --spray-users | (Optional) File containing usernames that were sprayed to match against cracked users.

## Errors

```
Redirection is not supported
```
Out of the box, PyCharm does not support Curses due to the way script output is formatted. To fix the issue, open your Run configuration, select `Modify options` (top right side of the dialog), and then select `Emulate terminal in the output console`. 
