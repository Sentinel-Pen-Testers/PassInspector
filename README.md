# Pass Inspector

## Description
PassInspector is built to parse through a list of cracked passwords to identify patterns that could show a weak password policy. This script is intended to be used on the passwords that have been cracked from the domain's NTDS.dit file using something like a DCsync attack. If Neo4j credentials are supplied, it will automatically pull enabled users, administrative users (only those within the "Administrators", "Domain Admins", and "Enterprise Admins" groups), and Kerberoastable users automatically.

The following items are searched for by PassInspector:
* The shortest password (not including blank passwords)
* The longest password cracked
* Accounts with blank passwords and if any of those accounts are enabled (when enabled accounts are provided)
* Passwords containing common words such as "Password" or "Welcome"
* Passwords containing keyboard walks such as "qwerty" or "asdf"
* Passwords containing seasons of the year
* Custom searched for password terms such as the company name
* Identity password re-use between administrative and non-administrative accounts (when administrative accounts are provided)
* Check if the username contains the password or the password contains the username
* Check if any credential stuffing results are valid (will automatically search DeHashed if BreachCreds.py is in the same directory and a domain or Neo4j credentials are provided)

The two required files are:
* The DCSync file, which should just be pasted in the format returned by SecretsDump (If not provided, it will try to find it)
* The cracked passwords, which should just be pasted in the format output by Hashtopolis (If not provided, it will try to find it)

PassInspector will automatically fix any HEX formatted passwords and identify if LM hashes are stored for any accounts.

When searching for administrative password re-use, it uses the NT hash, so it is not necessary to crack the administrative password to determine if it is re-used.

Three files are output:
* allcracked - This file contains all of the cracked passwords, their username, if the account is enabled (if the file is supplied), and if the account is administrative (if the file is supplied)
* results - These are all the interesting goodies like the shortest passwords, longest passwords, which administrative account(s) share a password with which non-administrative account(s), etc.
* Excel doc - An Excel document will also be output with various columns that can be used to manually investigate results

## To Do
* Output which administrative passwords were cracked

## Installation
`pip install -r requirements.txt`
`python3 PassInspector.py`

## Usage
```bash
python PassInspector.py -d <dcsync file> -p <password-file> [-a <admin-users-file> -c <custom-search-terms> -e <enabled-users-file>]
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
-h | Help dialog
-a | (OPTIONAL) A file containing a list of domain administrative users. The script will check if the passwords for these users are used on other accounts by using hashes. The format should be DOMAIN\USERNAME or USERNAME.
-c | (OPTIONAL) Comma-separated terms you would like searched for, such as the organization's name or acronym in lowercase
-cs | (OPTIONAL) Only required if BreachCreds.py is not in teh same directory. Colon-separated file containing credential stuffing accounts in the format of email:password
-csd | (OPTIONAL) If BreachCreds.py is in the same directory, these comma-separated domains will be used to search DeHashed for credential stuffing credentials
-d | (OPTIONAL) A file containing the output of a DCSync in the format of DOMAIN\USER:RID:LMHASH:NTHASH:::
-dpi | (OPTIONAL) Add a unique identifier for each password, so the customer can identify password reuse without needing the passwords.
-e | (OPTIONAL) A file containing a list of enabled domain users. If specified, it will specify enabled users in the output. The format should be DOMAIN\USERNAME or USERNAME
-fp | (OPTIONAL) File output prefix (if none is provided, datetime will be used instead.)
-k | (OPTIONAL) A file containing all of the Kerberoastable users. Overrides automatic Neo4j queries.
-nd | (OPTIONAL) Skip DeHashed search
-nh | (OPTIONAL) Neo4j hostname or IP (Default: localhost)
-nu | (OPTIONAL) Neo4j username for automatic queries (Default: neo4j)
-np | (OPTIONAL) Neo4j password for automatic queries. Must be specified for automatic queries to be attempted.
-p | (OPTIONAL) A file containing all of the cracked passwords from Hashtopolis in the form of NTHASH:PASSWORD
-ph | (OPTIONAL) Prepare hashes for cracking on Hashtopolis. A list of unique NT hashes will be output, with any accounts that have a cleartext password removed.
-s | (OPTIONAL) A file containing a list of students. Can be a BH JSON export, Neo4J CSV export, or a txt file with one username per line.
-su | (OPTIONAL) Match cracked users to list of usernames that will be sprayed.
-sp | (OPTIONAL) Match cracked passwords to passwords in the spray list.

## Errors

```
Redirection is not supported
```
Out of the box, PyCharm does not support Curses due to the way script output is formatted. To fix the issue, open your Run configuration, select `Modify options` (top right side of the dialog), and then select `Emulate terminal in the output console`. 
