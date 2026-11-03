# Protect a Westbridge private recovery file

`recovery.py` makes a passphrase-encrypted copy of a small private recovery file,
such as authenticator recovery material or an independent MFA encryption key.
It uses the external [age encryption tool](https://github.com/FiloSottile/age)
and Python's standard library. It does not change accounts, reset MFA, open the
runtime database, or manage a password vault.

Keep the passphrase separately from the encrypted file. Losing the passphrase
means this tool cannot recover the contents. Keep the original sheet until
encryption and recovery verification succeed and you have saved the passphrase.

Schema-eight provisioning creates `ACCOUNTS.md` with single-use, 24-hour
enrollment grants. It no longer creates an `ADMIN_MFA_SETUP.md` seed sheet.
Offline issuance creates a new `ENROLLMENT-...md` or `ADMIN_ENROLLMENT...md`
grant sheet. Encrypting and restoring these files neither extends expiry nor
makes a claimed code usable again; they are temporary setup authority, not
long-term authenticator recovery. A historical seed sheet is relevant only to
the unchanged authenticator it originally configured. For a lost factor, use
the [account-specific offline recovery procedure](README.md#enrollment-migration-and-recovery)
after external identity proofing and a durable operator case reference.

## Find the guide in the dashboard

Administrators can open **Security & recovery** from the workspace navigation
to find the local encryption, verification and restoration steps alongside
current-session information and account controls. The recovery section is a
guide: run the commands yourself in a private terminal with Python and age
installed. It does not upload files, collect encryption passphrases, read server
setup sheets, or execute the tool through the website.

The dashboard cannot inspect your local recovery copies or confirm that they
exist. A valid administrator session does not establish that a backup is current
or recoverable. Use the verification procedure below against the copy you intend
to keep.

## Prepare a private terminal and storage

Install age from its [official installation instructions](https://github.com/FiloSottile/age#installation).
The documented Windows package command is:

```powershell
winget install --id FiloSottile.age
```

Review the installer source, then open a fresh terminal if its PATH changed.
Confirm which executable you will run and its version:

```powershell
Get-Command age
age --version
```

Only use a trusted age executable: it receives the file contents. The wrapper
uses `age` from PATH unless you supply `--age-executable` before the subcommand,
for example `recovery.py --age-executable 'C:\Tools\age\age.exe' encrypt ...`.
Use an interactive terminal that is not being recorded or shared. Passphrases
are entered at age's private terminal prompts, never as command arguments.
Choose a **nonempty, strong, unique passphrase** and save it separately. Leaving
age's encryption prompt blank generates a passphrase and displays it in the
terminal; this workflow deliberately avoids that behavior.

Every input and output must be outside the entire source checkout and other
Git working trees. Paths may not use symbolic links, junctions or hard-linked
input files. The output parent must already exist and be private. On POSIX,
input files and their parent directories must be owned by the current user
and inaccessible to other users; use mode 0600 for files and 0700 for parent
directories. The output parent has the same requirement, and new outputs use
mode 0600. On
Windows, first confirm the directory's Security permissions restrict access to
your intended account and trusted system administrators. The tool does not
audit Windows ACLs, and POSIX mode checks do not establish Windows protection.
It refuses existing outputs instead of overwriting them.

## Encrypt and verify on Windows

Run from the repository root with the development Python environment available.
Choose an existing small recovery file in a private directory. The paths below
are placeholders for material you already retained securely; the application
does not create `authenticator-recovery.txt`. Substitute the actual file and a
new output path, and verify the directory permissions first:

```powershell
$recoveryDir = 'C:\Private\WestbridgeRecovery'
$originalSheet = Join-Path $recoveryDir 'authenticator-recovery.txt'
$encryptedSheet = Join-Path $recoveryDir 'authenticator-recovery.txt.age'
.\.venv\Scripts\python.exe -B examples/business_dashboard/recovery.py encrypt $originalSheet --output $encryptedSheet
```

If protecting a newly issued enrollment sheet, use the exact path printed by
the successful issuing command. A failed transaction can leave an unusable
sheet. Reissue or recovery invalidates earlier grants; an old encrypted copy
cannot recover the replacement authority. Never include secrets in filenames.

Age asks for the encryption passphrase and confirmation, then asks for the
passphrase again to decrypt the candidate. The wrapper compares the recovered
bytes with the original in memory **before** creating the encrypted output.
It rereads the original to reject a change made while you entered passphrases.
An encryption or verification failure does not replace the original or create
a successful recovery copy. Check the command's exit status and success message.
Do not pipe encrypted bytes through PowerShell or use shell redirection; the
wrapper writes the binary file itself.

You can repeat the comparison without writing a plaintext file:

```powershell
.\.venv\Scripts\python.exe -B examples/business_dashboard/recovery.py verify $encryptedSheet --original $originalSheet
```

Store the encrypted copy in your chosen private backup location, with the
passphrase kept separately. Verify the copy you intend to retain against the
original before removing that original. This tool never deletes source files.
After successful verification, saved-passphrase confirmation and confirmed
recovery, you may retire an unneeded plaintext recovery copy according to
your storage policy. **Do not remove the live identity key or MFA encryption
key:** the running application still needs them. File deletion is not a promise of secure erasure; backups,
filesystem history and other copies may still contain it.

## Restore when needed

Choose a new file name inside a private existing directory:

```powershell
$restoredSheet = Join-Path $recoveryDir 'authenticator-recovery.restored.txt'
.\.venv\Scripts\python.exe -B examples/business_dashboard/recovery.py restore $encryptedSheet --output $restoredSheet
```

The tool decrypts and authenticates the complete file in memory before creating
the plaintext output. It does not display the recovered contents. Open the
restored sheet only in your trusted private operator session, then protect or
remove that extra plaintext copy when finished. Restoration does not enroll or
reset an authenticator by itself. If the factor changed after this copy was
created, recover the current factor through its trusted backup process or use
the [offline account recovery procedure](README.md#enrollment-migration-and-recovery).
An old grant or seed must not override current account state.

## Hosted recovery and limits

For a hosted installation, use the actual private files from that installation;
your local demo's sheets belong to a different workspace. Run the helper in a
trusted interactive operator terminal with Python and age installed. On POSIX,
use `python examples/business_dashboard/recovery.py` with the same subcommands
and private absolute paths. See [hosting and operator access](HOSTING.md).

The plaintext limit is 1 MiB. This helper is for small recovery sheets, not
database backups. It does not back up SQLite, reconcile sessions, or establish
that a restored database and identity key belong together. Follow the hosting
guide's separate application backup and restore acceptance checks.

For the independent MFA encryption key, preserve its version and database/backup
dependencies and keep its encrypted recovery copy separately from database
bundles. Decrypt into a new private path, compare the unchanged bytes and validate
the matched database/key pair offline before any cutover. Do not replace a lost
key with a new random key to force startup. A restored key decrypts the records
bound to it; it does not reverse revoked access or restore expired enrollment.

File contents exist in Python and age process memory during the operation.
This workflow does not guarantee memory erasure or protect against an already
compromised computer. Keep the original and encrypted files out of source
control, chat, screenshots, support messages and build logs.
