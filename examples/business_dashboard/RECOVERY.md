# Protect a Westbridge recovery sheet

`recovery.py` makes a passphrase-encrypted copy of a small private recovery file,
such as `ADMIN_MFA_SETUP.md`. It uses the external [age encryption tool](https://github.com/FiloSottile/age)
and Python's standard library. It does not change accounts, reset MFA, open the
runtime database, or manage a password vault.

Keep the passphrase separately from the encrypted file. Losing the passphrase
means this tool cannot recover the contents. Keep the original sheet until
encryption and recovery verification succeed and you have saved the passphrase.

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
For the default, already provisioned local workspace:

```powershell
$recoveryDir = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'radt-business-demo'
$originalSheet = Join-Path $recoveryDir 'ADMIN_MFA_SETUP.md'
$encryptedSheet = Join-Path $recoveryDir 'ADMIN_MFA_SETUP.md.age'
.\.venv\Scripts\python.exe -B examples/business_dashboard/recovery.py encrypt $originalSheet --output $encryptedSheet
```

If you provisioned another directory or reset MFA, use the actual private sheet
path printed by that successful operation. A reset can produce a suffixed file
name; an older sheet does not recover the replacement authenticator.

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
After successful verification, saved-passphrase confirmation and authenticator
enrollment, you may manually remove the plaintext setup sheet according to
your storage policy. File deletion is not a promise of secure erasure; backups,
filesystem history and other copies may still contain it.

## Restore when needed

Choose a new file name inside a private existing directory:

```powershell
$restoredSheet = Join-Path $recoveryDir 'ADMIN_MFA_SETUP.restored.md'
.\.venv\Scripts\python.exe -B examples/business_dashboard/recovery.py restore $encryptedSheet --output $restoredSheet
```

The tool decrypts and authenticates the complete file in memory before creating
the plaintext output. It does not display the recovered contents. Open the
restored sheet only in your trusted private operator session, then protect or
remove that extra plaintext copy when finished. Restoration does not enroll or
reset an authenticator by itself. If MFA was reset after this backup, use the
current setup sheet or the [trusted operator reset procedure](README.md).

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

File contents exist in Python and age process memory during the operation.
This workflow does not guarantee memory erasure or protect against an already
compromised computer. Keep the original and encrypted files out of source
control, chat, screenshots, support messages and build logs.
