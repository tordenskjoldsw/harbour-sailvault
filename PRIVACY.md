# Privacy policy

SailVault is a password manager for Sailfish OS. This policy describes what
the app does with your data. It applies to SailVault 0.5 and later.

## What SailVault collects

Nothing. SailVault has no analytics, no crash reporting, no advertising and
no account. It never sends data to the developer or to any third party.

## Where your data is stored

- Your databases and key files are stored on your phone, in SailVault's
  private app directory, which other sandboxed apps cannot read. The
  databases are encrypted with your master password; key files are stored
  as they are.
- The app keeps the last three versions of a database as encrypted
  backups in the same directory.
- The settings file holds the name of the database you opened last and,
  if you set up sync, the time and file fingerprints (ETag and SHA-256) of
  the last sync, and a fingerprint of the sync settings you confirmed. It
  holds no passwords.
- When you save a copy, it goes to the folder you choose (Documents or
  Downloads), encrypted like the database.

## Network access

SailVault connects to nothing but your own Nextcloud server, and only
after you set up sync for a database. It then uploads and downloads that
database file, encrypted, and nothing else. The address of the server, the
user name and the Nextcloud app password are stored inside your encrypted
database. Your Nextcloud provider's privacy policy applies to the data on
that server.

To set up sync with the browser login, SailVault opens your Nextcloud's
login page in the Sailfish browser.

## Permissions

- **Documents and Downloads:** to add existing databases and key files,
  save copies and read Bitwarden exports that you pick.
- **Internet:** only for the Nextcloud sync you set up.

## Contact

Questions about privacy: open an issue at
https://github.com/tordenskjoldsw/harbour-sailvault/issues. For security
reports, see [SECURITY.md](SECURITY.md).
