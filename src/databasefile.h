#ifndef DATABASEFILE_H
#define DATABASEFILE_H

#include <QByteArray>
#include <QString>

// File I/O for the database, used by the unlock and save tasks on pool
// threads. Negative statuses complement the core's SV_* codes.
enum DatabaseFileStatus {
    StatusFileUnreadable = -1,
    StatusTooLarge = -2,
    StatusFileUnwritable = -3,
    StatusFileExists = -4
};

const qint64 MaxDatabaseBytes = 256 * 1024 * 1024;
const qint64 MaxKeyFileBytes = 1024 * 1024;

// Reads at most the size seen at open time into one exact allocation, so a
// file swapped while reading cannot grow the buffer and no partial copies
// are left behind by reallocation.
int readDatabaseFile(const QString &path, qint64 maxBytes, QByteArray &out);

QByteArray fileDigest(const QByteArray &data);

// Replaces the database file without a window in which it is incomplete:
// copies the current file into backupDir (keeping the newest three), writes
// data to a temporary file next to the database, syncs and re-reads it, then
// renames it over the original. A file that no longer matches expectedDigest
// was changed by another program; it is replaced too, its backup is kept
// outside the rotation, and replacedChangedFile reports it.
int writeDatabaseFile(const QString &path, const QByteArray &data, const QString &backupDir,
                      const QByteArray &expectedDigest, bool &replacedChangedFile);

// Writes a new database file that must not exist yet: the data goes to a
// temporary file, is synced and read back, then is linked to path, which
// fails instead of replacing a file that appeared meanwhile.
int createDatabaseFile(const QString &path, const QByteArray &data);

#endif // DATABASEFILE_H
