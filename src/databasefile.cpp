#include "databasefile.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStringList>

#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

#include "sailvault_core.h"
#include "secure.h"

namespace {

const int BackupsToKeep = 3;

bool writeAndSync(QFile &file, const QByteArray &data)
{
    if (file.write(data) != data.size() || !file.flush() || ::fsync(file.handle()) != 0)
        return false;
    file.close();
    return file.error() == QFile::NoError;
}

// Makes a rename or a new file durable: the directory entry is synced too.
bool syncDirectory(const QString &path)
{
    const int fd = ::open(QFile::encodeName(path).constData(), O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return false;
    const bool synced = ::fsync(fd) == 0;
    ::close(fd);
    return synced;
}

// Backups are named after the database with a UTC timestamp, so sorting by
// name sorts by age.
bool backUp(const QString &databasePath, const QByteArray &current, const QString &backupDir)
{
    QDir dir(backupDir);
    if (!dir.mkpath(QStringLiteral(".")))
        return false;
    const QString base = QFileInfo(databasePath).completeBaseName();
    const QString stamp = QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss-zzz"));
    QFile backup(dir.filePath(base + QLatin1Char('-') + stamp + QStringLiteral(".kdbx")));
    if (!backup.open(QIODevice::WriteOnly | QIODevice::Truncate) || !writeAndSync(backup, current))
        return false;
    backup.setPermissions(QFile::ReadOwner | QFile::WriteOwner);

    QStringList backups = dir.entryList(QStringList(base + QStringLiteral("-*.kdbx")),
                                        QDir::Files, QDir::Name);
    while (backups.size() > BackupsToKeep)
        dir.remove(backups.takeFirst());
    return syncDirectory(backupDir);
}

} // namespace

int readDatabaseFile(const QString &path, qint64 maxBytes, QByteArray &out)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return StatusFileUnreadable;
    const qint64 size = file.size();
    if (size > maxBytes)
        return StatusTooLarge;
    out = QByteArray(static_cast<int>(size), Qt::Uninitialized);
    if (size > 0 && file.read(out.data(), size) != size) {
        secureWipe(out);
        return StatusFileUnreadable;
    }
    return SV_OK;
}

QByteArray fileDigest(const QByteArray &data)
{
    return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
}

int writeDatabaseFile(const QString &path, const QByteArray &data, const QString &backupDir,
                      const QByteArray &expectedDigest, bool &replacedChangedFile)
{
    QByteArray current;
    const int status = readDatabaseFile(path, MaxDatabaseBytes, current);
    if (status != SV_OK)
        return status;
    replacedChangedFile = fileDigest(current) != expectedDigest;
    if (!backUp(path, current, backupDir))
        return StatusFileUnwritable;

    const QString tempPath = path + QStringLiteral(".sailvault-tmp");
    QFile temp(tempPath);
    QByteArray readBack;
    const bool written = temp.open(QIODevice::WriteOnly | QIODevice::Truncate)
        && writeAndSync(temp, data)
        && temp.setPermissions(QFile(path).permissions())
        && readDatabaseFile(tempPath, MaxDatabaseBytes, readBack) == SV_OK
        && readBack == data;
    if (!written
        || ::rename(QFile::encodeName(tempPath).constData(),
                    QFile::encodeName(path).constData()) != 0) {
        QFile::remove(tempPath);
        return StatusFileUnwritable;
    }
    if (!syncDirectory(QFileInfo(path).absolutePath()))
        return StatusFileUnwritable;
    return SV_OK;
}
