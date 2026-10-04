#include "databasefile.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QStringList>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sailvault_core.h"
#include "corebridge.h"

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

bool writeAll(int fd, const QByteArray &data)
{
    qint64 done = 0;
    while (done < data.size()) {
        const ssize_t length = ::write(fd, data.constData() + done,
                                       static_cast<size_t>(data.size() - done));
        if (length < 0 && errno == EINTR)
            continue;
        if (length <= 0)
            return false;
        done += length;
    }
    return true;
}

// Reads the file back from the start and compares it with data; one byte more
// is requested to notice a longer file. The copy may hold a key file and is
// wiped.
bool readsBackAs(int fd, const QByteArray &data)
{
    QByteArray readBack(data.size() + 1, Qt::Uninitialized);
    qint64 done = 0;
    while (done < readBack.size()) {
        const ssize_t length = ::pread(fd, readBack.data() + done,
                                       static_cast<size_t>(readBack.size() - done), done);
        if (length < 0 && errno == EINTR)
            continue;
        if (length <= 0)
            break;
        done += length;
    }
    const bool same = done == data.size() && ::memcmp(readBack.constData(), data.constData(),
                                                      static_cast<size_t>(data.size())) == 0;
    secureWipe(readBack);
    return same;
}

// Writes data to a new temporary file and reads it back through the same
// descriptor. POSIX calls keep QFile's buffers from holding unwiped copies.
// A leftover file or a symlink another app planted at tempPath is removed
// first, and O_EXCL | O_NOFOLLOW refuses anything that appears there in
// between, so the write never follows a link.
bool writeTemporary(const QString &tempPath, mode_t mode, const QByteArray &data)
{
    const QByteArray name = QFile::encodeName(tempPath);
    if (::unlink(name.constData()) != 0 && errno != ENOENT)
        return false;
    const int fd = ::open(name.constData(), O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                          mode);
    if (fd < 0)
        return false;
    const bool written = ::fchmod(fd, mode) == 0 && writeAll(fd, data) && ::fsync(fd) == 0
        && readsBackAs(fd, data);
    return ::close(fd) == 0 && written;
}

// Exactly this database's backups: a wildcard would also match those of
// "Work-old" for "Work".
QRegularExpression backupPattern(const QString &databasePath, bool withChangedElsewhere)
{
    const QString base = QFileInfo(databasePath).completeBaseName();
    return QRegularExpression(QStringLiteral("^%1-\\d{8}-\\d{6}-\\d{3}%2\\.kdbx$")
                                  .arg(QRegularExpression::escape(base),
                                       withChangedElsewhere ? QStringLiteral("(-changed-elsewhere)?")
                                                            : QString()));
}

// Backups are named after the database with a UTC timestamp, so sorting by
// name sorts by age. A version another program wrote is replaced without a
// merge, so its backup is marked and stays out of the rotation.
bool backUp(const QString &databasePath, const QByteArray &current, const QString &backupDir,
            bool changedElsewhere)
{
    QDir dir(backupDir);
    if (!dir.mkpath(QStringLiteral(".")))
        return false;
    const QString base = QFileInfo(databasePath).completeBaseName();
    const QString stamp = QDateTime::currentDateTimeUtc().toString(QStringLiteral("yyyyMMdd-HHmmss-zzz"));
    const QString suffix = changedElsewhere ? QStringLiteral("-changed-elsewhere.kdbx")
                                            : QStringLiteral(".kdbx");
    QFile backup(dir.filePath(base + QLatin1Char('-') + stamp + suffix));
    if (!backup.open(QIODevice::WriteOnly | QIODevice::Truncate) || !writeAndSync(backup, current))
        return false;
    backup.setPermissions(QFile::ReadOwner | QFile::WriteOwner);

    QStringList backups = dir.entryList(QDir::Files, QDir::Name)
                              .filter(backupPattern(databasePath, false));
    while (backups.size() > BackupsToKeep)
        dir.remove(backups.takeFirst());
    return syncDirectory(backupDir);
}

// Only regular files are read: a FIFO planted under a picked name would
// block, and O_NONBLOCK keeps the open itself from blocking on one.
int openRegularFile(const QString &path, struct stat &info)
{
    const int fd = ::open(QFile::encodeName(path).constData(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0 && (::fstat(fd, &info) != 0 || !S_ISREG(info.st_mode))) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool readFully(int fd, char *data, qint64 length)
{
    qint64 done = 0;
    while (done < length) {
        const ssize_t read = ::read(fd, data + done, static_cast<size_t>(length - done));
        if (read < 0 && errno == EINTR)
            continue;
        if (read <= 0)
            return false;
        done += read;
    }
    return true;
}

} // namespace

// POSIX calls instead of QFile, whose read buffer keeps an unwiped copy of
// small files such as key files.
int readBoundedFile(const QString &path, qint64 maxBytes, QByteArray &out)
{
    struct stat info;
    const int fd = openRegularFile(path, info);
    if (fd < 0)
        return StatusFileUnreadable;
    int status = SV_OK;
    if (info.st_size > maxBytes) {
        status = StatusTooLarge;
    } else {
        out = QByteArray(static_cast<int>(info.st_size), Qt::Uninitialized);
        if (!readFully(fd, out.data(), info.st_size)) {
            secureWipe(out);
            status = StatusFileUnreadable;
        }
    }
    ::close(fd);
    return status;
}

int readFileStart(const QString &path, int length, QByteArray &out)
{
    struct stat info;
    const int fd = openRegularFile(path, info);
    if (fd < 0)
        return StatusFileUnreadable;
    out = QByteArray(static_cast<int>(qMin<qint64>(length, info.st_size)), Qt::Uninitialized);
    const bool read = readFully(fd, out.data(), out.size());
    ::close(fd);
    if (!read) {
        out.clear();
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
    const int status = readBoundedFile(path, MaxDatabaseBytes, current);
    if (status != SV_OK)
        return status;
    replacedChangedFile = fileDigest(current) != expectedDigest;
    if (!backUp(path, current, backupDir, replacedChangedFile))
        return StatusFileUnwritable;

    // The replacement keeps the database file's permissions.
    struct stat info;
    if (::stat(QFile::encodeName(path).constData(), &info) != 0)
        return StatusFileUnwritable;
    const QString tempPath = path + QStringLiteral(".sailvault-tmp");
    if (!writeTemporary(tempPath, info.st_mode & 0777, data)
        || ::rename(QFile::encodeName(tempPath).constData(),
                    QFile::encodeName(path).constData()) != 0) {
        QFile::remove(tempPath);
        return StatusFileUnwritable;
    }
    // The file holds the new content once renamed. A failed directory sync
    // only leaves the rename less durable; reporting a failure would keep
    // the old digest and flag the next save as a change by another program.
    syncDirectory(QFileInfo(path).absolutePath());
    return SV_OK;
}

int createNewFile(const QString &path, const QByteArray &data)
{
    const QByteArray name = QFile::encodeName(path);
    if (::access(name.constData(), F_OK) == 0)
        return StatusFileExists;
    const QString tempPath = path + QStringLiteral(".sailvault-tmp");
    const QByteArray tempName = QFile::encodeName(tempPath);
    if (!writeTemporary(tempPath, S_IRUSR | S_IWUSR, data)) {
        ::unlink(tempName.constData());
        return StatusFileUnwritable;
    }
    const int linked = ::link(tempName.constData(), name.constData());
    const int linkError = errno;
    ::unlink(tempName.constData());
    if (linked != 0)
        return linkError == EEXIST ? StatusFileExists : StatusFileUnwritable;
    // As after a rename: the file exists now, and a retry would only find it.
    syncDirectory(QFileInfo(path).absolutePath());
    return SV_OK;
}

bool removeBackups(const QString &databasePath, const QString &backupDir)
{
    QDir dir(backupDir);
    bool removed = true;
    const QStringList backups = dir.entryList(QDir::Files).filter(backupPattern(databasePath, true));
    for (const QString &backup : backups)
        removed = dir.remove(backup) && removed;
    return removed;
}
