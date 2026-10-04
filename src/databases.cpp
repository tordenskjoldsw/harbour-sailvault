#include "databases.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

#include "corebridge.h"
#include "databasefile.h"
#include "sailvault_core.h"

namespace {

const QString DatabaseSuffix = QStringLiteral(".kdbx");
const QString KeyFileSuffix = QStringLiteral(".key");

QString dataDirectory(const QString &name)
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + QLatin1Char('/')
        + name;
}

QString databaseDirectory()
{
    return dataDirectory(QStringLiteral("databases"));
}

QString keyFileDirectory()
{
    return dataDirectory(QStringLiteral("keyfiles"));
}

QString copyKeyFilePath(const QString &copyPath)
{
    return copyPath.left(copyPath.size() - DatabaseSuffix.size()) + KeyFileSuffix;
}

int copyFile(const QString &from, const QString &to, qint64 maxBytes)
{
    QByteArray data;
    int status = readBoundedFile(from, maxBytes, data);
    if (status == SV_OK)
        status = createNewFile(to, data);
    secureWipe(data);
    return status;
}

bool makePrivateDirectory(const QString &path)
{
    return QDir().mkpath(path)
        && QFile::setPermissions(path, QFile::ReadOwner | QFile::WriteOwner | QFile::ExeOwner);
}

} // namespace

Databases::Databases(QObject *parent)
    : QObject(parent)
{
}

QString Databases::databasePath(const QString &name)
{
    return isValidName(name) ? databaseDirectory() + QLatin1Char('/') + name + DatabaseSuffix
                             : QString();
}

QString Databases::keyFilePath(const QString &name)
{
    return isValidName(name) ? keyFileDirectory() + QLatin1Char('/') + name + KeyFileSuffix
                             : QString();
}

QString Databases::backupDirectory()
{
    return dataDirectory(QStringLiteral("backups"));
}

int Databases::claim(const QString &name)
{
    if (!isValidName(name))
        return StatusFileUnwritable;
    if (!makePrivateDirectory(databaseDirectory()) || !makePrivateDirectory(keyFileDirectory()))
        return StatusFileUnwritable;
    if (exists(name))
        return StatusFileExists;
    const QString keyFile = keyFilePath(name);
    if (QFileInfo::exists(keyFile) && !QFile::remove(keyFile))
        return StatusFileUnwritable;
    return SV_OK;
}

bool Databases::isValidName(const QString &name)
{
    return !name.isEmpty() && name.size() <= 100 && name == name.trimmed()
        && !name.startsWith(QLatin1Char('.')) && !name.contains(QLatin1Char('/'))
        && !name.contains(QChar::Null);
}

bool Databases::exists(const QString &name)
{
    return isValidName(name) && QFileInfo::exists(databasePath(name));
}

bool Databases::hasKeyFile(const QString &name)
{
    return isValidName(name) && QFileInfo::exists(keyFilePath(name));
}

QStringList Databases::names()
{
    QStringList result;
    const QStringList files = QDir(databaseDirectory())
                                  .entryList(QStringList(QLatin1Char('*') + DatabaseSuffix),
                                             QDir::Files, QDir::Name | QDir::IgnoreCase);
    for (const QString &file : files) {
        const QString name = file.left(file.size() - DatabaseSuffix.size());
        if (isValidName(name))
            result.append(name);
    }
    return result;
}

QString Databases::copyPath(int location, const QString &fileName)
{
    if (!isValidName(fileName))
        return QString();
    const QString folder = QStandardPaths::writableLocation(
        location == Downloads ? QStandardPaths::DownloadLocation
                              : QStandardPaths::DocumentsLocation);
    return folder + QLatin1Char('/') + fileName + DatabaseSuffix;
}

bool Databases::copyExists(int location, const QString &fileName, bool withKeyFile)
{
    const QString path = copyPath(location, fileName);
    return !path.isEmpty()
        && (QFileInfo::exists(path) || (withKeyFile && QFileInfo::exists(copyKeyFilePath(path))));
}

Databases::CopyResult Databases::saveCopy(const QString &name, int location,
                                          const QString &fileName, bool withKeyFile)
{
    const QString path = copyPath(location, fileName);
    if (!exists(name) || path.isEmpty() || (withKeyFile && !hasKeyFile(name)))
        return CopyFailed;
    if (copyExists(location, fileName, withKeyFile))
        return CopyExists;
    int status = copyFile(databasePath(name), path, MaxDatabaseBytes);
    // Half a copy is no use: a database without the key file it was saved
    // with cannot be opened.
    if (status == SV_OK && withKeyFile) {
        status = copyFile(keyFilePath(name), copyKeyFilePath(path), MaxKeyFileBytes);
        if (status != SV_OK)
            QFile::remove(path);
    }
    switch (status) {
    case SV_OK:
        return CopySaved;
    case StatusFileExists:
        return CopyExists;
    default:
        return CopyFailed;
    }
}
