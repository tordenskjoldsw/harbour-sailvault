#include "databases.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QStandardPaths>

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
