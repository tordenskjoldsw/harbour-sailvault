#include "vaulttasks.h"

#include <QMetaObject>
#include <QStandardPaths>

#include "corebridge.h"
#include "databasefile.h"
#include "vault.h"

namespace {

// Backups live in the app's private data directory, never next to the
// database, which may be shared or synced.
QString backupDirectory()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        + QStringLiteral("/backups");
}

} // namespace

UnlockTask::UnlockTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
                       const QString &databasePath, const QString &keyFilePath,
                       QByteArray password)
    : m_vault(vault)
    , m_cancelled(std::move(cancelled))
    , m_attempt(attempt)
    , m_databasePath(databasePath)
    , m_keyFilePath(keyFilePath)
    , m_password(std::move(password))
{
}

UnlockTask::~UnlockTask()
{
    secureWipe(m_password);
}

void UnlockTask::run()
{
    SvDatabase *opened = nullptr;
    QByteArray digest;
    const int status = open(&opened, digest);
    CoreDatabase database(opened);
    secureWipe(m_password);

    const bool delivered = !*m_cancelled
        && QMetaObject::invokeMethod(m_vault, "onUnlockFinished", Qt::QueuedConnection,
                                     Q_ARG(int, m_attempt), Q_ARG(int, status),
                                     Q_ARG(qulonglong, reinterpret_cast<qulonglong>(database.get())),
                                     Q_ARG(QByteArray, digest));
    if (delivered)
        database.release();
}

int UnlockTask::open(SvDatabase **database, QByteArray &digest)
{
    QByteArray data;
    int status = readDatabaseFile(m_databasePath, MaxDatabaseBytes, data);
    if (status != SV_OK)
        return status;
    QByteArray keyFile;
    if (!m_keyFilePath.isEmpty()) {
        status = readDatabaseFile(m_keyFilePath, MaxKeyFileBytes, keyFile);
        if (status != SV_OK)
            return status;
    }
    // KDBX distinguishes "no password" from an empty one. Like KeePassXC,
    // an empty field means no password, and a failed attempt is retried
    // with an empty password.
    status = openWith(data, keyFile, !m_password.isEmpty(), database);
    if (status == SV_INVALID_CREDENTIALS && m_password.isEmpty())
        status = openWith(data, keyFile, true, database);
    secureWipe(keyFile);
    // A later save compares the file against this digest to notice
    // changes by other programs.
    if (status == SV_OK)
        digest = fileDigest(data);
    return status;
}

int UnlockTask::openWith(const QByteArray &data, const QByteArray &keyFile, bool hasPassword,
                         SvDatabase **database) const
{
    return sv_database_open(bytePointer(data), static_cast<size_t>(data.size()),
                            bytePointer(m_password), static_cast<size_t>(m_password.size()),
                            hasPassword, bytePointer(keyFile), static_cast<size_t>(keyFile.size()),
                            database);
}

SaveTask::SaveTask(Vault *vault, int attempt, const SvDatabase *database,
                   const QString &databasePath, const QByteArray &expectedDigest)
    : m_vault(vault)
    , m_attempt(attempt)
    , m_database(database)
    , m_databasePath(databasePath)
    , m_expectedDigest(expectedDigest)
{
}

void SaveTask::run()
{
    CoreBytes file;
    int status = sv_database_save(m_database, file.out());
    QByteArray digest;
    bool replacedChangedFile = false;
    if (status == SV_OK) {
        status = writeDatabaseFile(m_databasePath, file.view(), backupDirectory(),
                                   m_expectedDigest, replacedChangedFile);
        digest = fileDigest(file.view());
    }
    QMetaObject::invokeMethod(m_vault, "onSaveFinished", Qt::QueuedConnection,
                              Q_ARG(int, m_attempt), Q_ARG(int, status),
                              Q_ARG(QByteArray, digest), Q_ARG(bool, replacedChangedFile));
}

CreateTask::CreateTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
                       const QString &path, const QString &name, QByteArray password,
                       uint32_t kdfLevel)
    : m_vault(vault)
    , m_cancelled(std::move(cancelled))
    , m_attempt(attempt)
    , m_path(path)
    , m_name(name.toUtf8())
    , m_password(std::move(password))
    , m_kdfLevel(kdfLevel)
{
}

CreateTask::~CreateTask()
{
    secureWipe(m_password);
}

void CreateTask::run()
{
    SvDatabase *created = nullptr;
    CoreBytes file;
    int status = sv_database_create(bytePointer(m_password), static_cast<size_t>(m_password.size()),
                                    bytePointer(m_name), static_cast<size_t>(m_name.size()),
                                    m_kdfLevel, unixSeconds(), &created, file.out());
    CoreDatabase database(created);
    secureWipe(m_password);
    QByteArray digest;
    if (status == SV_OK) {
        status = createDatabaseFile(m_path, file.view());
        digest = fileDigest(file.view());
    }
    if (status != SV_OK)
        database.reset();

    const bool delivered = !*m_cancelled
        && QMetaObject::invokeMethod(m_vault, "onCreateFinished", Qt::QueuedConnection,
                                     Q_ARG(int, m_attempt), Q_ARG(int, status),
                                     Q_ARG(qulonglong, reinterpret_cast<qulonglong>(database.get())),
                                     Q_ARG(QByteArray, digest), Q_ARG(QString, m_path));
    if (delivered)
        database.release();
}
