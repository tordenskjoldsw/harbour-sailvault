#include "vaulttasks.h"

#include <QFile>
#include <QMetaObject>

#include "corebridge.h"
#include "databasefile.h"
#include "databases.h"
#include "vault.h"

namespace {

int openWith(const QByteArray &data, const QByteArray &keyFile, const QByteArray &password,
             bool hasPassword, SvDatabase **database)
{
    return sv_database_open(bytePointer(data), static_cast<size_t>(data.size()),
                            bytePointer(password), static_cast<size_t>(password.size()),
                            hasPassword, bytePointer(keyFile), static_cast<size_t>(keyFile.size()),
                            database);
}

// Reads the database and the key file, if there is one, and runs the KDF.
// The caller wipes keyFile.
int readAndOpen(const QString &databasePath, const QString &keyFilePath,
                const QByteArray &password, SvDatabase **database, QByteArray &data,
                QByteArray &keyFile)
{
    int status = readBoundedFile(databasePath, MaxDatabaseBytes, data);
    if (status == SV_OK && !keyFilePath.isEmpty())
        status = readBoundedFile(keyFilePath, MaxKeyFileBytes, keyFile);
    if (status != SV_OK)
        return status;
    // KDBX distinguishes "no password" from an empty one. Like KeePassXC,
    // an empty field means no password, and a failed attempt is retried
    // with an empty password.
    status = openWith(data, keyFile, password, !password.isEmpty(), database);
    if (status == SV_INVALID_CREDENTIALS && password.isEmpty())
        status = openWith(data, keyFile, password, true, database);
    return status;
}

// Hands the unlocked handle to the vault, or frees it when the result is no
// longer wanted. A later save compares the file against digest to notice
// changes by other programs.
void deliver(Vault *vault, const std::atomic_bool &cancelled, int attempt, int status,
             CoreDatabase database, const QByteArray &digest)
{
    if (status != SV_OK)
        database.reset();
    const bool delivered = !cancelled
        && QMetaObject::invokeMethod(vault, "onUnlockFinished", Qt::QueuedConnection,
                                     Q_ARG(int, attempt), Q_ARG(int, status),
                                     Q_ARG(qulonglong, reinterpret_cast<qulonglong>(database.get())),
                                     Q_ARG(QByteArray, status == SV_OK ? digest : QByteArray()));
    if (delivered)
        database.release();
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
    QByteArray data;
    QByteArray keyFile;
    const int status = readAndOpen(m_databasePath, m_keyFilePath, m_password, &opened, data,
                                   keyFile);
    CoreDatabase database(opened);
    secureWipe(m_password);
    secureWipe(keyFile);
    deliver(m_vault, *m_cancelled, m_attempt, status, std::move(database), fileDigest(data));
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
        status = writeDatabaseFile(m_databasePath, file.view(), Databases::backupDirectory(),
                                   m_expectedDigest, replacedChangedFile);
        digest = fileDigest(file.view());
    }
    QMetaObject::invokeMethod(m_vault, "onSaveFinished", Qt::QueuedConnection,
                              Q_ARG(int, m_attempt), Q_ARG(int, status),
                              Q_ARG(QByteArray, digest), Q_ARG(bool, replacedChangedFile));
}

MergeTask::MergeTask(Vault *vault, int attempt, const SvDatabase *database, const QString &path,
                     QByteArray password, const QString &keyFilePath)
    : m_vault(vault)
    , m_attempt(attempt)
    , m_database(database)
    , m_path(path)
    , m_password(std::move(password))
    , m_keyFilePath(keyFilePath)
{
}

MergeTask::~MergeTask()
{
    secureWipe(m_password);
}

void MergeTask::run()
{
    SvDatabase *opened = nullptr;
    QByteArray data;
    int status;
    if (m_password.isEmpty()) {
        status = readBoundedFile(m_path, MaxDatabaseBytes, data);
        if (status == SV_OK)
            status = sv_database_open_like(m_database, bytePointer(data),
                                           static_cast<size_t>(data.size()), &opened);
    } else {
        QByteArray keyFile;
        status = readAndOpen(m_path, m_keyFilePath, m_password, &opened, data, keyFile);
        secureWipe(keyFile);
    }
    CoreDatabase database(opened);
    secureWipe(m_password);
    // The vault waits for this result before it locks, so delivery cannot
    // fail; a database that is no longer wanted is freed by the slot.
    if (QMetaObject::invokeMethod(m_vault, "onMergeOpened", Qt::QueuedConnection,
                                  Q_ARG(int, m_attempt), Q_ARG(int, status),
                                  Q_ARG(qulonglong, reinterpret_cast<qulonglong>(database.get()))))
        database.release();
}

AddTask::AddTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
                 const QString &databasePath, const QString &keyFilePath, const QString &name,
                 QByteArray password, uint32_t kdfLevel)
    : m_vault(vault)
    , m_cancelled(std::move(cancelled))
    , m_attempt(attempt)
    , m_databasePath(databasePath)
    , m_keyFilePath(keyFilePath)
    , m_name(name)
    , m_password(std::move(password))
    , m_kdfLevel(kdfLevel)
{
}

AddTask::~AddTask()
{
    secureWipe(m_password);
}

void AddTask::run()
{
    SvDatabase *opened = nullptr;
    QByteArray data;
    QByteArray keyFile;
    int status = readAndOpen(m_databasePath, m_keyFilePath, m_password, &opened, data, keyFile);
    CoreDatabase database(opened);
    secureWipe(m_password);
    bool fromKdbx3 = false;
    if (status == SV_OK)
        status = sv_database_from_kdbx3(database.get(), &fromKdbx3);
    CoreBytes converted;
    if (status == SV_OK && fromKdbx3) {
        status = sv_database_set_kdf_level(database.get(), m_kdfLevel);
        if (status == SV_OK)
            status = sv_database_save(database.get(), converted.out());
    }
    const QByteArray file = fromKdbx3 ? converted.view() : data;
    // Only a database the credentials open is stored, together with the key
    // file that opened it. The key file goes first: a database without it
    // could not be opened, a leftover key file is removed by the next claim.
    if (status == SV_OK)
        status = Databases::claim(m_name);
    if (status == SV_OK && !keyFile.isEmpty())
        status = createNewFile(Databases::keyFilePath(m_name), keyFile);
    secureWipe(keyFile);
    if (status == SV_OK)
        status = createNewFile(Databases::databasePath(m_name), file);
    deliver(m_vault, *m_cancelled, m_attempt, status, std::move(database), fileDigest(file));
}

CreateTask::CreateTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
                       const QString &name, QByteArray password, uint32_t kdfLevel)
    : m_vault(vault)
    , m_cancelled(std::move(cancelled))
    , m_attempt(attempt)
    , m_name(name)
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
    const QByteArray name = m_name.toUtf8();
    int status = sv_database_create(bytePointer(m_password), static_cast<size_t>(m_password.size()),
                                    bytePointer(name), static_cast<size_t>(name.size()),
                                    m_kdfLevel, unixSeconds(), &created, file.out());
    CoreDatabase database(created);
    secureWipe(m_password);
    if (status == SV_OK)
        status = Databases::claim(m_name);
    if (status == SV_OK)
        status = createNewFile(Databases::databasePath(m_name), file.view());
    deliver(m_vault, *m_cancelled, m_attempt, status, std::move(database),
            fileDigest(file.view()));
}
