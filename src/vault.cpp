#include "vault.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDateTime>
#include <QEvent>
#include <QFileInfo>
#include <QGuiApplication>
#include <QRunnable>
#include <QSettings>
#include <QStandardPaths>
#include <QThreadPool>
#include <QVector>

#include "boottime.h"
#include "databasefile.h"
#include "secure.h"

namespace {

const long long IdleLockMs = 5 * 60 * 1000;
const long long BackgroundLockMs = 60 * 1000;
// Bounds how late a deadline is enforced after the phone wakes up.
const int WatchdogIntervalMs = 5 * 1000;

QString settingsPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        + QStringLiteral("/settings.ini");
}

// Backups live in the app's private data directory, never next to the
// database, which may be shared or synced.
QString backupDirectory()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
        + QStringLiteral("/backups");
}

// Reads the files and runs the KDF on a pool thread, then hands the result
// to the vault on its own thread. A cancelled task frees its result itself.
class UnlockTask : public QRunnable
{
public:
    UnlockTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
               const QString &databasePath, const QString &keyFilePath,
               const QByteArray &password)
        : m_vault(vault)
        , m_cancelled(std::move(cancelled))
        , m_attempt(attempt)
        , m_databasePath(databasePath)
        , m_keyFilePath(keyFilePath)
        , m_password(password)
    {
    }

    ~UnlockTask() override
    {
        secureWipe(m_password);
    }

    void run() override
    {
        SvDatabase *database = nullptr;
        QByteArray digest;
        const int status = open(&database, digest);
        secureWipe(m_password);

        const bool delivered = !*m_cancelled
            && QMetaObject::invokeMethod(m_vault, "onUnlockFinished", Qt::QueuedConnection,
                                         Q_ARG(int, m_attempt), Q_ARG(int, status),
                                         Q_ARG(qulonglong, reinterpret_cast<qulonglong>(database)),
                                         Q_ARG(QByteArray, digest));
        if (!delivered)
            sv_database_free(database);
    }

private:
    int open(SvDatabase **database, QByteArray &digest)
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

    int openWith(const QByteArray &data, const QByteArray &keyFile, bool hasPassword,
                 SvDatabase **database) const
    {
        return sv_database_open(reinterpret_cast<const uint8_t *>(data.constData()),
                                static_cast<size_t>(data.size()),
                                reinterpret_cast<const uint8_t *>(m_password.constData()),
                                static_cast<size_t>(m_password.size()), hasPassword,
                                reinterpret_cast<const uint8_t *>(keyFile.constData()),
                                static_cast<size_t>(keyFile.size()), database);
    }

    // The vault outlives every task: its destructor cancels and waits for
    // the pool before it is destroyed.
    Vault *m_vault;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_databasePath;
    QString m_keyFilePath;
    QByteArray m_password;
};

// Serializes the database, which runs the KDF, and replaces the file on a
// pool thread. The vault keeps the handle alive and read-only until the
// result arrives.
class SaveTask : public QRunnable
{
public:
    SaveTask(Vault *vault, int attempt, const SvDatabase *database, const QString &databasePath,
             const QByteArray &expectedDigest)
        : m_vault(vault)
        , m_attempt(attempt)
        , m_database(database)
        , m_databasePath(databasePath)
        , m_expectedDigest(expectedDigest)
    {
    }

    void run() override
    {
        SvBytes file;
        file.data = nullptr;
        file.length = 0;
        int status = sv_database_save(m_database, &file);
        QByteArray digest;
        bool replacedChangedFile = false;
        if (status == SV_OK) {
            const QByteArray data = QByteArray::fromRawData(
                reinterpret_cast<const char *>(file.data), static_cast<int>(file.length));
            status = writeDatabaseFile(m_databasePath, data, backupDirectory(), m_expectedDigest,
                                       replacedChangedFile);
            digest = fileDigest(data);
        }
        sv_bytes_free(file);
        QMetaObject::invokeMethod(m_vault, "onSaveFinished", Qt::QueuedConnection,
                                  Q_ARG(int, m_attempt), Q_ARG(int, status),
                                  Q_ARG(QByteArray, digest), Q_ARG(bool, replacedChangedFile));
    }

private:
    Vault *m_vault;
    int m_attempt;
    const SvDatabase *m_database;
    QString m_databasePath;
    QByteArray m_expectedDigest;
};

// Creates the database and its file on a pool thread, then hands the
// unlocked handle to the vault like an unlock does.
class CreateTask : public QRunnable
{
public:
    CreateTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
               const QString &path, const QString &name, const QByteArray &password,
               uint32_t kdfLevel)
        : m_vault(vault)
        , m_cancelled(std::move(cancelled))
        , m_attempt(attempt)
        , m_path(path)
        , m_name(name.toUtf8())
        , m_password(password)
        , m_kdfLevel(kdfLevel)
    {
    }

    ~CreateTask() override
    {
        secureWipe(m_password);
    }

    void run() override
    {
        SvDatabase *database = nullptr;
        SvBytes file;
        file.data = nullptr;
        file.length = 0;
        int status = sv_database_create(
            reinterpret_cast<const uint8_t *>(m_password.constData()),
            static_cast<size_t>(m_password.size()),
            reinterpret_cast<const uint8_t *>(m_name.constData()),
            static_cast<size_t>(m_name.size()), m_kdfLevel,
            QDateTime::currentMSecsSinceEpoch() / 1000, &database, &file);
        secureWipe(m_password);
        QByteArray digest;
        if (status == SV_OK) {
            const QByteArray data = QByteArray::fromRawData(
                reinterpret_cast<const char *>(file.data), static_cast<int>(file.length));
            status = createDatabaseFile(m_path, data);
            digest = fileDigest(data);
        }
        sv_bytes_free(file);
        if (status != SV_OK) {
            sv_database_free(database);
            database = nullptr;
        }

        const bool delivered = !*m_cancelled
            && QMetaObject::invokeMethod(m_vault, "onCreateFinished", Qt::QueuedConnection,
                                         Q_ARG(int, m_attempt), Q_ARG(int, status),
                                         Q_ARG(qulonglong, reinterpret_cast<qulonglong>(database)),
                                         Q_ARG(QByteArray, digest), Q_ARG(QString, m_path));
        if (!delivered)
            sv_database_free(database);
    }

private:
    Vault *m_vault;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_path;
    QByteArray m_name;
    QByteArray m_password;
    uint32_t m_kdfLevel;
};

Vault::Error errorFor(int status)
{
    switch (status) {
    case SV_OK:
        return Vault::NoError;
    case SV_INVALID_CREDENTIALS:
        return Vault::WrongCredentials;
    case SV_INVALID_KEY_FILE:
        return Vault::InvalidKeyFile;
    case SV_KDBX3_UNSUPPORTED:
        return Vault::Kdbx3Unsupported;
    case SV_NOT_KDBX:
        return Vault::NotKdbx;
    case SV_UNSUPPORTED_FORMAT:
        return Vault::UnsupportedFormat;
    case SV_LIMIT_EXCEEDED:
    case StatusTooLarge:
        return Vault::TooLarge;
    case StatusFileUnreadable:
        return Vault::FileUnreadable;
    case StatusFileUnwritable:
        return Vault::FileUnwritable;
    case StatusFileExists:
        return Vault::FileExists;
    case SV_WRITE_FAILED:
    case SV_RANDOM_UNAVAILABLE:
        return Vault::SaveFailed;
    default:
        return Vault::Corrupted;
    }
}

QByteArray itemUuid(const QString &itemId)
{
    const QByteArray uuid = QByteArray::fromHex(itemId.toLatin1());
    return uuid.size() == SV_UUID_LENGTH ? uuid : QByteArray();
}

const uint8_t *bytePointer(const QByteArray &bytes)
{
    return reinterpret_cast<const uint8_t *>(bytes.constData());
}

uint32_t characterClass(bool selected, int flag)
{
    return selected ? static_cast<uint32_t>(flag) : 0u;
}

qint64 unixSeconds()
{
    return QDateTime::currentMSecsSinceEpoch() / 1000;
}

// UTF-8 copies of entry fields for the core, wiped when they go out of
// scope. The map's own QString copies cannot be wiped (see the threat model).
class CoreFields
{
public:
    explicit CoreFields(const QVariantMap &fields)
        : m_fields(fields.size())
    {
        m_buffers.reserve(2 * fields.size());
        for (auto field = fields.constBegin(); field != fields.constEnd(); ++field) {
            m_buffers.append(field.key().toUtf8());
            m_buffers.append(field.value().toString().toUtf8());
        }
        for (int index = 0; index < m_fields.size(); ++index) {
            const QByteArray &key = m_buffers.at(2 * index);
            const QByteArray &value = m_buffers.at(2 * index + 1);
            m_fields[index].key = bytePointer(key);
            m_fields[index].key_length = static_cast<size_t>(key.size());
            m_fields[index].value = bytePointer(value);
            m_fields[index].value_length = static_cast<size_t>(value.size());
        }
    }

    ~CoreFields()
    {
        for (QByteArray &buffer : m_buffers)
            secureWipe(buffer);
    }

    const SvField *data() const { return m_fields.constData(); }
    size_t count() const { return static_cast<size_t>(m_fields.size()); }

private:
    QVector<QByteArray> m_buffers;
    QVector<SvField> m_fields;
};

} // namespace

Vault::Vault(QObject *parent)
    : QObject(parent)
    , m_unlockCancelled(std::make_shared<std::atomic_bool>(false))
{
    const QSettings settings(settingsPath(), QSettings::IniFormat);
    m_databasePath = settings.value(QStringLiteral("databasePath")).toString();
    m_keyFilePath = settings.value(QStringLiteral("keyFilePath")).toString();

    m_idleTimer.setSingleShot(true);
    m_idleTimer.setInterval(static_cast<int>(IdleLockMs));
    m_watchdog.setInterval(WatchdogIntervalMs);
    connect(&m_idleTimer, &QTimer::timeout, this, &Vault::enforceDeadlines);
    connect(&m_watchdog, &QTimer::timeout, this, &Vault::enforceDeadlines);
    connect(qApp, &QGuiApplication::applicationStateChanged, this,
            &Vault::onApplicationStateChanged);
    connect(qApp, &QCoreApplication::aboutToQuit, this, &Vault::lock);
    qApp->installEventFilter(this);
}

Vault::~Vault()
{
    cancelPendingUnlock();
    // A running save finishes writing the file first.
    QThreadPool::globalInstance()->waitForDone();
    // A task may have posted its result before it saw the cancellation;
    // deliver it now so the slot frees or locks the handle.
    QCoreApplication::sendPostedEvents(this, QEvent::MetaCall);
    m_clipboard.clear();
    sv_database_free(m_database);
}

Vault::State Vault::state() const
{
    return m_state;
}

Vault::Error Vault::error() const
{
    return m_error;
}

bool Vault::saving() const
{
    return m_saving;
}

bool Vault::dirty() const
{
    return m_dirty;
}

QString Vault::databasePath() const
{
    return m_databasePath;
}

void Vault::setDatabasePath(const QString &path)
{
    if (m_databasePath == path)
        return;
    m_databasePath = path;
    setError(NoError);
    emit databasePathChanged();
}

QString Vault::keyFilePath() const
{
    return m_keyFilePath;
}

void Vault::setKeyFilePath(const QString &path)
{
    if (m_keyFilePath == path)
        return;
    m_keyFilePath = path;
    setError(NoError);
    emit keyFilePathChanged();
}

const SvDatabase *Vault::database()
{
    enforceDeadlines();
    return m_database;
}

void Vault::unlock(const QString &password)
{
    if (m_state != Locked || m_databasePath.isEmpty())
        return;
    QByteArray passwordBytes = password.toUtf8();
    setError(NoError);
    setState(Unlocking);
    QThreadPool::globalInstance()->start(new UnlockTask(this, m_unlockCancelled, ++m_attempt,
                                                        m_databasePath, m_keyFilePath,
                                                        passwordBytes));
    secureWipe(passwordBytes);
}

void Vault::onUnlockFinished(int attempt, int status, qulonglong handle, const QByteArray &digest)
{
    SvDatabase *database = reinterpret_cast<SvDatabase *>(handle);
    if (m_state != Unlocking || attempt != m_attempt) {
        sv_database_free(database);
        return;
    }
    if (status != SV_OK) {
        sv_database_free(database);
        setError(errorFor(status));
        setState(Locked);
        return;
    }
    finishUnlock(database, digest);
}

void Vault::finishUnlock(SvDatabase *database, const QByteArray &digest)
{
    m_database = database;
    m_fileDigest = digest;
    saveSettings();
    m_lastActivityMs = bootTimeMs();
    m_idleTimer.start();
    setState(Unlocked);
    // The app may have left the foreground while the KDF ran.
    onApplicationStateChanged(QGuiApplication::applicationState());
}

QString Vault::newDatabasePath(int location, const QString &name) const
{
    const QString fileName = name.trimmed();
    if (fileName.isEmpty() || fileName.startsWith(QLatin1Char('.'))
        || fileName.contains(QLatin1Char('/')) || fileName.size() > 100)
        return QString();
    const QString folder = QStandardPaths::writableLocation(
        location == Downloads ? QStandardPaths::DownloadLocation
                              : QStandardPaths::DocumentsLocation);
    return folder + QLatin1Char('/') + fileName + QStringLiteral(".kdbx");
}

bool Vault::fileExists(const QString &path) const
{
    return QFileInfo::exists(path);
}

void Vault::createDatabase(int location, const QString &name, const QString &password,
                           int kdfLevel)
{
    const QString path = newDatabasePath(location, name);
    if (m_state != Locked || path.isEmpty() || password.isEmpty()
        || (kdfLevel != KdfStandard && kdfLevel != KdfHigh && kdfLevel != KdfMaximum))
        return;
    QByteArray passwordBytes = password.toUtf8();
    setError(NoError);
    setState(Unlocking);
    QThreadPool::globalInstance()->start(new CreateTask(this, m_unlockCancelled, ++m_attempt, path,
                                                        name.trimmed(), passwordBytes,
                                                        static_cast<uint32_t>(kdfLevel)));
    secureWipe(passwordBytes);
}

void Vault::onCreateFinished(int attempt, int status, qulonglong handle,
                             const QByteArray &digest, const QString &path)
{
    SvDatabase *database = reinterpret_cast<SvDatabase *>(handle);
    if (m_state != Unlocking || attempt != m_attempt) {
        sv_database_free(database);
        return;
    }
    if (status != SV_OK) {
        sv_database_free(database);
        setError(errorFor(status));
        setState(Locked);
        return;
    }
    m_databasePath = path;
    m_keyFilePath.clear();
    emit databasePathChanged();
    emit keyFilePathChanged();
    finishUnlock(database, digest);
}

void Vault::lock()
{
    m_idleTimer.stop();
    m_backgroundSinceMs = 0;
    m_clipboard.clear();
    updateWatchdog();
    if (m_saving) {
        // The save task still reads the handle; onSaveFinished locks.
        m_lockAfterSave = true;
        return;
    }
    ++m_attempt;
    if (m_state == Unlocking) {
        setState(Locked);
        return;
    }
    if (!m_database)
        return;
    sv_database_free(m_database);
    m_database = nullptr;
    m_fileDigest.clear();
    setDirty(false);
    setState(Locked);
}

void Vault::cancelPendingUnlock()
{
    m_unlockCancelled->store(true);
    m_unlockCancelled = std::make_shared<std::atomic_bool>(false);
    ++m_attempt;
}

void Vault::clearError()
{
    setError(NoError);
}

void Vault::lockAutomatically()
{
    if (m_state != Unlocked)
        return;
    if (m_saving) {
        m_autoLockAfterSave = true;
        return;
    }
    lock();
    emit lockedAutomatically();
}

void Vault::enforceDeadlines()
{
    m_clipboard.enforceDeadline();
    if (m_state == Unlocked) {
        const long long now = bootTimeMs();
        const bool idle = now - m_lastActivityMs >= IdleLockMs;
        const bool background = m_backgroundSinceMs != 0
            && now - m_backgroundSinceMs >= BackgroundLockMs;
        if (idle || background)
            lockAutomatically();
    }
    updateWatchdog();
}

void Vault::updateWatchdog()
{
    const bool needed = m_clipboard.isPending()
        || (m_state == Unlocked && m_backgroundSinceMs != 0);
    if (needed && !m_watchdog.isActive())
        m_watchdog.start();
    else if (!needed)
        m_watchdog.stop();
}

QVariantList Vault::fields(const QString &entryId, int version)
{
    QVariantList result;
    const QByteArray uuid = itemUuid(entryId);
    const SvDatabase *handle = database();
    SvFieldList *fields = nullptr;
    if (!handle || uuid.isEmpty()
        || sv_database_fields(handle, bytePointer(uuid), version, &fields) != SV_OK)
        return result;
    for (size_t index = 0; index < sv_field_list_length(fields); ++index) {
        SvString key = emptyCoreString();
        if (sv_field_list_key(fields, index, &key) != SV_OK)
            continue;
        QVariantMap field;
        field.insert(QStringLiteral("key"), takeCoreString(key));
        field.insert(QStringLiteral("protected"), sv_field_list_is_protected(fields, index));
        result.append(field);
    }
    sv_field_list_free(fields);
    return result;
}

QString Vault::fieldValue(const QString &entryId, const QString &key, int version)
{
    return database() ? readField(entryId, key, version) : QString();
}

QString Vault::readField(const QString &entryId, const QString &key, int version) const
{
    const QByteArray uuid = itemUuid(entryId);
    const QByteArray keyBytes = key.toUtf8();
    SvString value = emptyCoreString();
    if (!m_database || uuid.isEmpty()
        || sv_database_field_value(m_database, bytePointer(uuid), version,
                                   bytePointer(keyBytes), static_cast<size_t>(keyBytes.size()),
                                   &value)
            != SV_OK)
        return QString();
    return takeCoreString(value);
}

bool Vault::copyField(const QString &entryId, const QString &key, int version)
{
    const QString value = fieldValue(entryId, key, version);
    if (value.isEmpty())
        return false;
    // The guard compares against the core's value instead of keeping a copy
    // or hash; lock() clears the clipboard before it frees the database.
    m_clipboard.copy(value, [this, entryId, key, version] {
        return readField(entryId, key, version);
    });
    updateWatchdog();
    return true;
}

QVariantList Vault::history(const QString &entryId)
{
    QVariantList result;
    const QByteArray uuid = itemUuid(entryId);
    const SvDatabase *handle = database();
    size_t length = 0;
    if (!handle || uuid.isEmpty()
        || sv_database_history_length(handle, bytePointer(uuid), &length) != SV_OK)
        return result;
    for (size_t index = length; index-- > 0;) {
        const int version = static_cast<int>(index);
        int64_t modified = 0;
        if (sv_database_modification_time(handle, bytePointer(uuid), version, &modified) != SV_OK)
            continue;
        QVariantMap item;
        item.insert(QStringLiteral("version"), version);
        item.insert(QStringLiteral("modified"),
                    QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(modified) * 1000));
        item.insert(QStringLiteral("title"), readField(entryId, QStringLiteral("Title"), version));
        item.insert(QStringLiteral("userName"),
                    readField(entryId, QStringLiteral("UserName"), version));
        result.append(item);
    }
    return result;
}

bool Vault::addEntry(const QString &groupId, const QVariantMap &fields)
{
    if (m_saving || !database())
        return false;
    const QByteArray group = QByteArray::fromHex(groupId.toLatin1());
    const CoreFields coreFields(fields);
    QByteArray uuid(SV_UUID_LENGTH, Qt::Uninitialized);
    const int status = sv_database_add_entry(
        m_database, group.size() == SV_UUID_LENGTH ? bytePointer(group) : nullptr,
        coreFields.data(), coreFields.count(), unixSeconds(),
        reinterpret_cast<uint8_t *>(uuid.data()));
    if (status != SV_OK)
        return false;
    commitChange();
    return true;
}

bool Vault::updateEntry(const QString &entryId, const QVariantMap &fields)
{
    const QByteArray uuid = itemUuid(entryId);
    if (m_saving || uuid.isEmpty() || !database())
        return false;
    const CoreFields coreFields(fields);
    bool changed = false;
    if (sv_database_update_entry(m_database, bytePointer(uuid), coreFields.data(),
                                 coreFields.count(), unixSeconds(), &changed) != SV_OK)
        return false;
    if (changed)
        commitChange();
    return true;
}

bool Vault::addImport(const SvImport *import, int &added, int &updated)
{
    if (m_saving || !database())
        return false;
    size_t addedEntries = 0;
    size_t updatedEntries = 0;
    if (sv_database_import(m_database, import, unixSeconds(), &addedEntries, &updatedEntries)
        != SV_OK)
        return false;
    added = static_cast<int>(addedEntries);
    updated = static_cast<int>(updatedEntries);
    if (added > 0 || updated > 0)
        commitChange();
    return true;
}

bool Vault::addGroup(const QString &parentId, const QString &name)
{
    if (m_saving || !database())
        return false;
    const QByteArray parent = itemUuid(parentId);
    const QByteArray nameBytes = name.toUtf8();
    QByteArray uuid(SV_UUID_LENGTH, Qt::Uninitialized);
    if (sv_database_add_group(m_database, parent.isEmpty() ? nullptr : bytePointer(parent),
                              bytePointer(nameBytes), static_cast<size_t>(nameBytes.size()),
                              unixSeconds(), reinterpret_cast<uint8_t *>(uuid.data()))
        != SV_OK)
        return false;
    commitChange();
    return true;
}

bool Vault::inRecycleBin(const QString &itemId)
{
    const QByteArray uuid = itemUuid(itemId);
    bool inside = false;
    return !uuid.isEmpty() && database()
        && sv_database_in_recycle_bin(m_database, bytePointer(uuid), &inside) == SV_OK && inside;
}

bool Vault::moveEntry(const QString &entryId, const QString &groupId)
{
    const QByteArray uuid = itemUuid(entryId);
    const QByteArray group = itemUuid(groupId);
    if (m_saving || uuid.isEmpty() || group.isEmpty() || !database())
        return false;
    bool moved = false;
    if (sv_database_move_entry(m_database, bytePointer(uuid), bytePointer(group), unixSeconds(),
                               &moved) != SV_OK)
        return false;
    if (moved)
        commitChange();
    return true;
}

bool Vault::renameGroup(const QString &groupId, const QString &name)
{
    const QByteArray uuid = itemUuid(groupId);
    if (m_saving || uuid.isEmpty() || !database())
        return false;
    const QByteArray nameBytes = name.toUtf8();
    bool changed = false;
    if (sv_database_rename_group(m_database, bytePointer(uuid), bytePointer(nameBytes),
                                 static_cast<size_t>(nameBytes.size()), unixSeconds(), &changed)
        != SV_OK)
        return false;
    if (changed)
        commitChange();
    return true;
}

bool Vault::moveGroup(const QString &groupId, const QString &parentId)
{
    const QByteArray uuid = itemUuid(groupId);
    const QByteArray parent = itemUuid(parentId);
    if (m_saving || uuid.isEmpty() || parent.isEmpty() || !database())
        return false;
    bool moved = false;
    if (sv_database_move_group(m_database, bytePointer(uuid), bytePointer(parent), unixSeconds(),
                               &moved)
        != SV_OK)
        return false;
    if (moved)
        commitChange();
    return true;
}

bool Vault::restore(const QString &itemId)
{
    const QByteArray uuid = itemUuid(itemId);
    if (m_saving || uuid.isEmpty() || !database()
        || sv_database_restore(m_database, bytePointer(uuid), unixSeconds()) != SV_OK)
        return false;
    commitChange();
    return true;
}

bool Vault::emptyRecycleBin()
{
    if (m_saving || !database())
        return false;
    bool changed = false;
    if (sv_database_empty_recycle_bin(m_database, unixSeconds(), &changed) != SV_OK)
        return false;
    if (changed)
        commitChange();
    return true;
}

QString Vault::recycleBinId()
{
    QByteArray uuid(SV_UUID_LENGTH, Qt::Uninitialized);
    const SvDatabase *handle = database();
    if (!handle || sv_database_recycle_bin(handle, reinterpret_cast<uint8_t *>(uuid.data())) != SV_OK)
        return QString();
    return QString::fromLatin1(uuid.toHex());
}

bool Vault::deletesPermanently(const QString &itemId)
{
    const QByteArray uuid = itemUuid(itemId);
    bool permanent = false;
    return !uuid.isEmpty() && database()
        && sv_database_delete_is_permanent(m_database, bytePointer(uuid), &permanent) == SV_OK
        && permanent;
}

bool Vault::deleteItem(const QString &itemId)
{
    const QByteArray uuid = itemUuid(itemId);
    if (m_saving || uuid.isEmpty() || !database())
        return false;
    bool permanent = false;
    if (sv_database_delete_item(m_database, bytePointer(uuid), unixSeconds(), &permanent) != SV_OK)
        return false;
    commitChange();
    return true;
}

void Vault::commitChange()
{
    setDirty(true);
    emit contentChanged();
    save();
}

void Vault::save()
{
    if (m_state != Unlocked || m_saving || !m_dirty || !m_database)
        return;
    setSaving(true);
    QThreadPool::globalInstance()->start(
        new SaveTask(this, m_attempt, m_database, m_databasePath, m_fileDigest));
}

void Vault::onSaveFinished(int attempt, int status, const QByteArray &digest,
                           bool replacedChangedFile)
{
    setSaving(false);
    if (attempt == m_attempt && m_state == Unlocked) {
        if (status == SV_OK) {
            m_fileDigest = digest;
            setDirty(false);
            if (replacedChangedFile)
                emit savedOverChangedFile();
        } else {
            setError(errorFor(status));
            emit saveFailed();
        }
    }
    if (m_autoLockAfterSave) {
        m_autoLockAfterSave = false;
        m_lockAfterSave = false;
        lockAutomatically();
    } else if (m_lockAfterSave) {
        m_lockAfterSave = false;
        lock();
    } else {
        // A deadline that passed during the save has no timer left.
        enforceDeadlines();
    }
}

QString Vault::generatePassword(int length, bool lower, bool upper, bool digits,
                                bool symbols) const
{
    const uint32_t classes = characterClass(lower, SV_CLASS_LOWER)
        | characterClass(upper, SV_CLASS_UPPER) | characterClass(digits, SV_CLASS_DIGITS)
        | characterClass(symbols, SV_CLASS_SYMBOLS);
    SvString password = emptyCoreString();
    if (length <= 0
        || sv_generate_password(static_cast<size_t>(length), classes, &password) != SV_OK)
        return QString();
    return takeCoreString(password);
}

bool Vault::eventFilter(QObject *watched, QEvent *event)
{
    switch (event->type()) {
    case QEvent::TouchBegin:
    case QEvent::MouseButtonPress:
    case QEvent::KeyPress:
    case QEvent::InputMethod:
        if (m_state == Unlocked) {
            m_lastActivityMs = bootTimeMs();
            m_idleTimer.start();
        }
        break;
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void Vault::onApplicationStateChanged(Qt::ApplicationState state)
{
    if (state == Qt::ApplicationActive) {
        // Check before clearing the background stamp, so time spent asleep
        // in the background still counts.
        enforceDeadlines();
        m_backgroundSinceMs = 0;
    } else if (m_state == Unlocked && m_backgroundSinceMs == 0) {
        m_backgroundSinceMs = bootTimeMs();
    }
    updateWatchdog();
}

void Vault::setState(State state)
{
    if (m_state == state)
        return;
    m_state = state;
    emit stateChanged();
}

void Vault::setError(Error error)
{
    if (m_error == error)
        return;
    m_error = error;
    emit errorChanged();
}

void Vault::setSaving(bool saving)
{
    if (m_saving == saving)
        return;
    m_saving = saving;
    emit savingChanged();
}

void Vault::setDirty(bool dirty)
{
    if (m_dirty == dirty)
        return;
    m_dirty = dirty;
    emit dirtyChanged();
}

void Vault::saveSettings() const
{
    QSettings settings(settingsPath(), QSettings::IniFormat);
    settings.setValue(QStringLiteral("databasePath"), m_databasePath);
    settings.setValue(QStringLiteral("keyFilePath"), m_keyFilePath);
}
