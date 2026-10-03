#include "vault.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDateTime>
#include <QFileInfo>
#include <QSettings>
#include <QStandardPaths>
#include <QThreadPool>
#include <QVector>

#include "corebridge.h"
#include "databasefile.h"
#include "vaulttasks.h"

namespace {

QString settingsPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        + QStringLiteral("/settings.ini");
}

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

uint32_t characterClass(bool selected, int flag)
{
    return selected ? static_cast<uint32_t>(flag) : 0u;
}

// One-time password secrets, in KeePassXC's and KeePass's attributes, are
// shown hidden even when a file stores them unprotected.
bool isOneTimePasswordSecret(const QString &key)
{
    return key == QLatin1String("otp") || key == QLatin1String("TOTP Seed")
        || key.startsWith(QLatin1String("TimeOtp-Secret"))
        || key.startsWith(QLatin1String("HmacOtp-Secret"));
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

    CoreFields(const CoreFields &) = delete;
    CoreFields &operator=(const CoreFields &) = delete;
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

    connect(&m_autoLock, &AutoLock::expired, this, &Vault::lockAutomatically);
    connect(qApp, &QCoreApplication::aboutToQuit, this, &Vault::lock);
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
    m_database.reset();
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
    // Saves write to this path, so it changes only while locked.
    if (m_state != Locked || m_databasePath == path)
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
    if (m_state != Locked || m_keyFilePath == path)
        return;
    m_keyFilePath = path;
    setError(NoError);
    emit keyFilePathChanged();
}

const SvDatabase *Vault::database()
{
    enforceDeadlines();
    // A requested lock waits for the running save; nothing is read meanwhile.
    return m_lockAfterSave || m_autoLockAfterSave ? nullptr : m_database.get();
}

void Vault::unlock(const QString &password)
{
    if (m_state != Locked || m_databasePath.isEmpty())
        return;
    setError(NoError);
    setState(Unlocking);
    // The task owns the only copy of the password bytes and wipes it.
    QThreadPool::globalInstance()->start(new UnlockTask(this, m_unlockCancelled, ++m_attempt,
                                                        m_databasePath, m_keyFilePath,
                                                        password.toUtf8()));
}

void Vault::onUnlockFinished(int attempt, int status, qulonglong handle, const QByteArray &digest)
{
    CoreDatabase database(reinterpret_cast<SvDatabase *>(handle));
    if (acceptsResult(attempt, status))
        finishUnlock(std::move(database), digest);
}

bool Vault::acceptsResult(int attempt, int status)
{
    if (m_state != Unlocking || attempt != m_attempt)
        return false;
    if (status != SV_OK) {
        setError(errorFor(status));
        setState(Locked);
        return false;
    }
    return true;
}

void Vault::finishUnlock(CoreDatabase database, const QByteArray &digest)
{
    m_database = std::move(database);
    m_fileDigest = digest;
    saveSettings();
    setState(Unlocked);
    m_autoLock.start();
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
    setError(NoError);
    setState(Unlocking);
    QThreadPool::globalInstance()->start(new CreateTask(this, m_unlockCancelled, ++m_attempt, path,
                                                        name.trimmed(), password.toUtf8(),
                                                        static_cast<uint32_t>(kdfLevel)));
}

void Vault::onCreateFinished(int attempt, int status, qulonglong handle,
                             const QByteArray &digest, const QString &path)
{
    CoreDatabase database(reinterpret_cast<SvDatabase *>(handle));
    if (!acceptsResult(attempt, status))
        return;
    m_databasePath = path;
    m_keyFilePath.clear();
    emit databasePathChanged();
    emit keyFilePathChanged();
    finishUnlock(std::move(database), digest);
}

void Vault::lock()
{
    m_autoLock.stop();
    m_clipboard.clear();
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
    m_database.reset();
    m_fileDigest.clear();
    // An earlier save error no longer applies; changes it kept from being
    // written are gone now, which the unlock page reports.
    setError(m_dirty ? ChangesDiscarded : NoError);
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
    m_autoLock.check();
}

QVariantList Vault::fields(const QString &entryId, int version)
{
    QVariantList result;
    const QByteArray uuid = itemUuid(entryId);
    const SvDatabase *handle = database();
    SvFieldList *found = nullptr;
    if (!handle || uuid.isEmpty()
        || sv_database_fields(handle, bytePointer(uuid), version, &found) != SV_OK)
        return result;
    const CoreFieldList fields(found);
    for (size_t index = 0; index < sv_field_list_length(fields.get()); ++index) {
        SvString key = emptyCoreString();
        if (sv_field_list_key(fields.get(), index, &key) != SV_OK)
            continue;
        const QString name = takeCoreString(key);
        QVariantMap field;
        field.insert(QStringLiteral("key"), name);
        field.insert(QStringLiteral("protected"), sv_field_list_is_protected(fields.get(), index)
                                                      || isOneTimePasswordSecret(name));
        result.append(field);
    }
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
        || sv_database_field_value(m_database.get(), bytePointer(uuid), version,
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
    // or hash; edits pin the value first, and lock() clears the clipboard
    // before it frees the database.
    m_clipboard.copy(value, [this, entryId, key, version] {
        return readField(entryId, key, version);
    });
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
    const QByteArray group = itemUuid(groupId);
    const CoreFields coreFields(fields);
    return change([&](SvDatabase *database, int64_t now, bool &changed) {
        changed = true;
        QByteArray uuid(SV_UUID_LENGTH, Qt::Uninitialized);
        return sv_database_add_entry(database, uuidOrRoot(group),
                                     coreFields.data(), coreFields.count(), now,
                                     reinterpret_cast<uint8_t *>(uuid.data()));
    });
}

bool Vault::updateEntry(const QString &entryId, const QVariantMap &fields)
{
    const QByteArray uuid = itemUuid(entryId);
    const CoreFields coreFields(fields);
    return !uuid.isEmpty() && change([&](SvDatabase *database, int64_t now, bool &changed) {
        return sv_database_update_entry(database, bytePointer(uuid), coreFields.data(),
                                        coreFields.count(), now, &changed);
    });
}

bool Vault::addImport(const SvImport *import, int &added, int &updated)
{
    return change([&](SvDatabase *database, int64_t now, bool &changed) {
        size_t addedEntries = 0;
        size_t updatedEntries = 0;
        const int status = sv_database_import(database, import, now, &addedEntries,
                                              &updatedEntries);
        added = static_cast<int>(addedEntries);
        updated = static_cast<int>(updatedEntries);
        changed = added > 0 || updated > 0;
        return status;
    });
}

bool Vault::addGroup(const QString &parentId, const QString &name)
{
    const QByteArray parent = itemUuid(parentId);
    const QByteArray nameBytes = name.toUtf8();
    return change([&](SvDatabase *database, int64_t now, bool &changed) {
        changed = true;
        QByteArray uuid(SV_UUID_LENGTH, Qt::Uninitialized);
        return sv_database_add_group(database, uuidOrRoot(parent),
                                     bytePointer(nameBytes), static_cast<size_t>(nameBytes.size()),
                                     now, reinterpret_cast<uint8_t *>(uuid.data()));
    });
}

bool Vault::inRecycleBin(const QString &itemId)
{
    const QByteArray uuid = itemUuid(itemId);
    bool inside = false;
    return !uuid.isEmpty() && database()
        && sv_database_in_recycle_bin(m_database.get(), bytePointer(uuid), &inside) == SV_OK && inside;
}

bool Vault::moveEntry(const QString &entryId, const QString &groupId)
{
    const QByteArray uuid = itemUuid(entryId);
    const QByteArray group = itemUuid(groupId);
    return !uuid.isEmpty() && !group.isEmpty()
        && change([&](SvDatabase *database, int64_t now, bool &changed) {
               return sv_database_move_entry(database, bytePointer(uuid), bytePointer(group), now,
                                             &changed);
           });
}

bool Vault::renameGroup(const QString &groupId, const QString &name)
{
    const QByteArray uuid = itemUuid(groupId);
    const QByteArray nameBytes = name.toUtf8();
    return !uuid.isEmpty() && change([&](SvDatabase *database, int64_t now, bool &changed) {
        return sv_database_rename_group(database, bytePointer(uuid), bytePointer(nameBytes),
                                        static_cast<size_t>(nameBytes.size()), now, &changed);
    });
}

bool Vault::moveGroup(const QString &groupId, const QString &parentId)
{
    const QByteArray uuid = itemUuid(groupId);
    const QByteArray parent = itemUuid(parentId);
    return !uuid.isEmpty() && !parent.isEmpty()
        && change([&](SvDatabase *database, int64_t now, bool &changed) {
               return sv_database_move_group(database, bytePointer(uuid), bytePointer(parent), now,
                                             &changed);
           });
}

bool Vault::restore(const QString &itemId)
{
    const QByteArray uuid = itemUuid(itemId);
    return !uuid.isEmpty() && change([&](SvDatabase *database, int64_t now, bool &changed) {
        changed = true;
        return sv_database_restore(database, bytePointer(uuid), now);
    });
}

bool Vault::emptyRecycleBin()
{
    return change([](SvDatabase *database, int64_t now, bool &changed) {
        return sv_database_empty_recycle_bin(database, now, &changed);
    });
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
        && sv_database_delete_is_permanent(m_database.get(), bytePointer(uuid), &permanent) == SV_OK
        && permanent;
}

bool Vault::deleteItem(const QString &itemId)
{
    const QByteArray uuid = itemUuid(itemId);
    return !uuid.isEmpty() && change([&](SvDatabase *database, int64_t now, bool &changed) {
        changed = true;
        bool permanent = false;
        return sv_database_delete_item(database, bytePointer(uuid), now, &permanent);
    });
}

bool Vault::change(const Edit &edit)
{
    if (m_saving || !database())
        return false;
    m_clipboard.keepCopiedValue();
    bool changed = false;
    if (edit(m_database.get(), unixSeconds(), changed) != SV_OK)
        return false;
    if (changed)
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
        new SaveTask(this, m_attempt, m_database.get(), m_databasePath, m_fileDigest));
}

void Vault::onSaveFinished(int attempt, int status, const QByteArray &digest,
                           bool replacedChangedFile)
{
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
    // After the result is applied: the end of a save lets a pending import
    // merge, which starts the next save against the new digest.
    setSaving(false);
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
