#include "vault.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QDateTime>
#include <QFile>
#include <QSettings>
#include <QStandardPaths>
#include <QThreadPool>
#include <QVector>

#include "corebridge.h"
#include "databasefile.h"
#include "databases.h"
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

bool isKdbx3File(const QString &path)
{
    QByteArray start;
    uint16_t major = 0;
    uint16_t minor = 0;
    return readFileStart(path, 12, start) == SV_OK
        && sv_kdbx_version(bytePointer(start), static_cast<size_t>(start.size()), &major, &minor)
               == SV_OK
        && major == 3;
}

bool isKdfLevel(int level)
{
    return level == Vault::KdfStandard || level == Vault::KdfHigh || level == Vault::KdfMaximum;
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
    const QString name = settings.value(QStringLiteral("databaseName")).toString();
    if (Databases::exists(name))
        m_databaseName = name;
    // Versions before 0.3.0 opened the files where they were; they are
    // offered for adding.
    if (m_databaseName.isEmpty()) {
        m_sourcePath = settings.value(QStringLiteral("databasePath")).toString();
        m_sourceFromKdbx3 = !m_sourcePath.isEmpty() && isKdbx3File(m_sourcePath);
        m_sourceKeyFilePath = settings.value(QStringLiteral("keyFilePath")).toString();
    }

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

bool Vault::merging() const
{
    return m_merging;
}

bool Vault::busy() const
{
    return m_saving || m_merging;
}

bool Vault::dirty() const
{
    return m_dirty;
}

QString Vault::databaseName() const
{
    return m_databaseName;
}

void Vault::setDatabaseName(const QString &name)
{
    // Saves write to this database, so it changes only while locked.
    if (m_state != Locked || m_databaseName == name || (!name.isEmpty() && !Databases::exists(name)))
        return;
    m_databaseName = name;
    setError(NoError);
    emit databaseNameChanged();
}

QString Vault::sourcePath() const
{
    return m_sourcePath;
}

void Vault::setSourcePath(const QString &path)
{
    if (m_state != Locked || m_sourcePath == path)
        return;
    m_sourcePath = path;
    m_sourceFromKdbx3 = !path.isEmpty() && isKdbx3File(path);
    setError(NoError);
    emit sourcePathChanged();
}

bool Vault::sourceFromKdbx3() const
{
    return m_sourceFromKdbx3;
}

QString Vault::sourceKeyFilePath() const
{
    return m_sourceKeyFilePath;
}

void Vault::setSourceKeyFilePath(const QString &path)
{
    if (m_state != Locked || m_sourceKeyFilePath == path)
        return;
    m_sourceKeyFilePath = path;
    setError(NoError);
    emit sourceKeyFilePathChanged();
}

QStringList Vault::addedOriginals() const
{
    return m_addedOriginals;
}

bool Vault::removeAddedOriginals()
{
    bool removed = true;
    for (const QString &path : m_addedOriginals)
        removed = QFile::remove(path) && removed;
    setAddedOriginals(QStringList());
    return removed;
}

bool Vault::removeDatabase(const QString &name)
{
    if (m_state != Locked || !Databases::exists(name))
        return false;
    const QString path = Databases::databasePath(name);
    if (!QFile::remove(path))
        return false;
    if (m_databaseName == name) {
        m_databaseName.clear();
        setError(NoError);
        emit databaseNameChanged();
        saveSettings();
    }
    const QString keyFile = Databases::keyFilePath(name);
    const bool keyFileRemoved = !QFile::exists(keyFile) || QFile::remove(keyFile);
    return removeBackups(path, Databases::backupDirectory()) && keyFileRemoved;
}

int Vault::clipboardClearSeconds() const
{
    return ClipboardGuard::ClearAfterSeconds;
}

const SvDatabase *Vault::database()
{
    enforceDeadlines();
    // A requested lock waits for the running save; nothing is read meanwhile.
    return m_pendingLock != PendingLock::None ? nullptr : m_database.get();
}

void Vault::unlock(const QString &password)
{
    if (m_state != Locked || !Databases::exists(m_databaseName))
        return;
    const QString keyFile = Databases::hasKeyFile(m_databaseName)
        ? Databases::keyFilePath(m_databaseName) : QString();
    const int attempt = startUnlocking(m_databaseName);
    // The task owns the only copy of the password bytes and wipes it.
    QThreadPool::globalInstance()->start(new UnlockTask(this, m_unlockCancelled, attempt,
                                                        Databases::databasePath(m_databaseName),
                                                        keyFile, password.toUtf8()));
}

void Vault::addDatabase(const QString &name, const QString &password, int kdfLevel)
{
    if (m_state != Locked || m_sourcePath.isEmpty() || !Databases::isValidName(name)
        || !isKdfLevel(kdfLevel))
        return;
    QStringList sources(m_sourcePath);
    if (!m_sourceKeyFilePath.isEmpty())
        sources.append(m_sourceKeyFilePath);
    const int attempt = startUnlocking(name, sources);
    QThreadPool::globalInstance()->start(new AddTask(this, m_unlockCancelled, attempt, m_sourcePath,
                                                     m_sourceKeyFilePath, name, password.toUtf8(),
                                                     static_cast<uint32_t>(kdfLevel)));
}

void Vault::createDatabase(const QString &name, const QString &password, int kdfLevel)
{
    if (m_state != Locked || !Databases::isValidName(name) || password.isEmpty()
        || !isKdfLevel(kdfLevel))
        return;
    const int attempt = startUnlocking(name);
    QThreadPool::globalInstance()->start(new CreateTask(this, m_unlockCancelled, attempt, name,
                                                        password.toUtf8(),
                                                        static_cast<uint32_t>(kdfLevel)));
}

int Vault::startUnlocking(const QString &name, const QStringList &sources)
{
    m_unlockingName = name;
    m_unlockingSources = sources;
    setError(NoError);
    setState(Unlocking);
    return ++m_attempt;
}

void Vault::onUnlockFinished(int attempt, int status, qulonglong handle, const QByteArray &digest)
{
    CoreDatabase database(reinterpret_cast<SvDatabase *>(handle));
    if (m_state != Unlocking || attempt != m_attempt)
        return;
    if (status != SV_OK) {
        setError(errorFor(status));
        setState(Locked);
        return;
    }
    m_database = std::move(database);
    m_fileDigest = digest;
    if (m_databaseName != m_unlockingName) {
        m_databaseName = m_unlockingName;
        emit databaseNameChanged();
    }
    // An added database is stored now; a pending add is abandoned once
    // another database opens.
    clearSource();
    setAddedOriginals(m_unlockingSources);
    saveSettings();
    setState(Unlocked);
    m_autoLock.start();
}

void Vault::lock()
{
    m_autoLock.stop();
    m_clipboard.clear();
    if (busy()) {
        // The task still reads the handle; its result handler locks.
        if (m_pendingLock == PendingLock::None)
            m_pendingLock = PendingLock::Manual;
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
    setAddedOriginals(QStringList());
    m_mergedPath.clear();
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
    if (busy()) {
        m_pendingLock = PendingLock::Automatic;
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

int Vault::historyLength(const QString &entryId)
{
    const QByteArray uuid = itemUuid(entryId);
    const SvDatabase *handle = database();
    size_t length = 0;
    if (!handle || uuid.isEmpty()
        || sv_database_history_length(handle, bytePointer(uuid), &length) != SV_OK)
        return 0;
    return static_cast<int>(length);
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

Vault::MoveResult Vault::moveEntry(const QString &entryId, const QString &groupId)
{
    const QByteArray uuid = itemUuid(entryId);
    const QByteArray group = itemUuid(groupId);
    if (uuid.isEmpty() || group.isEmpty())
        return MoveRefused;
    return move([&](SvDatabase *database, int64_t now, bool &changed) {
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

Vault::MoveResult Vault::moveGroup(const QString &groupId, const QString &parentId)
{
    const QByteArray uuid = itemUuid(groupId);
    const QByteArray parent = itemUuid(parentId);
    if (uuid.isEmpty() || parent.isEmpty())
        return MoveRefused;
    return move([&](SvDatabase *database, int64_t now, bool &changed) {
        return sv_database_move_group(database, bytePointer(uuid), bytePointer(parent), now,
                                      &changed);
    });
}

Vault::MoveResult Vault::move(const Edit &edit)
{
    bool moved = false;
    const bool done = change([&](SvDatabase *database, int64_t now, bool &changed) {
        const int status = edit(database, now, changed);
        moved = changed;
        return status;
    });
    return !done ? MoveRefused : moved ? Moved : AlreadyThere;
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
    if (busy() || !database())
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
    if (m_state != Unlocked || busy() || !m_dirty || !m_database)
        return;
    setSaving(true);
    QThreadPool::globalInstance()->start(
        new SaveTask(this, m_attempt, m_database.get(), Databases::databasePath(m_databaseName),
                     m_fileDigest));
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
    resumePendingLock();
}

void Vault::mergeFile(const QString &path, const QString &password)
{
    if (busy() || path.isEmpty() || !database())
        return;
    m_mergePath = path;
    m_mergedPath.clear();
    const QString keyFile = !password.isEmpty() && Databases::hasKeyFile(m_databaseName)
        ? Databases::keyFilePath(m_databaseName) : QString();
    setMerging(true);
    QThreadPool::globalInstance()->start(new MergeTask(this, m_attempt, m_database.get(), path,
                                                       password.toUtf8(), keyFile));
}

void Vault::onMergeOpened(int attempt, int status, qulonglong handle)
{
    CoreDatabase source(reinterpret_cast<SvDatabase *>(handle));
    setMerging(false);
    // A lock requested meanwhile wins over the merge.
    if (attempt == m_attempt && m_state == Unlocked && m_pendingLock == PendingLock::None) {
        SvMergeChanges changes{0, 0, 0, 0, false};
        if (status == SV_OK) {
            m_clipboard.keepCopiedValue();
            status = sv_database_merge(m_database.get(), source.get(), &changes);
        }
        if (status == SV_INVALID_CREDENTIALS) {
            emit mergeNeedsPassword();
        } else if (status != SV_OK) {
            emit mergeFailed(errorFor(status));
        } else {
            m_mergedPath = m_mergePath;
            if (changes.added || changes.modified || changes.moved || changes.deleted
                || changes.metadata)
                commitChange();
            emit mergeFinished(static_cast<int>(changes.added), static_cast<int>(changes.modified),
                               static_cast<int>(changes.moved), static_cast<int>(changes.deleted));
        }
    }
    source.reset();
    resumePendingLock();
}

bool Vault::removeMergedFile()
{
    const bool removed = !m_mergedPath.isEmpty() && QFile::remove(m_mergedPath);
    m_mergedPath.clear();
    return removed;
}

void Vault::resumePendingLock()
{
    // A save the merge started handles the lock when it finishes.
    if (busy())
        return;
    const PendingLock pending = m_pendingLock;
    m_pendingLock = PendingLock::None;
    switch (pending) {
    case PendingLock::Automatic:
        lockAutomatically();
        break;
    case PendingLock::Manual:
        lock();
        break;
    case PendingLock::None:
        // A deadline that passed during the save has no timer left.
        enforceDeadlines();
        break;
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

void Vault::setMerging(bool merging)
{
    if (m_merging == merging)
        return;
    m_merging = merging;
    emit mergingChanged();
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

void Vault::setAddedOriginals(const QStringList &paths)
{
    if (m_addedOriginals == paths)
        return;
    m_addedOriginals = paths;
    emit addedOriginalsChanged();
}

void Vault::clearSource()
{
    if (!m_sourcePath.isEmpty()) {
        m_sourcePath.clear();
        m_sourceFromKdbx3 = false;
        emit sourcePathChanged();
    }
    if (!m_sourceKeyFilePath.isEmpty()) {
        m_sourceKeyFilePath.clear();
        emit sourceKeyFilePathChanged();
    }
}

void Vault::saveSettings() const
{
    QSettings settings(settingsPath(), QSettings::IniFormat);
    settings.setValue(QStringLiteral("databaseName"), m_databaseName);
    settings.remove(QStringLiteral("databasePath"));
    settings.remove(QStringLiteral("keyFilePath"));
}
