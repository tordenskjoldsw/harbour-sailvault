#ifndef VAULT_H
#define VAULT_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVariantList>
#include <QVariantMap>

#include <atomic>
#include <functional>
#include <memory>

#include "autolock.h"
#include "clipboardguard.h"
#include "corebridge.h"

// Owns the unlocked database handle and the lock state. QML gets list
// titles and user names, and field values one at a time when a page shows,
// copies or edits them; everything else stays in the Rust core.
//
// AutoLock and ClipboardGuard keep their deadlines, which are checked again
// before every access.
//
// An edit changes the database in memory and starts a save at once. While
// the save runs on a pool thread the handle is read-only for everyone, and
// a lock request waits for the save to finish.
class Vault : public QObject
{
    Q_OBJECT
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(Error error READ error NOTIFY errorChanged)
    Q_PROPERTY(bool saving READ saving NOTIFY savingChanged)
    Q_PROPERTY(bool dirty READ dirty NOTIFY dirtyChanged)
    Q_PROPERTY(QString databaseName READ databaseName WRITE setDatabaseName NOTIFY databaseNameChanged)
    Q_PROPERTY(QString sourcePath READ sourcePath WRITE setSourcePath NOTIFY sourcePathChanged)
    Q_PROPERTY(QString sourceKeyFilePath READ sourceKeyFilePath WRITE setSourceKeyFilePath NOTIFY sourceKeyFilePathChanged)
    Q_PROPERTY(int clipboardClearSeconds READ clipboardClearSeconds CONSTANT)

public:
    enum State {
        Locked,
        Unlocking,
        Unlocked
    };
    Q_ENUM(State)

    enum Error {
        NoError,
        WrongCredentials,
        InvalidKeyFile,
        Kdbx3Unsupported,
        NotKdbx,
        UnsupportedFormat,
        Corrupted,
        TooLarge,
        FileUnreadable,
        FileUnwritable,
        SaveFailed,
        FileExists,
        // Changes that could not be saved were discarded by a lock.
        ChangesDiscarded
    };
    Q_ENUM(Error)

    // Key derivation levels of a new database, as SV_KDF_* in the core.
    enum KdfLevel {
        KdfStandard = SV_KDF_STANDARD,
        KdfHigh = SV_KDF_HIGH,
        KdfMaximum = SV_KDF_MAXIMUM
    };
    Q_ENUM(KdfLevel)

    // Results of moveEntry and moveGroup.
    enum MoveResult {
        MoveRefused,
        Moved,
        AlreadyThere
    };
    Q_ENUM(MoveResult)

    explicit Vault(QObject *parent = nullptr);
    ~Vault() override;

    State state() const;
    Error error() const;
    bool saving() const;
    // Changes in memory that no save has written yet.
    bool dirty() const;
    // The stored database that unlock opens (see Databases).
    QString databaseName() const;
    void setDatabaseName(const QString &name);
    // A database file and key file outside the app that addDatabase stores.
    QString sourcePath() const;
    void setSourcePath(const QString &path);
    QString sourceKeyFilePath() const;
    void setSourceKeyFilePath(const QString &path);
    int clipboardClearSeconds() const;

    // Null when locked, when a lock deadline has passed or while a requested
    // lock waits for a save.
    const SvDatabase *database();
    // Merges a Bitwarden import into its group in the root group and saves
    // when anything changed; refused while a save runs or when locked.
    bool addImport(const SvImport *import, int &added, int &updated);

    Q_INVOKABLE void unlock(const QString &password);
    // Unlocks the source files and stores copies under name, which then
    // becomes the database; an existing database is never replaced.
    Q_INVOKABLE void addDatabase(const QString &name, const QString &password);
    // Creates an empty database under name, protected by password with the
    // key derivation kdfLevel, and unlocks it; an existing database is never
    // replaced.
    Q_INVOKABLE void createDatabase(const QString &name, const QString &password, int kdfLevel);
    Q_INVOKABLE void lock();
    Q_INVOKABLE void clearError();
    // version -1 is the current state of an entry, 0 and up its history
    // items, oldest first. Each field has its key and whether it is shown
    // hidden: protected in the file, or a one-time password secret.
    Q_INVOKABLE QVariantList fields(const QString &entryId, int version = -1);
    Q_INVOKABLE QString fieldValue(const QString &entryId, const QString &key, int version = -1);
    Q_INVOKABLE bool copyField(const QString &entryId, const QString &key, int version = -1);
    // History items newest first, each with version, modified, title and
    // userName.
    Q_INVOKABLE QVariantList history(const QString &entryId);
    Q_INVOKABLE int historyLength(const QString &entryId);
    // fields maps field names to values; an empty groupId means the root
    // group. Each change starts a save.
    Q_INVOKABLE bool addEntry(const QString &groupId, const QVariantMap &fields);
    Q_INVOKABLE bool updateEntry(const QString &entryId, const QVariantMap &fields);
    // An empty parentId means the root group.
    Q_INVOKABLE bool addGroup(const QString &parentId, const QString &name);
    // True for the recycle bin and everything in it, where nothing new is
    // added.
    Q_INVOKABLE bool inRecycleBin(const QString &itemId);
    // Moves an entry into another group; moving out of the recycle bin
    // restores it.
    Q_INVOKABLE MoveResult moveEntry(const QString &entryId, const QString &groupId);
    Q_INVOKABLE bool renameGroup(const QString &groupId, const QString &name);
    Q_INVOKABLE MoveResult moveGroup(const QString &groupId, const QString &parentId);
    // Moves an entry or group out of the recycle bin to where it was deleted
    // from, or to the root group.
    Q_INVOKABLE bool restore(const QString &itemId);
    Q_INVOKABLE bool emptyRecycleBin();
    // Empty when the database has no recycle bin.
    Q_INVOKABLE QString recycleBinId();
    // True when deleteItem would remove the entry or group for good instead
    // of moving it to the recycle bin.
    Q_INVOKABLE bool deletesPermanently(const QString &itemId);
    // Deletes an entry, or a group with everything in it.
    Q_INVOKABLE bool deleteItem(const QString &itemId);
    Q_INVOKABLE void save();
    Q_INVOKABLE QString generatePassword(int length, bool lower, bool upper, bool digits,
                                         bool symbols) const;

signals:
    void stateChanged();
    void errorChanged();
    void savingChanged();
    void dirtyChanged();
    void databaseNameChanged();
    void sourcePathChanged();
    void sourceKeyFilePathChanged();
    void lockedAutomatically();
    // The entries or groups changed; lists reload.
    void contentChanged();
    void saveFailed();
    // The file had been changed by another program since it was unlocked;
    // that version is kept in the backups.
    void savedOverChangedFile();

private slots:
    void onUnlockFinished(int attempt, int status, qulonglong handle, const QByteArray &digest);
    void onSaveFinished(int attempt, int status, const QByteArray &digest,
                        bool replacedChangedFile);

private:
    // One edit of the database; sets changed when it changed anything.
    using Edit = std::function<int(SvDatabase *database, int64_t now, bool &changed)>;

    // Runs an edit and saves when it changed anything; refused while a save
    // runs or when locked.
    bool change(const Edit &edit);
    MoveResult move(const Edit &edit);
    QString readField(const QString &entryId, const QString &key, int version) const;
    // Enters Unlocking for a task that opens the database name; returns the
    // task's attempt.
    int startUnlocking(const QString &name);
    // Marks the in-memory change and starts the save.
    void commitChange();
    void lockAutomatically();
    // Clears the clipboard and locks when their deadlines have passed.
    void enforceDeadlines();
    void cancelPendingUnlock();
    void setState(State state);
    void setError(Error error);
    void setSaving(bool saving);
    void setDirty(bool dirty);
    void saveSettings() const;

    CoreDatabase m_database;
    int m_attempt = 0;
    std::shared_ptr<std::atomic_bool> m_unlockCancelled;
    State m_state = Locked;
    Error m_error = NoError;
    bool m_saving = false;
    bool m_dirty = false;
    // A lock requested during a save waits for it.
    enum class PendingLock { None, Manual, Automatic };
    PendingLock m_pendingLock = PendingLock::None;
    // SHA-256 of the file as it was unlocked or last saved.
    QByteArray m_fileDigest;
    QString m_databaseName;
    // The database the running unlock, add or create task opens.
    QString m_unlockingName;
    QString m_sourcePath;
    QString m_sourceKeyFilePath;
    AutoLock m_autoLock;
    ClipboardGuard m_clipboard;
};

#endif // VAULT_H
