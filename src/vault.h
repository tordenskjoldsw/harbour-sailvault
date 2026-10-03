#ifndef VAULT_H
#define VAULT_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include <atomic>
#include <functional>
#include <memory>

#include "clipboardguard.h"
#include "sailvault_core.h"

// Owns the unlocked database handle and the lock state. QML sees titles
// and the one value the user shows or copies; everything else stays in
// the Rust core.
//
// Lock and clipboard deadlines are measured on CLOCK_BOOTTIME and checked
// before every access and by a watchdog, because Qt timers stop while the
// phone sleeps.
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
    Q_PROPERTY(QString databasePath READ databasePath WRITE setDatabasePath NOTIFY databasePathChanged)
    Q_PROPERTY(QString keyFilePath READ keyFilePath WRITE setKeyFilePath NOTIFY keyFilePathChanged)

public:
    // Where a new database file is created.
    enum Location {
        Documents,
        Downloads
    };
    Q_ENUM(Location)

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

    explicit Vault(QObject *parent = nullptr);
    ~Vault() override;

    State state() const;
    Error error() const;
    bool saving() const;
    // Changes in memory that no save has written yet.
    bool dirty() const;
    QString databasePath() const;
    void setDatabasePath(const QString &path);
    QString keyFilePath() const;
    void setKeyFilePath(const QString &path);

    // Null when locked, when a lock deadline has passed or while a requested
    // lock waits for a save.
    const SvDatabase *database();
    // Merges a Bitwarden import into its group in the root group and saves
    // when anything changed; refused while a save runs or when locked.
    bool addImport(const SvImport *import, int &added, int &updated);

    Q_INVOKABLE void unlock(const QString &password);
    // Key derivation levels of a new database, as SV_KDF_* in the core.
    enum KdfLevel {
        KdfStandard = SV_KDF_STANDARD,
        KdfHigh = SV_KDF_HIGH,
        KdfMaximum = SV_KDF_MAXIMUM
    };
    Q_ENUM(KdfLevel)

    // Creates an empty database file name.kdbx in location, protected by
    // password with the key derivation kdfLevel, and unlocks it; an existing
    // file is never replaced.
    Q_INVOKABLE void createDatabase(int location, const QString &name, const QString &password,
                                    int kdfLevel);
    // The path createDatabase would write, or empty for an invalid name.
    Q_INVOKABLE QString newDatabasePath(int location, const QString &name) const;
    Q_INVOKABLE bool fileExists(const QString &path) const;
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
    Q_INVOKABLE bool moveEntry(const QString &entryId, const QString &groupId);
    Q_INVOKABLE bool renameGroup(const QString &groupId, const QString &name);
    Q_INVOKABLE bool moveGroup(const QString &groupId, const QString &parentId);
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
    void databasePathChanged();
    void keyFilePathChanged();
    void lockedAutomatically();
    // The entries or groups changed; lists reload.
    void contentChanged();
    void saveFailed();
    // The file had been changed by another program since it was unlocked;
    // that version is kept in the backups.
    void savedOverChangedFile();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void onUnlockFinished(int attempt, int status, qulonglong handle, const QByteArray &digest);
    void onCreateFinished(int attempt, int status, qulonglong handle, const QByteArray &digest,
                          const QString &path);
    void onSaveFinished(int attempt, int status, const QByteArray &digest,
                        bool replacedChangedFile);
    void onApplicationStateChanged(Qt::ApplicationState state);
    void enforceDeadlines();

private:
    // One edit of the database; sets changed when it changed anything.
    using Edit = std::function<int(SvDatabase *database, int64_t now, bool &changed)>;

    // Runs an edit and saves when it changed anything; refused while a save
    // runs or when locked.
    bool change(const Edit &edit);
    QString readField(const QString &entryId, const QString &key, int version) const;
    void finishUnlock(SvDatabase *database, const QByteArray &digest);
    // Marks the in-memory change and starts the save.
    void commitChange();
    void lockAutomatically();
    void cancelPendingUnlock();
    void updateWatchdog();
    void setState(State state);
    void setError(Error error);
    void setSaving(bool saving);
    void setDirty(bool dirty);
    void saveSettings() const;

    SvDatabase *m_database = nullptr;
    int m_attempt = 0;
    std::shared_ptr<std::atomic_bool> m_unlockCancelled;
    State m_state = Locked;
    Error m_error = NoError;
    bool m_saving = false;
    bool m_dirty = false;
    bool m_lockAfterSave = false;
    bool m_autoLockAfterSave = false;
    // SHA-256 of the file as it was unlocked or last saved.
    QByteArray m_fileDigest;
    QString m_databasePath;
    QString m_keyFilePath;
    long long m_lastActivityMs = 0;
    long long m_backgroundSinceMs = 0;
    QTimer m_idleTimer;
    QTimer m_watchdog;
    ClipboardGuard m_clipboard;
};

#endif // VAULT_H
