#ifndef VAULT_H
#define VAULT_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include <atomic>
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
        SaveFailed
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

    // Null when locked or when a lock deadline has passed.
    const SvDatabase *database();

    Q_INVOKABLE void unlock(const QString &password);
    Q_INVOKABLE void lock();
    Q_INVOKABLE void clearError();
    Q_INVOKABLE QVariantList fields(const QString &entryId);
    Q_INVOKABLE QString fieldValue(const QString &entryId, const QString &key);
    Q_INVOKABLE bool copyField(const QString &entryId, const QString &key);
    // fields maps field names to values; an empty groupId means the root
    // group. Each change starts a save.
    Q_INVOKABLE bool addEntry(const QString &groupId, const QVariantMap &fields);
    Q_INVOKABLE bool updateEntry(const QString &entryId, const QVariantMap &fields);
    // True when deleteEntry would remove the entry for good instead of
    // moving it to the recycle bin.
    Q_INVOKABLE bool deletesPermanently(const QString &entryId);
    Q_INVOKABLE bool deleteEntry(const QString &entryId);
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
    void onSaveFinished(int attempt, int status, const QByteArray &digest,
                        bool replacedChangedFile);
    void onApplicationStateChanged(Qt::ApplicationState state);
    void enforceDeadlines();

private:
    QString readField(const QString &entryId, const QString &key) const;
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
