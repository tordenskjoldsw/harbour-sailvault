#ifndef VAULT_H
#define VAULT_H

#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantList>

#include "clipboardguard.h"
#include "sailvault_core.h"

// Owns the unlocked database handle and the lock state. QML sees titles
// and the one value the user shows or copies; everything else stays in
// the Rust core.
class Vault : public QObject
{
    Q_OBJECT
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(Error error READ error NOTIFY errorChanged)
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
        FileUnreadable
    };
    Q_ENUM(Error)

    explicit Vault(QObject *parent = nullptr);
    ~Vault() override;

    State state() const;
    Error error() const;
    QString databasePath() const;
    void setDatabasePath(const QString &path);
    QString keyFilePath() const;
    void setKeyFilePath(const QString &path);

    const SvDatabase *database() const;

    Q_INVOKABLE void unlock(const QString &password);
    Q_INVOKABLE void lock();
    Q_INVOKABLE void clearError();
    Q_INVOKABLE QVariantList fields(const QString &entryId) const;
    Q_INVOKABLE QString fieldValue(const QString &entryId, const QString &key) const;
    Q_INVOKABLE bool copyField(const QString &entryId, const QString &key);

signals:
    void stateChanged();
    void errorChanged();
    void databasePathChanged();
    void keyFilePathChanged();
    void lockedAutomatically();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void onUnlockFinished(int attempt, int status, qulonglong handle);
    void onApplicationStateChanged(Qt::ApplicationState state);
    void lockAutomatically();

private:
    void setState(State state);
    void setError(Error error);
    void saveSettings() const;

    SvDatabase *m_database = nullptr;
    int m_attempt = 0;
    State m_state = Locked;
    Error m_error = NoError;
    QString m_databasePath;
    QString m_keyFilePath;
    QTimer m_idleTimer;
    QTimer m_backgroundTimer;
    ClipboardGuard m_clipboard;
};

#endif // VAULT_H
