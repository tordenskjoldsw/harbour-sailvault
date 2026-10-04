#ifndef SYNC_H
#define SYNC_H

#include <QByteArray>
#include <QDateTime>
#include <QObject>
#include <QString>

#include <functional>

#include "nextcloud.h"

class QNetworkConfigurationManager;
class QTimer;
class Vault;

// Syncs the open database with its file on Nextcloud while the app runs:
// after unlocking, after each save (shortly delayed) and on request. The
// settings and the app password come from the database's sync entry.
//
// A sync downloads the file if its ETag changed, merges it, and uploads the
// result only if this copy has changes the server lacks, conditional on the
// ETag it merged; a changed file on the server starts over, at most three
// times. ETag and file digest of the last sync are kept per database; they
// are not secret.
class Sync : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool configured READ configured NOTIFY configuredChanged)
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(Problem problem READ problem NOTIFY stateChanged)
    Q_PROPERTY(QDateTime lastSynced READ lastSynced NOTIFY stateChanged)
    Q_PROPERTY(SetupState setupState READ setupState NOTIFY setupChanged)
    Q_PROPERTY(Problem setupProblem READ setupProblem NOTIFY setupChanged)
    // The certificate waiting for confirmation, as colon-separated hex.
    Q_PROPERTY(QString certificateFingerprint READ certificateFingerprint NOTIFY certificateChanged)
    // True when a pinned certificate was replaced by another one.
    Q_PROPERTY(bool certificateReplaced READ certificateReplaced NOTIFY certificateChanged)

public:
    enum State {
        Off,
        Idle,
        Syncing,
        Failed
    };
    Q_ENUM(State)

    enum Problem {
        NoProblem,
        Offline,
        LoginFailed,
        CertificateUnknown,
        FolderMissing,
        // The file on the server does not open with this database's
        // credentials.
        OtherCredentials,
        NotDatabase,
        ServerProblem,
        InvalidServer,
        LoginExpired
    };
    Q_ENUM(Problem)

    enum SetupState {
        SetupIdle,
        WaitingForBrowser,
        Checking,
        SetupDone,
        SetupFailed
    };
    Q_ENUM(SetupState)

    explicit Sync(Vault *vault, QObject *parent = nullptr);

    bool configured() const;
    State state() const;
    Problem problem() const;
    QDateTime lastSynced() const;
    SetupState setupState() const;
    Problem setupProblem() const;
    QString certificateFingerprint() const;
    bool certificateReplaced() const;

    // The suggested path on the server for the open database.
    Q_INVOKABLE QString defaultPath() const;
    // The stored settings, for the settings page; the app password stays
    // out of QML.
    Q_INVOKABLE QString storedServer() const;
    Q_INVOKABLE QString storedPath() const;
    Q_INVOKABLE QString storedLoginName() const;
    // Moves the sync to another file on the same server with the stored
    // login; the next sync uses it.
    Q_INVOKABLE void changePath(const QString &path);
    // Sets up sync for the open database through Nextcloud Login Flow v2:
    // opens the login page in the browser and waits for access.
    Q_INVOKABLE void startLogin(const QString &server, const QString &path);
    // The same with an app password created in Nextcloud by hand.
    Q_INVOKABLE void setUpManually(const QString &server, const QString &path,
                                   const QString &loginName, const QString &appPassword);
    Q_INVOKABLE void cancelSetup();
    // Accepts the certificate waiting for confirmation, pins it and repeats
    // the step that met it.
    Q_INVOKABLE void trustCertificate();
    Q_INVOKABLE void sync();

signals:
    void configuredChanged();
    void stateChanged();
    void setupChanged();
    void certificateChanged();

private:
    struct Setup {
        QUrl server;
        QString path;
        QString loginName;
        QByteArray appPassword;
        QByteArray pin;
    };

    void onVaultStateChanged();
    void onSaved();
    void stop();
    void abortSync();
    // Starts a sync after a short delay and shows it as running already:
    // the change it covers is not on the server yet.
    void scheduleSync();
    void updateConfigured();
    bool loadAccount();
    void withUserId(const std::function<void()> &next);
    void download();
    void merge(const QByteArray &data, const QByteArray &etag);
    void onMerged(bool changed);
    void uploadIfNeeded();
    void upload();
    void createFolders(const QStringList &folders);
    void finish(Problem problem);
    Problem problemOf(NextcloudClient::Result result, const QByteArray &pin);
    void remember();
    QString settingsGroup() const;

    void checkSetup();
    void failSetup(Problem problem, const std::function<void()> &retry = nullptr);
    void setSetupState(SetupState state, Problem problem = NoProblem);
    void wipeSetup();

    Vault *m_vault;
    NextcloudClient *m_client;
    QTimer *m_delay;
    QNetworkConfigurationManager *m_connectivity;
    bool m_configured = false;
    State m_state = Off;
    Problem m_problem = NoProblem;
    QDateTime m_lastSynced;
    // Bumped by every stop, so answers to aborted requests are ignored.
    int m_generation = 0;
    bool m_running = false;
    bool m_again = false;
    int m_attempts = 0;
    bool m_foldersCreated = false;
    QString m_path;
    QString m_remote;
    QString m_userId;
    QByteArray m_pin;
    QByteArray m_etag;
    QByteArray m_digest;
    // The remote ETag being merged, and the digest of this copy before.
    QByteArray m_mergedEtag;
    QByteArray m_digestBeforeMerge;
    bool m_waitingForSave = false;
    QByteArray m_pendingData;
    QByteArray m_pendingEtag;

    SetupState m_setupState = SetupIdle;
    Problem m_setupProblem = NoProblem;
    Setup m_setup;
    QByteArray m_fingerprint;
    bool m_certificateReplaced = false;
    std::function<void()> m_retry;
};

#endif // SYNC_H
