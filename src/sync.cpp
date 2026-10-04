#include "sync.h"

#include <QDesktopServices>
#include <QNetworkConfigurationManager>
#include <QSettings>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>

#include "corebridge.h"
#include "databasefile.h"
#include "databases.h"
#include "vault.h"

namespace {

// Saves come in bursts while editing; one sync covers them.
const int SaveDelayMs = 2000;
const int MaxAttempts = 3;

QString settingsPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        + QStringLiteral("/settings.ini");
}

// Only https: the app password must never travel in the clear.
QUrl serverUrl(const QString &text)
{
    QString trimmed = text.trimmed();
    if (!trimmed.contains(QStringLiteral("://")))
        trimmed.prepend(QStringLiteral("https://"));
    const QUrl url(trimmed, QUrl::StrictMode);
    if (!url.isValid() || url.scheme() != QLatin1String("https") || url.host().isEmpty()
        || !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment())
        return QUrl();
    return url;
}

QString remotePath(const QString &text)
{
    const QString trimmed = text.trimmed();
    return trimmed.startsWith(QLatin1Char('/')) ? trimmed : QLatin1Char('/') + trimmed;
}

} // namespace

Sync::Sync(Vault *vault, QObject *parent)
    : QObject(parent)
    , m_vault(vault)
    , m_client(new NextcloudClient(this))
    , m_delay(new QTimer(this))
    , m_connectivity(new QNetworkConfigurationManager(this))
{
    // Only a trigger: a sync that failed for want of a connection runs again
    // once one is back. Syncs never wait for this report, which may be
    // wrong inside the sandbox.
    connect(m_connectivity, &QNetworkConfigurationManager::onlineStateChanged, this,
            [this](bool online) {
                if (online && m_state == Failed && m_problem == Offline)
                    scheduleSync();
            });
    m_delay->setSingleShot(true);
    m_delay->setInterval(SaveDelayMs);
    connect(m_delay, &QTimer::timeout, this, &Sync::sync);
    connect(vault, &Vault::stateChanged, this, &Sync::onVaultStateChanged);
    connect(vault, &Vault::saved, this, &Sync::onSaved);
    connect(vault, &Vault::contentChanged, this, &Sync::updateConfigured);
    connect(vault, &Vault::syncMergeFinished, this, &Sync::onMerged);
    connect(vault, &Vault::syncMergeFailed, this, [this](int error) {
        if (!m_running)
            return;
        switch (error) {
        case Vault::WrongCredentials:
        case Vault::InvalidKeyFile:
            finish(OtherCredentials);
            break;
        case Vault::NotKdbx:
        case Vault::Corrupted:
        case Vault::UnsupportedFormat:
            finish(NotDatabase);
            break;
        default:
            finish(ServerProblem);
        }
    });
    connect(vault, &Vault::saveFailed, this, [this]() {
        if (m_waitingForSave)
            finish(ServerProblem);
    });
    // A download that arrived during a save is merged once the vault is
    // free again.
    auto resume = [this]() {
        if (!m_pendingData.isEmpty() && !m_vault->busy()) {
            const QByteArray data = m_pendingData;
            m_pendingData.clear();
            merge(data, m_pendingEtag);
        }
    };
    connect(vault, &Vault::savingChanged, this, resume);
    connect(vault, &Vault::mergingChanged, this, resume);
}

bool Sync::configured() const
{
    return m_configured;
}

Sync::State Sync::state() const
{
    return m_state;
}

Sync::Problem Sync::problem() const
{
    return m_problem;
}

QDateTime Sync::lastSynced() const
{
    return m_lastSynced;
}

Sync::SetupState Sync::setupState() const
{
    return m_setupState;
}

Sync::Problem Sync::setupProblem() const
{
    return m_setupProblem;
}

QString Sync::certificateFingerprint() const
{
    QStringList pairs;
    const QByteArray hex = m_fingerprint.toUpper();
    for (int index = 0; index + 1 < hex.size(); index += 2)
        pairs.append(QString::fromLatin1(hex.mid(index, 2)));
    return pairs.join(QLatin1Char(':'));
}

bool Sync::certificateReplaced() const
{
    return m_certificateReplaced;
}

QString Sync::defaultPath() const
{
    return QStringLiteral("/SailVault/") + m_vault->databaseName() + QStringLiteral(".kdbx");
}

QString Sync::storedServer() const
{
    return QString::fromUtf8(m_vault->syncSetting(SV_SYNC_SERVER));
}

QString Sync::storedPath() const
{
    return QString::fromUtf8(m_vault->syncSetting(SV_SYNC_PATH));
}

QString Sync::storedLoginName() const
{
    return QString::fromUtf8(m_vault->syncSetting(SV_SYNC_USER));
}

void Sync::changePath(const QString &path)
{
    const QString remote = remotePath(path);
    if (!m_configured || remote.length() < 2 || remote == storedPath())
        return;
    abortSync();
    QByteArray password = m_vault->syncSetting(SV_SYNC_APP_PASSWORD);
    // Saving the entry starts the next sync.
    const bool stored = m_vault->storeSyncSettings(storedServer(), storedLoginName(), password,
                                                   remote,
                                                   m_vault->syncSetting(SV_SYNC_CERTIFICATE));
    secureWipe(password);
    setSetupState(stored ? SetupDone : SetupFailed, stored ? NoProblem : ServerProblem);
}

void Sync::onVaultStateChanged()
{
    if (m_vault->state() == Vault::Unlocked) {
        updateConfigured();
        sync();
    } else {
        stop();
    }
}

void Sync::onSaved()
{
    updateConfigured();
    if (m_waitingForSave) {
        m_waitingForSave = false;
        uploadIfNeeded();
        return;
    }
    if (m_running)
        m_again = true;
    else if (m_configured)
        scheduleSync();
}

void Sync::scheduleSync()
{
    m_delay->start();
    if (m_state != Syncing || m_problem != NoProblem) {
        m_state = Syncing;
        m_problem = NoProblem;
        emit stateChanged();
    }
}

// Locking ends everything: requests, the login flow and every credential
// held here.
void Sync::stop()
{
    ++m_generation;
    m_delay->stop();
    m_client->abortAll();
    m_client->clearAccount();
    m_running = false;
    m_again = false;
    m_waitingForSave = false;
    m_pendingData.clear();
    m_userId.clear();
    m_remote.clear();
    wipeSetup();
    setSetupState(SetupIdle);
    updateConfigured();
    if (m_state != Off || m_problem != NoProblem) {
        m_state = Off;
        m_problem = NoProblem;
        emit stateChanged();
    }
}

void Sync::updateConfigured()
{
    const bool configured = m_vault->state() == Vault::Unlocked
        && !m_vault->syncSetting(SV_SYNC_SERVER).isEmpty();
    if (m_configured == configured)
        return;
    m_configured = configured;
    emit configuredChanged();
}

QString Sync::settingsGroup() const
{
    return QStringLiteral("sync-") + m_vault->databaseName();
}

bool Sync::loadAccount()
{
    QByteArray password = m_vault->syncSetting(SV_SYNC_APP_PASSWORD);
    NextcloudClient::Account account;
    account.server = QUrl(QString::fromUtf8(m_vault->syncSetting(SV_SYNC_SERVER)));
    account.loginName = QString::fromUtf8(m_vault->syncSetting(SV_SYNC_USER));
    account.appPassword = password;
    account.pinnedCertificate = m_vault->syncSetting(SV_SYNC_CERTIFICATE);
    secureWipe(password);
    const QString path = QString::fromUtf8(m_vault->syncSetting(SV_SYNC_PATH));
    if (!serverUrl(account.server.toString()).isValid() || account.loginName.isEmpty()
        || account.appPassword.isEmpty() || path.isEmpty()) {
        secureWipe(account.appPassword);
        return false;
    }

    const QString remote = account.server.toString() + QLatin1Char('\n') + account.loginName
        + QLatin1Char('\n') + path;
    if (remote != m_remote) {
        // Another server, account or file: what was synced before says
        // nothing about it.
        m_remote = remote;
        m_userId.clear();
        QSettings settings(settingsPath(), QSettings::IniFormat);
        settings.beginGroup(settingsGroup());
        const bool same = settings.value(QStringLiteral("remote")).toString() == remote;
        m_etag = same ? settings.value(QStringLiteral("etag")).toByteArray() : QByteArray();
        m_digest = same ? QByteArray::fromHex(settings.value(QStringLiteral("digest")).toByteArray())
                        : QByteArray();
        m_lastSynced = same ? settings.value(QStringLiteral("synced")).toDateTime() : QDateTime();
    }
    m_path = path;
    m_pin = account.pinnedCertificate;
    m_client->setAccount(account);
    secureWipe(account.appPassword);
    return true;
}

void Sync::remember()
{
    QSettings settings(settingsPath(), QSettings::IniFormat);
    settings.beginGroup(settingsGroup());
    settings.setValue(QStringLiteral("remote"), m_remote);
    settings.setValue(QStringLiteral("etag"), m_etag);
    settings.setValue(QStringLiteral("digest"), m_digest.toHex());
    settings.setValue(QStringLiteral("synced"), m_lastSynced);
}

void Sync::sync()
{
    if (m_vault->state() != Vault::Unlocked || m_setupState == WaitingForBrowser
        || m_setupState == Checking)
        return;
    m_delay->stop();
    if (m_running) {
        m_again = true;
        return;
    }
    if (!loadAccount()) {
        if (m_state != Off) {
            m_state = Off;
            m_problem = NoProblem;
            emit stateChanged();
        }
        return;
    }
    m_running = true;
    m_attempts = 0;
    m_foldersCreated = false;
    m_mergedEtag.clear();
    m_digestBeforeMerge.clear();
    m_state = Syncing;
    m_problem = NoProblem;
    emit stateChanged();
    withUserId([this]() { download(); });
}

void Sync::withUserId(const std::function<void()> &next)
{
    if (!m_userId.isEmpty()) {
        next();
        return;
    }
    const int generation = m_generation;
    m_client->userId([this, generation, next](NextcloudClient::Result result, const QString &id) {
        if (generation != m_generation)
            return;
        if (result != NextcloudClient::Ok) {
            finish(problemOf(result, m_pin));
            return;
        }
        m_userId = id;
        next();
    });
}

void Sync::download()
{
    const int generation = m_generation;
    m_client->download(
        m_userId, m_path, m_etag,
        [this, generation](NextcloudClient::Result result, const QByteArray &data,
                           const QByteArray &etag) {
            if (generation != m_generation)
                return;
            switch (result) {
            case NextcloudClient::NotModified:
                m_mergedEtag = m_etag;
                uploadIfNeeded();
                break;
            case NextcloudClient::NotFound:
                // Not on the server yet: this copy creates it.
                m_mergedEtag.clear();
                m_digest.clear();
                upload();
                break;
            case NextcloudClient::Ok:
                merge(data, etag);
                break;
            default:
                finish(problemOf(result, m_pin));
            }
        });
}

void Sync::merge(const QByteArray &data, const QByteArray &etag)
{
    m_pendingEtag = etag;
    m_digestBeforeMerge = m_vault->fileDigest();
    if (!m_vault->mergeData(data))
        m_pendingData = data;
}

void Sync::onMerged(bool changed)
{
    if (!m_running)
        return;
    m_mergedEtag = m_pendingEtag;
    if (changed)
        m_waitingForSave = true;
    else
        uploadIfNeeded();
}

void Sync::uploadIfNeeded()
{
    const QByteArray local = m_vault->fileDigest();
    // Unchanged here since the last sync: whatever the server had is merged
    // now, and the server has nothing to learn from this copy.
    const QByteArray before = m_digestBeforeMerge.isEmpty() ? local : m_digestBeforeMerge;
    if (!m_digest.isEmpty() && before == m_digest) {
        m_etag = m_mergedEtag;
        m_digest = local;
        finish(NoProblem);
        return;
    }
    upload();
}

void Sync::upload()
{
    QByteArray data;
    if (readBoundedFile(Databases::databasePath(m_vault->databaseName()), MaxDatabaseBytes, data)
        != SV_OK) {
        finish(ServerProblem);
        return;
    }
    const QByteArray digest = fileDigest(data);
    const int generation = m_generation;
    m_client->upload(m_userId, m_path, data, m_mergedEtag,
                     [this, generation, digest](NextcloudClient::Result result,
                                                const QByteArray &etag) {
                         if (generation != m_generation)
                             return;
                         if (result == NextcloudClient::Ok) {
                             m_etag = etag;
                             m_digest = digest;
                             finish(NoProblem);
                         } else if ((result == NextcloudClient::FolderMissing
                                     || result == NextcloudClient::NotFound)
                                    && !m_foldersCreated) {
                             // Nextcloud answers 404 for a missing folder,
                             // the WebDAV library alone 409.
                             m_foldersCreated = true;
                             QStringList folders;
                             const QStringList parts = m_path.split(QLatin1Char('/'),
                                                                    QString::SkipEmptyParts);
                             for (int count = 1; count < parts.size(); ++count)
                                 folders.append(QLatin1Char('/')
                                                + QStringList(parts.mid(0, count))
                                                      .join(QLatin1Char('/')));
                             createFolders(folders);
                         } else if (result == NextcloudClient::PreconditionFailed
                                    && ++m_attempts < MaxAttempts) {
                             // Changed on the server meanwhile: merge that first.
                             m_etag.clear();
                             m_digestBeforeMerge.clear();
                             download();
                         } else {
                             finish(result == NextcloudClient::NotFound
                                        ? FolderMissing
                                        : problemOf(result, m_pin));
                         }
                     });
}

// Creates the missing folders of the path from the top, then uploads again.
void Sync::createFolders(const QStringList &folders)
{
    if (folders.isEmpty()) {
        upload();
        return;
    }
    const int generation = m_generation;
    m_client->createFolder(m_userId, folders.first(),
                           [this, generation, folders](NextcloudClient::Result result) {
                               if (generation != m_generation)
                                   return;
                               if (result != NextcloudClient::Ok) {
                                   finish(problemOf(result, m_pin));
                                   return;
                               }
                               createFolders(folders.mid(1));
                           });
}

void Sync::finish(Problem problem)
{
    m_running = false;
    m_waitingForSave = false;
    m_pendingData.clear();
    if (problem == NoProblem) {
        m_lastSynced = QDateTime::currentDateTimeUtc();
        remember();
    }
    m_state = problem == NoProblem ? Idle : Failed;
    m_problem = problem;
    emit stateChanged();
    if (m_again) {
        m_again = false;
        scheduleSync();
    }
}

Sync::Problem Sync::problemOf(NextcloudClient::Result result, const QByteArray &pin)
{
    switch (result) {
    case NextcloudClient::CertificateUntrusted:
        m_fingerprint = m_client->lastFingerprint();
        m_certificateReplaced = !pin.isEmpty() && pin != m_fingerprint;
        emit certificateChanged();
        return CertificateUnknown;
    case NextcloudClient::NetworkError:
        return Offline;
    case NextcloudClient::Unauthorized:
        return LoginFailed;
    case NextcloudClient::FolderMissing:
        return FolderMissing;
    default:
        return ServerProblem;
    }
}

void Sync::startLogin(const QString &server, const QString &path)
{
    if (m_vault->state() != Vault::Unlocked)
        return;
    const QUrl url = serverUrl(server);
    if (!url.isValid()) {
        setSetupState(SetupFailed, InvalidServer);
        return;
    }
    // A certificate confirmed for this server stays pinned for the retry.
    const QByteArray pin = m_setup.server.host() == url.host() ? m_setup.pin : QByteArray();
    wipeSetup();
    abortSync();
    m_setup.server = url;
    m_setup.path = remotePath(path);
    m_setup.pin = pin;
    std::function<void()> begin = [this]() {
        NextcloudClient::Account account;
        account.server = m_setup.server;
        account.pinnedCertificate = m_setup.pin;
        m_client->setAccount(account);
        setSetupState(Checking);
        const int generation = m_generation;
        m_client->startLogin(
            [this, generation](NextcloudClient::Result result, const QUrl &loginUrl) {
                if (generation != m_generation)
                    return;
                if (result != NextcloudClient::Ok) {
                    failSetup(problemOf(result, m_setup.pin), [this]() {
                        startLogin(m_setup.server.toString(), m_setup.path);
                    });
                    return;
                }
                QDesktopServices::openUrl(loginUrl);
                setSetupState(WaitingForBrowser);
            },
            [this, generation](NextcloudClient::Result result, const QString &loginName,
                               const QByteArray &appPassword) {
                if (generation != m_generation)
                    return;
                if (result != NextcloudClient::Ok) {
                    failSetup(result == NextcloudClient::NotFound ? LoginExpired
                                                                  : problemOf(result, m_setup.pin));
                    return;
                }
                m_setup.loginName = loginName;
                m_setup.appPassword = appPassword;
                checkSetup();
            });
    };
    begin();
}

void Sync::setUpManually(const QString &server, const QString &path, const QString &loginName,
                         const QString &appPassword)
{
    if (m_vault->state() != Vault::Unlocked)
        return;
    const QUrl url = serverUrl(server);
    if (!url.isValid()) {
        setSetupState(SetupFailed, InvalidServer);
        return;
    }
    const QByteArray pin = m_setup.server.host() == url.host() ? m_setup.pin : QByteArray();
    wipeSetup();
    abortSync();
    m_setup.server = url;
    m_setup.path = remotePath(path);
    m_setup.loginName = loginName.trimmed();
    m_setup.appPassword = appPassword.toUtf8();
    m_setup.pin = pin;
    checkSetup();
}

// Checks the credentials and finds the user id, then stores the settings
// in the database; the save that follows starts the first sync.
void Sync::checkSetup()
{
    NextcloudClient::Account account;
    account.server = m_setup.server;
    account.loginName = m_setup.loginName;
    account.appPassword = m_setup.appPassword;
    account.pinnedCertificate = m_setup.pin;
    m_client->setAccount(account);
    secureWipe(account.appPassword);
    setSetupState(Checking);
    const int generation = m_generation;
    m_client->userId([this, generation](NextcloudClient::Result result, const QString &id) {
        if (generation != m_generation)
            return;
        if (result != NextcloudClient::Ok) {
            failSetup(problemOf(result, m_setup.pin), [this]() { checkSetup(); });
            return;
        }
        if (!m_vault->storeSyncSettings(m_setup.server.toString(), m_setup.loginName,
                                        m_setup.appPassword, m_setup.path, m_setup.pin)) {
            failSetup(ServerProblem);
            return;
        }
        Q_UNUSED(id)
        m_remote.clear();
        wipeSetup();
        setSetupState(SetupDone);
        updateConfigured();
    });
}

void Sync::failSetup(Problem problem, const std::function<void()> &retry)
{
    m_retry = problem == CertificateUnknown ? retry : nullptr;
    setSetupState(SetupFailed, problem);
}

void Sync::cancelSetup()
{
    if (m_setupState == WaitingForBrowser || m_setupState == Checking)
        abortSync();
    wipeSetup();
    setSetupState(SetupIdle);
}

// The setup uses the client with another account; a running sync ends.
void Sync::abortSync()
{
    ++m_generation;
    m_delay->stop();
    m_client->abortAll();
    m_waitingForSave = false;
    m_pendingData.clear();
    if (m_running) {
        m_running = false;
        m_state = Idle;
        emit stateChanged();
    }
}

void Sync::trustCertificate()
{
    if (m_fingerprint.isEmpty())
        return;
    if (m_setupState == SetupFailed && m_setupProblem == CertificateUnknown && m_retry) {
        m_setup.pin = m_fingerprint;
        const std::function<void()> retry = m_retry;
        m_retry = nullptr;
        retry();
        return;
    }
    if (m_state != Failed || m_problem != CertificateUnknown)
        return;
    QByteArray password = m_vault->syncSetting(SV_SYNC_APP_PASSWORD);
    // The new pin is saved, and the save starts the next sync.
    m_vault->storeSyncSettings(QString::fromUtf8(m_vault->syncSetting(SV_SYNC_SERVER)),
                               QString::fromUtf8(m_vault->syncSetting(SV_SYNC_USER)), password,
                               QString::fromUtf8(m_vault->syncSetting(SV_SYNC_PATH)),
                               m_fingerprint);
    secureWipe(password);
}

void Sync::setSetupState(SetupState state, Problem problem)
{
    if (m_setupState == state && m_setupProblem == problem)
        return;
    m_setupState = state;
    m_setupProblem = problem;
    emit setupChanged();
}

void Sync::wipeSetup()
{
    m_client->cancelLogin();
    secureWipe(m_setup.appPassword);
    m_setup = Setup();
    m_retry = nullptr;
}
