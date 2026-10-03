#include "vault.h"

#include <QByteArray>
#include <QCoreApplication>
#include <QEvent>
#include <QFile>
#include <QGuiApplication>
#include <QPointer>
#include <QRunnable>
#include <QSettings>
#include <QStandardPaths>
#include <QThreadPool>

#include "boottime.h"
#include "secure.h"

namespace {

const long long IdleLockMs = 5 * 60 * 1000;
const long long BackgroundLockMs = 60 * 1000;
// Bounds how late a deadline is enforced after the phone wakes up.
const int WatchdogIntervalMs = 5 * 1000;
const qint64 MaxDatabaseBytes = 256 * 1024 * 1024;
const qint64 MaxKeyFileBytes = 1024 * 1024;
const int StatusFileUnreadable = -1;
const int StatusTooLarge = -2;

QString settingsPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        + QStringLiteral("/settings.ini");
}

// Reads at most the size seen at open time into one exact allocation, so a
// file swapped while reading cannot grow the buffer and no partial copies
// are left behind by reallocation.
int readFile(const QString &path, qint64 maxBytes, QByteArray &out)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return StatusFileUnreadable;
    const qint64 size = file.size();
    if (size > maxBytes)
        return StatusTooLarge;
    out = QByteArray(static_cast<int>(size), Qt::Uninitialized);
    if (size > 0 && file.read(out.data(), size) != size) {
        secureWipe(out);
        return StatusFileUnreadable;
    }
    return SV_OK;
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
        const int status = open(&database);
        secureWipe(m_password);

        const bool delivered = !*m_cancelled
            && QMetaObject::invokeMethod(m_vault, "onUnlockFinished", Qt::QueuedConnection,
                                         Q_ARG(int, m_attempt), Q_ARG(int, status),
                                         Q_ARG(qulonglong, reinterpret_cast<qulonglong>(database)));
        if (!delivered)
            sv_database_free(database);
    }

private:
    int open(SvDatabase **database)
    {
        QByteArray data;
        int status = readFile(m_databasePath, MaxDatabaseBytes, data);
        if (status != SV_OK)
            return status;
        QByteArray keyFile;
        if (!m_keyFilePath.isEmpty()) {
            status = readFile(m_keyFilePath, MaxKeyFileBytes, keyFile);
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
    default:
        return Vault::Corrupted;
    }
}

QByteArray entryUuid(const QString &entryId)
{
    const QByteArray uuid = QByteArray::fromHex(entryId.toLatin1());
    return uuid.size() == SV_UUID_LENGTH ? uuid : QByteArray();
}

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
    QThreadPool::globalInstance()->waitForDone();
    // A task may have posted its result before it saw the cancellation;
    // deliver it now so onUnlockFinished frees the handle.
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

void Vault::onUnlockFinished(int attempt, int status, qulonglong handle)
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
    m_database = database;
    saveSettings();
    m_lastActivityMs = bootTimeMs();
    m_idleTimer.start();
    setState(Unlocked);
    // The app may have left the foreground while the KDF ran.
    onApplicationStateChanged(QGuiApplication::applicationState());
}

void Vault::lock()
{
    m_idleTimer.stop();
    m_backgroundSinceMs = 0;
    m_clipboard.clear();
    updateWatchdog();
    ++m_attempt;
    if (m_state == Unlocking) {
        setState(Locked);
        return;
    }
    if (!m_database)
        return;
    sv_database_free(m_database);
    m_database = nullptr;
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

QVariantList Vault::fields(const QString &entryId)
{
    QVariantList result;
    const QByteArray uuid = entryUuid(entryId);
    const SvDatabase *handle = database();
    SvFieldList *fields = nullptr;
    if (!handle || uuid.isEmpty()
        || sv_database_fields(handle, reinterpret_cast<const uint8_t *>(uuid.constData()),
                              &fields) != SV_OK)
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

QString Vault::fieldValue(const QString &entryId, const QString &key)
{
    return database() ? readField(entryId, key) : QString();
}

QString Vault::readField(const QString &entryId, const QString &key) const
{
    const QByteArray uuid = entryUuid(entryId);
    const QByteArray keyBytes = key.toUtf8();
    SvString value = emptyCoreString();
    if (!m_database || uuid.isEmpty()
        || sv_database_field_value(m_database, reinterpret_cast<const uint8_t *>(uuid.constData()),
                                   reinterpret_cast<const uint8_t *>(keyBytes.constData()),
                                   static_cast<size_t>(keyBytes.size()), &value) != SV_OK)
        return QString();
    return takeCoreString(value);
}

bool Vault::copyField(const QString &entryId, const QString &key)
{
    const QString value = fieldValue(entryId, key);
    if (value.isEmpty())
        return false;
    // The guard compares against the core's value instead of keeping a copy
    // or hash; lock() clears the clipboard before it frees the database.
    m_clipboard.copy(value, [this, entryId, key] { return readField(entryId, key); });
    updateWatchdog();
    return true;
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

void Vault::saveSettings() const
{
    QSettings settings(settingsPath(), QSettings::IniFormat);
    settings.setValue(QStringLiteral("databasePath"), m_databasePath);
    settings.setValue(QStringLiteral("keyFilePath"), m_keyFilePath);
}
