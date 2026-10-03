#include "vault.h"

#include <QByteArray>
#include <QEvent>
#include <QFile>
#include <QGuiApplication>
#include <QPointer>
#include <QRunnable>
#include <QSettings>
#include <QStandardPaths>
#include <QThreadPool>

#include "secure.h"

namespace {

const int IdleLockMs = 5 * 60 * 1000;
const int BackgroundLockMs = 60 * 1000;
const qint64 MaxDatabaseBytes = 256 * 1024 * 1024;
const qint64 MaxKeyFileBytes = 1024 * 1024;
const int StatusFileUnreadable = -1;
const int StatusTooLarge = -2;

QString settingsPath()
{
    return QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation)
        + QStringLiteral("/settings.ini");
}

int readFile(const QString &path, qint64 maxBytes, QByteArray &out)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return StatusFileUnreadable;
    if (file.size() > maxBytes)
        return StatusTooLarge;
    out = file.readAll();
    return file.error() == QFileDevice::NoError ? SV_OK : StatusFileUnreadable;
}

// Reads the files and runs the KDF on a pool thread, then hands the result
// to the vault on its own thread.
class UnlockTask : public QRunnable
{
public:
    UnlockTask(Vault *vault, int attempt, const QString &databasePath,
               const QString &keyFilePath, const QByteArray &password)
        : m_vault(vault)
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

        const QPointer<Vault> vault = m_vault;
        const bool delivered = vault
            && QMetaObject::invokeMethod(vault, "onUnlockFinished", Qt::QueuedConnection,
                                         Q_ARG(int, m_attempt), Q_ARG(int, status),
                                         Q_ARG(quintptr, reinterpret_cast<quintptr>(database)));
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
        status = sv_database_open(reinterpret_cast<const uint8_t *>(data.constData()),
                                  static_cast<size_t>(data.size()),
                                  reinterpret_cast<const uint8_t *>(m_password.constData()),
                                  static_cast<size_t>(m_password.size()), !m_password.isEmpty(),
                                  reinterpret_cast<const uint8_t *>(keyFile.constData()),
                                  static_cast<size_t>(keyFile.size()), database);
        secureWipe(keyFile);
        return status;
    }

    QPointer<Vault> m_vault;
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
{
    const QSettings settings(settingsPath(), QSettings::IniFormat);
    m_databasePath = settings.value(QStringLiteral("databasePath")).toString();
    m_keyFilePath = settings.value(QStringLiteral("keyFilePath")).toString();

    m_idleTimer.setSingleShot(true);
    m_idleTimer.setInterval(IdleLockMs);
    m_backgroundTimer.setSingleShot(true);
    m_backgroundTimer.setInterval(BackgroundLockMs);
    connect(&m_idleTimer, &QTimer::timeout, this, &Vault::lockAutomatically);
    connect(&m_backgroundTimer, &QTimer::timeout, this, &Vault::lockAutomatically);
    connect(qApp, &QGuiApplication::applicationStateChanged, this,
            &Vault::onApplicationStateChanged);
    connect(qApp, &QCoreApplication::aboutToQuit, this, &Vault::lock);
    qApp->installEventFilter(this);
}

Vault::~Vault()
{
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
    emit keyFilePathChanged();
}

const SvDatabase *Vault::database() const
{
    return m_database;
}

void Vault::unlock(const QString &password)
{
    if (m_state != Locked || m_databasePath.isEmpty())
        return;
    QByteArray passwordBytes = password.toUtf8();
    setError(NoError);
    setState(Unlocking);
    QThreadPool::globalInstance()->start(
        new UnlockTask(this, ++m_attempt, m_databasePath, m_keyFilePath, passwordBytes));
    secureWipe(passwordBytes);
}

void Vault::onUnlockFinished(int attempt, int status, quintptr handle)
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
    m_idleTimer.start();
    setState(Unlocked);
}

void Vault::lock()
{
    m_idleTimer.stop();
    m_backgroundTimer.stop();
    m_clipboard.clear();
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

void Vault::lockAutomatically()
{
    if (m_state != Unlocked)
        return;
    lock();
    emit lockedAutomatically();
}

QVariantList Vault::fields(const QString &entryId) const
{
    QVariantList result;
    const QByteArray uuid = entryUuid(entryId);
    SvFieldList *fields = nullptr;
    if (!m_database || uuid.isEmpty()
        || sv_database_fields(m_database, reinterpret_cast<const uint8_t *>(uuid.constData()),
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

QString Vault::fieldValue(const QString &entryId, const QString &key) const
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
    m_clipboard.copy(value);
    return true;
}

bool Vault::eventFilter(QObject *watched, QEvent *event)
{
    switch (event->type()) {
    case QEvent::TouchBegin:
    case QEvent::MouseButtonPress:
    case QEvent::KeyPress:
        if (m_state == Unlocked)
            m_idleTimer.start();
        break;
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void Vault::onApplicationStateChanged(Qt::ApplicationState state)
{
    if (m_state != Unlocked)
        return;
    if (state == Qt::ApplicationActive)
        m_backgroundTimer.stop();
    else if (!m_backgroundTimer.isActive())
        m_backgroundTimer.start();
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
