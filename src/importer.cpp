#include "importer.h"

#include <QCoreApplication>
#include <QEvent>
#include <QFile>
#include <QRunnable>
#include <QThreadPool>

#include "databasefile.h"
#include "secure.h"
#include "vault.h"

namespace {

// The core refuses larger exports; reading stops here already.
const qint64 MaxExportBytes = 32 * 1024 * 1024;

Importer::Status statusFor(int status)
{
    switch (status) {
    case SV_NOT_AN_EXPORT:
        return Importer::NotAnExport;
    case StatusFileUnreadable:
        return Importer::FileUnreadable;
    case StatusTooLarge:
    case SV_LIMIT_EXCEEDED:
        return Importer::FileTooLarge;
    case SV_INVALID_CREDENTIALS:
        return Importer::WrongPassword;
    case SV_UNSUPPORTED_FORMAT:
        return Importer::Unsupported;
    default:
        return Importer::Corrupted;
    }
}

const uint8_t *bytePointer(const QByteArray &bytes)
{
    return reinterpret_cast<const uint8_t *>(bytes.constData());
}

// Reads, decrypts and maps the export on a pool thread. A cancelled task
// frees its result itself.
class ReadTask : public QRunnable
{
public:
    ReadTask(Importer *importer, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
             const QString &path, const QByteArray &password, bool hasPassword,
             const QString &groupName)
        : m_importer(importer)
        , m_cancelled(std::move(cancelled))
        , m_attempt(attempt)
        , m_path(path)
        , m_password(password)
        , m_hasPassword(hasPassword)
        , m_groupName(groupName.toUtf8())
    {
    }

    ~ReadTask() override
    {
        secureWipe(m_password);
    }

    void run() override
    {
        SvImport *import = nullptr;
        QByteArray data;
        int status = readDatabaseFile(m_path, MaxExportBytes, data);
        if (status == SV_OK) {
            status = sv_bitwarden_read(bytePointer(data), static_cast<size_t>(data.size()),
                                       bytePointer(m_password),
                                       static_cast<size_t>(m_password.size()), m_hasPassword,
                                       bytePointer(m_groupName),
                                       static_cast<size_t>(m_groupName.size()), &import);
        }
        secureWipe(data);
        secureWipe(m_password);

        const bool delivered = !*m_cancelled
            && QMetaObject::invokeMethod(m_importer, "onReadFinished", Qt::QueuedConnection,
                                         Q_ARG(int, m_attempt), Q_ARG(int, status),
                                         Q_ARG(qulonglong, reinterpret_cast<qulonglong>(import)));
        if (!delivered)
            sv_import_free(import);
    }

private:
    // The importer outlives every task: its destructor cancels and waits for
    // the pool.
    Importer *m_importer;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_path;
    QByteArray m_password;
    bool m_hasPassword;
    QByteArray m_groupName;
};

} // namespace

Importer::Importer(Vault *vault, QObject *parent)
    : QObject(parent)
    , m_vault(vault)
    , m_cancelled(std::make_shared<std::atomic_bool>(false))
{
    connect(m_vault, &Vault::stateChanged, this, &Importer::onVaultStateChanged);
    connect(m_vault, &Vault::savingChanged, this, &Importer::addPendingImport);
}

Importer::~Importer()
{
    m_cancelled->store(true);
    QThreadPool::globalInstance()->waitForDone();
    QCoreApplication::sendPostedEvents(this, QEvent::MetaCall);
    discardPendingImport();
}

bool Importer::busy() const
{
    return m_busy;
}

int Importer::inspect(const QString &path) const
{
    QByteArray data;
    int status = readDatabaseFile(path, MaxExportBytes, data);
    int32_t kind = SV_EXPORT_UNENCRYPTED;
    if (status == SV_OK)
        status = sv_bitwarden_export_kind(bytePointer(data), static_cast<size_t>(data.size()), &kind);
    secureWipe(data);
    if (status != SV_OK)
        return statusFor(status);
    switch (kind) {
    case SV_EXPORT_UNENCRYPTED:
        return Unencrypted;
    case SV_EXPORT_PASSWORD_PROTECTED:
        return PasswordProtected;
    default:
        return AccountRestricted;
    }
}

void Importer::start(const QString &path, const QString &password, const QString &groupName)
{
    if (m_busy || m_vault->state() != Vault::Unlocked)
        return;
    const int kind = inspect(path);
    if (kind != Unencrypted && kind != PasswordProtected) {
        fail(kind == AccountRestricted ? Unsupported : static_cast<Status>(kind));
        return;
    }
    m_path = path;
    m_unencrypted = kind == Unencrypted;
    m_removablePath.clear();
    QByteArray passwordBytes = password.toUtf8();
    setBusy(true);
    QThreadPool::globalInstance()->start(new ReadTask(this, m_cancelled, ++m_attempt, path,
                                                      passwordBytes, !m_unencrypted, groupName));
    secureWipe(passwordBytes);
}

void Importer::onReadFinished(int attempt, int status, qulonglong handle)
{
    SvImport *import = reinterpret_cast<SvImport *>(handle);
    if (attempt != m_attempt || !m_busy) {
        sv_import_free(import);
        return;
    }
    if (status != SV_OK) {
        sv_import_free(import);
        fail(statusFor(status));
        return;
    }
    m_pending = import;
    addPendingImport();
}

// An edit made while the export was read may still be saving; the vault
// takes no changes until that save is done.
void Importer::addPendingImport()
{
    if (!m_pending || m_vault->saving())
        return;
    SvImport *import = m_pending;
    m_pending = nullptr;
    int added = 0;
    int updated = 0;
    const bool merged = m_vault->addImport(import, added, updated);
    sv_import_free(import);
    if (!merged) {
        fail(NotAdded);
        return;
    }
    if (m_unencrypted)
        m_removablePath = m_path;
    setBusy(false);
    emit finished(added, updated, m_unencrypted);
}

void Importer::onVaultStateChanged()
{
    if (m_vault->state() == Vault::Unlocked || !m_busy)
        return;
    ++m_attempt;
    discardPendingImport();
    fail(Locked);
}

bool Importer::removeImportedFile()
{
    if (m_removablePath.isEmpty())
        return false;
    const bool removed = QFile::remove(m_removablePath);
    m_removablePath.clear();
    return removed;
}

void Importer::fail(Status status)
{
    setBusy(false);
    emit failed(status);
}

void Importer::setBusy(bool busy)
{
    if (m_busy == busy)
        return;
    m_busy = busy;
    emit busyChanged();
}

void Importer::discardPendingImport()
{
    sv_import_free(m_pending);
    m_pending = nullptr;
}
