#include "importer.h"

#include <QCoreApplication>
#include <QEvent>
#include <QFile>
#include <QRunnable>
#include <QThreadPool>

#include "corebridge.h"
#include "databasefile.h"
#include "vault.h"

namespace {

// The core refuses larger exports; reading stops here already.
const qint64 MaxExportBytes = 32 * 1024 * 1024;
const char GroupName[] = "Bitwarden import";

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
        return Importer::UnsupportedFormat;
    case StatusFileChanged:
        return Importer::FileChanged;
    default:
        return Importer::Corrupted;
    }
}

// Reads the export's top level on a pool thread.
class InspectTask : public QRunnable
{
public:
    InspectTask(Importer *importer, std::shared_ptr<std::atomic_bool> cancelled, int inspection,
                const QString &path)
        : m_importer(importer)
        , m_cancelled(std::move(cancelled))
        , m_inspection(inspection)
        , m_path(path)
    {
    }

    void run() override
    {
        QByteArray data;
        int status = readBoundedFile(m_path, MaxExportBytes, data);
        int32_t kind = -1;
        if (status == SV_OK)
            status = sv_bitwarden_export_kind(bytePointer(data), static_cast<size_t>(data.size()),
                                              &kind);
        secureWipe(data);
        if (!*m_cancelled)
            QMetaObject::invokeMethod(m_importer, "onInspected", Qt::QueuedConnection,
                                      Q_ARG(int, m_inspection), Q_ARG(int, status),
                                      Q_ARG(int, kind));
    }

private:
    Importer *m_importer;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_inspection;
    QString m_path;
};

// Reads, decrypts and maps the export on a pool thread. A cancelled task
// frees its result itself.
class ReadTask : public QRunnable
{
public:
    ReadTask(Importer *importer, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
             const QString &path, QByteArray password, int32_t kind)
        : m_importer(importer)
        , m_cancelled(std::move(cancelled))
        , m_attempt(attempt)
        , m_path(path)
        , m_password(std::move(password))
        , m_kind(kind)
        , m_groupName(GroupName)
    {
    }

    ~ReadTask() override
    {
        secureWipe(m_password);
    }

    void run() override
    {
        SvImport *read = nullptr;
        QByteArray data;
        int status = readBoundedFile(m_path, MaxExportBytes, data);
        // The user decided on the kind shown from an earlier read. A file
        // swapped since, such as a plain export instead of a protected one,
        // is refused instead of imported without its warning.
        int32_t kind = -1;
        if (status == SV_OK)
            status = sv_bitwarden_export_kind(bytePointer(data), static_cast<size_t>(data.size()),
                                              &kind);
        if (status == SV_OK && kind != m_kind)
            status = StatusFileChanged;
        if (status == SV_OK) {
            status = sv_bitwarden_read(bytePointer(data), static_cast<size_t>(data.size()),
                                       bytePointer(m_password),
                                       static_cast<size_t>(m_password.size()),
                                       m_kind == SV_EXPORT_PASSWORD_PROTECTED,
                                       bytePointer(m_groupName),
                                       static_cast<size_t>(m_groupName.size()), &read);
        }
        CoreImport import(read);
        secureWipe(data);
        secureWipe(m_password);

        const bool delivered = !*m_cancelled
            && QMetaObject::invokeMethod(m_importer, "onReadFinished", Qt::QueuedConnection,
                                         Q_ARG(int, m_attempt), Q_ARG(int, status),
                                         Q_ARG(qulonglong,
                                               reinterpret_cast<qulonglong>(import.get())));
        if (delivered)
            import.release();
    }

private:
    // The importer outlives every task: its destructor cancels and waits for
    // the pool.
    Importer *m_importer;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_path;
    QByteArray m_password;
    int32_t m_kind;
    QByteArray m_groupName;
};

} // namespace

Importer::Importer(Vault *vault, QObject *parent)
    : QObject(parent)
    , m_vault(vault)
    , m_cancelled(std::make_shared<std::atomic_bool>(false))
{
    connect(m_vault, &Vault::stateChanged, this, &Importer::onVaultStateChanged);
    connect(m_vault, &Vault::savingChanged, this, &Importer::onSavingChanged);
}

Importer::~Importer()
{
    m_cancelled->store(true);
    QThreadPool::globalInstance()->waitForDone();
    QCoreApplication::sendPostedEvents(this, QEvent::MetaCall);
}

bool Importer::busy() const
{
    return m_busy;
}

Importer::Kind Importer::kind() const
{
    return m_kind;
}

QString Importer::groupName() const
{
    return QString::fromUtf8(GroupName);
}

void Importer::inspect(const QString &path)
{
    m_path = path;
    setKind(Unknown);
    QThreadPool::globalInstance()->start(
        new InspectTask(this, m_cancelled, ++m_inspection, path));
}

void Importer::onInspected(int inspection, int status, int kind)
{
    if (inspection != m_inspection)
        return;
    if (status != SV_OK) {
        emit failed(statusFor(status));
        return;
    }
    switch (kind) {
    case SV_EXPORT_UNENCRYPTED:
        setKind(Unencrypted);
        break;
    case SV_EXPORT_PASSWORD_PROTECTED:
        setKind(PasswordProtected);
        break;
    default:
        setKind(AccountRestricted);
        break;
    }
}

void Importer::start(const QString &password)
{
    if (m_busy || m_vault->state() != Vault::Unlocked
        || (m_kind != Unencrypted && m_kind != PasswordProtected))
        return;
    const bool unencrypted = m_kind == Unencrypted;
    m_removablePath.clear();
    setBusy(true);
    // The task owns the only copy of the password bytes and wipes it.
    QThreadPool::globalInstance()->start(new ReadTask(
        this, m_cancelled, ++m_attempt, m_path, unencrypted ? QByteArray() : password.toUtf8(),
        unencrypted ? SV_EXPORT_UNENCRYPTED : SV_EXPORT_PASSWORD_PROTECTED));
}

void Importer::onReadFinished(int attempt, int status, qulonglong handle)
{
    CoreImport import(reinterpret_cast<SvImport *>(handle));
    if (attempt != m_attempt || !m_busy)
        return;
    if (status != SV_OK) {
        fail(statusFor(status));
        return;
    }
    m_pending = std::move(import);
    addPendingImport();
}

// An edit made while the export was read may still be saving; the vault
// takes no changes until that save is done.
void Importer::addPendingImport()
{
    if (!m_pending || m_vault->saving())
        return;
    const CoreImport import = std::move(m_pending);
    int added = 0;
    int updated = 0;
    if (!m_vault->addImport(import.get(), added, updated)) {
        fail(NotAdded);
        return;
    }
    m_added = added;
    m_updated = updated;
    // A merge that changed something started a save; the export may only
    // be deleted once its entries are on disk.
    if (m_vault->saving())
        m_awaitingSave = true;
    else
        finish();
}

void Importer::onSavingChanged()
{
    if (m_vault->saving())
        return;
    if (m_awaitingSave) {
        m_awaitingSave = false;
        if (m_vault->dirty())
            fail(NotSaved);
        else
            finish();
        return;
    }
    addPendingImport();
}

void Importer::onVaultStateChanged()
{
    if (m_vault->state() == Vault::Unlocked || !m_busy)
        return;
    ++m_attempt;
    m_awaitingSave = false;
    m_pending.reset();
    fail(Locked);
}

void Importer::finish()
{
    if (m_kind == Unencrypted && !m_vault->dirty())
        m_removablePath = m_path;
    setBusy(false);
    emit finished(m_added, m_updated, !m_removablePath.isEmpty());
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

void Importer::setKind(Kind kind)
{
    if (m_kind == kind)
        return;
    m_kind = kind;
    emit kindChanged();
}
