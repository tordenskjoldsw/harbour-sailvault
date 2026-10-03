#ifndef IMPORTER_H
#define IMPORTER_H

#include <QObject>
#include <QString>

#include <atomic>
#include <memory>

#include "sailvault_core.h"

class Vault;

// Imports a Bitwarden/Vaultwarden JSON export into the unlocked database,
// merged into the group of the same name when it exists. Reading and
// decrypting the export, which runs its KDF, happens on a pool thread; the
// vault merges the result on the main thread and saves.
class Importer : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QString groupName READ groupName CONSTANT)

public:
    // The first three are export kinds from inspect(); the rest are errors.
    enum Status {
        Unencrypted,
        PasswordProtected,
        AccountRestricted,
        NotAnExport,
        FileUnreadable,
        FileTooLarge,
        WrongPassword,
        Corrupted,
        Unsupported,
        Locked,
        NotAdded,
        // Merged, but the save failed; the entries are unsaved changes.
        NotSaved,
        // The file is no longer the one that was inspected.
        FileChanged
    };
    Q_ENUM(Status)

    explicit Importer(Vault *vault, QObject *parent = nullptr);
    ~Importer() override;

    bool busy() const;
    // The group in the root group that imports go into. Not translated: a
    // later import finds it by this name.
    QString groupName() const;

    // Reads only the top level, so the UI can ask for a password or warn
    // about a plain file first.
    Q_INVOKABLE int inspect(const QString &path) const;
    Q_INVOKABLE void start(const QString &path, const QString &password);
    // Deletes the last unencrypted export whose import was merged and
    // saved; no other file can be deleted this way.
    Q_INVOKABLE bool removeImportedFile();

signals:
    void busyChanged();
    // fileRemovable: the export is unencrypted and everything in it is
    // saved, so removeImportedFile may delete it.
    void finished(int added, int updated, bool fileRemovable);
    void failed(int status);

private slots:
    void onReadFinished(int attempt, int status, qulonglong handle);
    void onSavingChanged();
    void onVaultStateChanged();

private:
    void addPendingImport();
    void finish();
    void fail(Status status);
    void setBusy(bool busy);
    void discardPendingImport();

    Vault *m_vault;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt = 0;
    bool m_busy = false;
    bool m_unencrypted = false;
    // Merged; finished once the vault's save succeeds.
    bool m_awaitingSave = false;
    int m_added = 0;
    int m_updated = 0;
    QString m_path;
    QString m_removablePath;
    SvImport *m_pending = nullptr;
};

#endif // IMPORTER_H
