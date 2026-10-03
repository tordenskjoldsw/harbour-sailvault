#ifndef IMPORTER_H
#define IMPORTER_H

#include <QObject>
#include <QString>

#include <atomic>
#include <memory>

#include "corebridge.h"

class Vault;

// Imports a Bitwarden/Vaultwarden JSON export into the unlocked database,
// merged into the group of the same name when it exists. Reading and
// decrypting the export, which runs its KDF, happens on a pool thread; the
// vault merges the result on the main thread and saves.
class Importer : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(Kind kind READ kind NOTIFY kindChanged)
    Q_PROPERTY(QString groupName READ groupName CONSTANT)

public:
    // What inspect found; Unknown until it is done or when it failed.
    enum Kind {
        Unknown,
        Unencrypted,
        PasswordProtected,
        // Encrypted with the account key, which only Bitwarden has.
        AccountRestricted
    };
    Q_ENUM(Kind)

    enum Status {
        NotAnExport,
        FileUnreadable,
        FileTooLarge,
        WrongPassword,
        Corrupted,
        // Encrypted in a way the core does not read.
        UnsupportedFormat,
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
    Kind kind() const;
    // The group in the root group that imports go into. Not translated: a
    // later import finds it by this name.
    QString groupName() const;

    // Reads the top level of the export at path on a pool thread, so the UI
    // can ask for a password or warn about a plain file first; sets kind or
    // reports failed.
    Q_INVOKABLE void inspect(const QString &path);
    // Imports the inspected export; the password is ignored for an
    // unencrypted one.
    Q_INVOKABLE void start(const QString &password);
    // Deletes the last unencrypted export whose import was merged and
    // saved; no other file can be deleted this way.
    Q_INVOKABLE bool removeImportedFile();

signals:
    void busyChanged();
    void kindChanged();
    // fileRemovable: the export is unencrypted and everything in it is
    // saved, so removeImportedFile may delete it.
    void finished(int added, int updated, bool fileRemovable);
    void failed(int status);

private slots:
    void onInspected(int inspection, int status, int kind);
    void onReadFinished(int attempt, int status, qulonglong handle);
    void onSavingChanged();
    void onVaultStateChanged();

private:
    void addPendingImport();
    void finish();
    void fail(Status status);
    void setBusy(bool busy);
    void setKind(Kind kind);

    Vault *m_vault;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt = 0;
    int m_inspection = 0;
    bool m_busy = false;
    Kind m_kind = Unknown;
    // Merged; finished once the vault's save succeeds.
    bool m_awaitingSave = false;
    int m_added = 0;
    int m_updated = 0;
    QString m_path;
    QString m_removablePath;
    CoreImport m_pending;
};

#endif // IMPORTER_H
