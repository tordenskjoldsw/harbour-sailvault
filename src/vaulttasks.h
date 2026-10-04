#ifndef VAULTTASKS_H
#define VAULTTASKS_H

#include <QByteArray>
#include <QRunnable>
#include <QString>

#include <atomic>
#include <memory>

#include "sailvault_core.h"

class Vault;

// The vault's work on pool threads. Each task hands its result to a private
// slot of the vault through a queued call. A task whose result is no longer
// wanted frees it itself. The vault outlives every task: its destructor
// cancels and waits for the pool.

// Reads the database and key file and runs the KDF.
class UnlockTask : public QRunnable
{
public:
    UnlockTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
               const QString &databasePath, const QString &keyFilePath, QByteArray password);
    ~UnlockTask() override;

    void run() override;

private:
    int open(SvDatabase **database, QByteArray &digest);

    Vault *m_vault;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_databasePath;
    QString m_keyFilePath;
    QByteArray m_password;
};

// Serializes the database, which runs the KDF, and replaces the file. The
// vault keeps the handle alive and read-only until the result arrives.
class SaveTask : public QRunnable
{
public:
    SaveTask(Vault *vault, int attempt, const SvDatabase *database, const QString &databasePath,
             const QByteArray &expectedDigest);

    void run() override;

private:
    Vault *m_vault;
    int m_attempt;
    const SvDatabase *m_database;
    QString m_databasePath;
    QByteArray m_expectedDigest;
};

// Reads a database file and its key file from outside the app, unlocks
// them and stores copies under name. The unlocked handle is handed over like
// an unlock does.
class AddTask : public QRunnable
{
public:
    AddTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
            const QString &databasePath, const QString &keyFilePath, const QString &name,
            QByteArray password);
    ~AddTask() override;

    void run() override;

private:
    int add(SvDatabase **database, QByteArray &digest);

    Vault *m_vault;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_databasePath;
    QString m_keyFilePath;
    QString m_name;
    QByteArray m_password;
};

// Creates the database and stores its file under name, then hands over the
// unlocked handle like an unlock does.
class CreateTask : public QRunnable
{
public:
    CreateTask(Vault *vault, std::shared_ptr<std::atomic_bool> cancelled, int attempt,
               const QString &name, QByteArray password, uint32_t kdfLevel);
    ~CreateTask() override;

    void run() override;

private:
    Vault *m_vault;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    int m_attempt;
    QString m_name;
    QByteArray m_password;
    uint32_t m_kdfLevel;
};

#endif // VAULTTASKS_H
