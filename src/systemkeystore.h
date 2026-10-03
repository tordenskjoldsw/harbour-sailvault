#ifndef SYSTEMKEYSTORE_H
#define SYSTEMKEYSTORE_H

#include <QObject>
#include <QScopedPointer>
#include <QString>

#include <functional>

#include <Sailfish/Secrets/request.h>
#include <Sailfish/Secrets/result.h>
#include <Sailfish/Secrets/secretmanager.h>

class SystemKeyStore : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(QString status READ status NOTIFY statusChanged)

public:
    enum LockMode {
        VerifyLock,
        Relock
    };
    Q_ENUM(LockMode)

    explicit SystemKeyStore(QObject *parent = nullptr);

    bool busy() const;
    QString status() const;

    Q_INVOKABLE void storeTestKey(LockMode mode);
    Q_INVOKABLE void readTestKey(LockMode mode);
    Q_INVOKABLE void deleteTestKey(LockMode mode);

signals:
    void busyChanged();
    void statusChanged();

private:
    bool canStart();
    void storeGeneratedKey(LockMode mode);
    void run(Sailfish::Secrets::Request *request, const QString &activity,
             std::function<void(const Sailfish::Secrets::Result &)> onFinished);
    void finish(const QString &status);
    void finishWithError(const QString &operation, const Sailfish::Secrets::Result &result);
    void setBusy(bool busy);
    void setStatus(const QString &status);

    Sailfish::Secrets::SecretManager m_manager;
    QScopedPointer<Sailfish::Secrets::Request, QScopedPointerDeleteLater> m_request;
    bool m_busy = false;
    QString m_status;
};

#endif // SYSTEMKEYSTORE_H
