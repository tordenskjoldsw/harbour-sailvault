#ifndef NEXTCLOUD_H
#define NEXTCLOUD_H

#include <QByteArray>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>
#include <QUrl>

#include <functional>

class QNetworkReply;
class QNetworkRequest;
class QTimer;

// HTTP client for one Nextcloud server: Login Flow v2, the account's user
// id, and WebDAV download and upload of one file with ETags.
//
// Every request carries Basic auth itself; redirects are not followed,
// since Qt 5.6 would send the credentials to any redirect target, and
// cookies are not kept. Only https is used. A certificate the system does
// not trust is accepted only when its SHA-256 fingerprint equals the
// pinned one; otherwise the request fails with CertificateUntrusted and
// lastFingerprint() names the certificate for the user to confirm.
class NextcloudClient : public QObject
{
    Q_OBJECT

public:
    enum Result {
        Ok,
        NotModified,
        NotFound,
        // The file changed on the server, or exists where a new one was to
        // be created.
        PreconditionFailed,
        // The folder of the file does not exist.
        FolderMissing,
        Unauthorized,
        CertificateUntrusted,
        NetworkError,
        ServerError
    };

    struct Account {
        QUrl server;
        QString loginName;
        QByteArray appPassword;
        // Hex SHA-256 of a pinned self-signed certificate, or empty.
        QByteArray pinnedCertificate;
    };

    using Done = std::function<void(Result result)>;
    using Downloaded = std::function<void(Result result, const QByteArray &data,
                                          const QByteArray &etag)>;
    using Uploaded = std::function<void(Result result, const QByteArray &etag)>;
    using UserId = std::function<void(Result result, const QString &userId)>;
    using LoginStarted = std::function<void(Result result, const QUrl &loginUrl)>;
    using LoginGranted = std::function<void(Result result, const QString &loginName,
                                            const QByteArray &appPassword)>;

    explicit NextcloudClient(QObject *parent = nullptr);
    ~NextcloudClient() override;

    // Replaces the account and drops open connections, which may have been
    // made under another pin.
    void setAccount(const Account &account);
    void clearAccount();
    QByteArray lastFingerprint() const;

    void userId(const UserId &done);
    // path is the file in the user's files, starting with a slash.
    // ifNoneMatch is the ETag already known, or empty.
    void download(const QString &userId, const QString &path, const QByteArray &ifNoneMatch,
                  const Downloaded &done);
    // ifMatch is the ETag the upload replaces; empty creates the file and
    // fails with PreconditionFailed if it exists.
    void upload(const QString &userId, const QString &path, const QByteArray &data,
                const QByteArray &ifMatch, const Uploaded &done);
    // Creates the folder at path, whose parent must exist; a folder that is
    // already there counts as created.
    void createFolder(const QString &userId, const QString &path, const Done &done);

    // Login Flow v2: asks the server of the account for a login URL to open
    // in the browser, then polls until the user granted access, the flow
    // expired or cancelLogin was called.
    void startLogin(const LoginStarted &started, const LoginGranted &granted);
    void cancelLogin();
    void abortAll();

signals:
    // Every request has finished or was aborted.
    void idle();

private:
    QNetworkRequest request(const QUrl &url, bool authenticated) const;
    QUrl fileUrl(const QString &userId, const QString &path) const;
    // Watches the reply: pinning, inactivity timeout and the result.
    QNetworkReply *track(QNetworkReply *reply, const std::function<void(QNetworkReply *)> &done);
    Result resultOf(QNetworkReply *reply) const;
    void poll();
    void finishLogin(Result result, const QString &loginName, const QByteArray &appPassword);

    QNetworkAccessManager *m_network;
    Account m_account;
    QByteArray m_lastFingerprint;
    int m_running = 0;
    // Login Flow v2 state. The poll token yields the app password, so it
    // stays here and is wiped when the flow ends.
    QTimer *m_pollTimer;
    QUrl m_pollEndpoint;
    QByteArray m_pollToken;
    qint64 m_loginDeadline = 0;
    QNetworkReply *m_pollReply = nullptr;
    LoginGranted m_granted;
};

#endif // NEXTCLOUD_H
