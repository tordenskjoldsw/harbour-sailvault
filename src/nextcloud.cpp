#include "nextcloud.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QList>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <QSslError>
#include <QTimer>

#include "corebridge.h"

namespace {

const int InactivityTimeoutMs = 30 * 1000;
const int PollIntervalMs = 3 * 1000;
// Nextcloud deletes a login flow after 20 minutes.
const qint64 LoginLifetimeMs = 20 * 60 * 1000;
const QByteArray UserAgent = QByteArrayLiteral("SailVault (Sailfish OS)");

// Errors a pinned self-signed certificate raises. With the exact
// certificate pinned, its name does not need to match the host either.
bool expectedForPinned(QSslError::SslError error)
{
    switch (error) {
    case QSslError::SelfSignedCertificate:
    case QSslError::SelfSignedCertificateInChain:
    case QSslError::UnableToGetLocalIssuerCertificate:
    case QSslError::UnableToVerifyFirstCertificate:
    case QSslError::CertificateUntrusted:
    case QSslError::HostNameMismatch:
        return true;
    default:
        return false;
    }
}

bool sameServer(const QUrl &url, const QUrl &server)
{
    return url.scheme() == QLatin1String("https") && url.host() == server.host()
        && url.port(443) == server.port(443);
}

QByteArray etagOf(QNetworkReply *reply)
{
    // Nextcloud copies the ETag into OC-ETag because proxies may change it.
    const QByteArray etag = reply->rawHeader("OC-ETag");
    return etag.isEmpty() ? reply->rawHeader("ETag") : etag;
}

} // namespace

NextcloudClient::NextcloudClient(QObject *parent)
    : QObject(parent)
    , m_network(new QNetworkAccessManager(this))
    , m_pollTimer(new QTimer(this))
{
    m_pollTimer->setSingleShot(true);
    m_pollTimer->setInterval(PollIntervalMs);
    connect(m_pollTimer, &QTimer::timeout, this, &NextcloudClient::poll);
}

NextcloudClient::~NextcloudClient()
{
    cancelLogin();
    secureWipe(m_account.appPassword);
}

void NextcloudClient::setAccount(const Account &account)
{
    secureWipe(m_account.appPassword);
    m_account = account;
    m_network->clearAccessCache();
}

void NextcloudClient::clearAccount()
{
    setAccount(Account());
}

QByteArray NextcloudClient::lastFingerprint() const
{
    return m_lastFingerprint;
}

QNetworkRequest NextcloudClient::request(const QUrl &url, bool authenticated) const
{
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::UserAgentHeader, UserAgent);
    request.setAttribute(QNetworkRequest::FollowRedirectsAttribute, false);
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute, QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    if (authenticated) {
        QByteArray credentials = m_account.loginName.toUtf8() + ':' + m_account.appPassword;
        QByteArray header = "Basic " + credentials.toBase64();
        request.setRawHeader("Authorization", header);
        secureWipe(credentials);
        secureWipe(header);
    }
    return request;
}

QUrl NextcloudClient::fileUrl(const QString &userId, const QString &path) const
{
    QUrl url = m_account.server;
    QString base = url.path(QUrl::FullyDecoded);
    while (base.endsWith(QLatin1Char('/')))
        base.chop(1);
    url.setPath(base + QStringLiteral("/remote.php/dav/files/") + userId + path,
                QUrl::DecodedMode);
    return url;
}

QNetworkReply *NextcloudClient::track(QNetworkReply *reply,
                                      const std::function<void(QNetworkReply *)> &done)
{
    ++m_running;
    QTimer *inactivity = new QTimer(reply);
    inactivity->setSingleShot(true);
    inactivity->setInterval(InactivityTimeoutMs);
    connect(inactivity, &QTimer::timeout, reply, &QNetworkReply::abort);
    auto activity = [inactivity](qint64, qint64) { inactivity->start(); };
    connect(reply, &QNetworkReply::uploadProgress, inactivity, activity);
    connect(reply, &QNetworkReply::downloadProgress, inactivity, activity);
    inactivity->start();

    connect(reply, &QNetworkReply::sslErrors, this, [this, reply](const QList<QSslError> &errors) {
        QSslCertificate peer = reply->sslConfiguration().peerCertificate();
        if (peer.isNull() && !errors.isEmpty())
            peer = errors.first().certificate();
        m_lastFingerprint = peer.digest(QCryptographicHash::Sha256).toHex();
        if (m_account.pinnedCertificate.isEmpty()
            || m_lastFingerprint != m_account.pinnedCertificate)
            return;
        QList<QSslError> expected;
        for (const QSslError &error : errors) {
            if (error.certificate() == peer && expectedForPinned(error.error()))
                expected.append(error);
        }
        // Anything else, such as an expired certificate, still fails.
        if (expected.size() == errors.size())
            reply->ignoreSslErrors(expected);
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, done]() {
        done(reply);
        reply->deleteLater();
        if (--m_running == 0)
            emit idle();
    });
    return reply;
}

NextcloudClient::Result NextcloudClient::resultOf(QNetworkReply *reply) const
{
    if (reply->error() == QNetworkReply::SslHandshakeFailedError)
        return CertificateUntrusted;
    const QVariant code = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    if (!code.isValid())
        return NetworkError;
    const int status = code.toInt();
    if (status >= 200 && status < 300)
        return Ok;
    switch (status) {
    case 304:
        return NotModified;
    case 401:
    case 403:
        return Unauthorized;
    case 404:
        return NotFound;
    case 409:
        return FolderMissing;
    case 412:
        return PreconditionFailed;
    default:
        // Redirects are not followed and count as server errors.
        return ServerError;
    }
}

void NextcloudClient::userId(const UserId &done)
{
    QUrl url = m_account.server;
    QString base = url.path(QUrl::FullyDecoded);
    while (base.endsWith(QLatin1Char('/')))
        base.chop(1);
    url.setPath(base + QStringLiteral("/ocs/v2.php/cloud/user"), QUrl::DecodedMode);
    url.setQuery(QStringLiteral("format=json"));
    QNetworkRequest request = this->request(url, true);
    request.setRawHeader("OCS-APIRequest", "true");
    track(m_network->get(request), [this, done](QNetworkReply *reply) {
        const Result result = resultOf(reply);
        const QString id = QJsonDocument::fromJson(reply->readAll())
                               .object()
                               .value(QStringLiteral("ocs"))
                               .toObject()
                               .value(QStringLiteral("data"))
                               .toObject()
                               .value(QStringLiteral("id"))
                               .toString();
        if (result == Ok && id.isEmpty())
            done(ServerError, QString());
        else
            done(result, id);
    });
}

void NextcloudClient::download(const QString &userId, const QString &path,
                               const QByteArray &ifNoneMatch, const Downloaded &done)
{
    QNetworkRequest request = this->request(fileUrl(userId, path), true);
    if (!ifNoneMatch.isEmpty())
        request.setRawHeader("If-None-Match", ifNoneMatch);
    track(m_network->get(request), [this, done](QNetworkReply *reply) {
        const Result result = resultOf(reply);
        if (result == Ok)
            done(result, reply->readAll(), etagOf(reply));
        else
            done(result, QByteArray(), QByteArray());
    });
}

void NextcloudClient::upload(const QString &userId, const QString &path, const QByteArray &data,
                             const QByteArray &ifMatch, const Uploaded &done)
{
    QNetworkRequest request = this->request(fileUrl(userId, path), true);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QByteArrayLiteral("application/octet-stream"));
    if (ifMatch.isEmpty())
        request.setRawHeader("If-None-Match", "*");
    else
        request.setRawHeader("If-Match", ifMatch);
    track(m_network->put(request, data), [this, done](QNetworkReply *reply) {
        const Result result = resultOf(reply);
        done(result, result == Ok ? etagOf(reply) : QByteArray());
    });
}

void NextcloudClient::createFolder(const QString &userId, const QString &path, const Done &done)
{
    QNetworkRequest request = this->request(fileUrl(userId, path), true);
    track(m_network->sendCustomRequest(request, QByteArrayLiteral("MKCOL")),
          [this, done](QNetworkReply *reply) {
              const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
              // 405: there is already something at this path.
              done(status == 405 ? Ok : resultOf(reply));
          });
}

void NextcloudClient::startLogin(const LoginStarted &started, const LoginGranted &granted)
{
    cancelLogin();
    QUrl url = m_account.server;
    QString base = url.path(QUrl::FullyDecoded);
    while (base.endsWith(QLatin1Char('/')))
        base.chop(1);
    url.setPath(base + QStringLiteral("/index.php/login/v2"), QUrl::DecodedMode);
    track(m_network->post(request(url, false), QByteArray()),
          [this, started, granted](QNetworkReply *reply) {
              const Result result = resultOf(reply);
              const QJsonObject answer = QJsonDocument::fromJson(reply->readAll()).object();
              const QJsonObject poll = answer.value(QStringLiteral("poll")).toObject();
              const QUrl endpoint(poll.value(QStringLiteral("endpoint")).toString());
              const QUrl login(answer.value(QStringLiteral("login")).toString());
              QByteArray token = poll.value(QStringLiteral("token")).toString().toUtf8();
              // The poll token yields the app password: it goes only to the
              // server the user entered, never to the browser.
              if (result != Ok || token.isEmpty() || !sameServer(endpoint, m_account.server)
                  || !sameServer(login, m_account.server)) {
                  secureWipe(token);
                  started(result == Ok ? ServerError : result, QUrl());
                  return;
              }
              m_pollEndpoint = endpoint;
              m_pollToken = token;
              secureWipe(token);
              m_granted = granted;
              m_loginDeadline = QDateTime::currentMSecsSinceEpoch() + LoginLifetimeMs;
              m_pollTimer->start();
              started(Ok, login);
          });
}

void NextcloudClient::poll()
{
    if (m_pollToken.isEmpty())
        return;
    if (QDateTime::currentMSecsSinceEpoch() > m_loginDeadline) {
        finishLogin(NotFound, QString(), QByteArray());
        return;
    }
    QNetworkRequest request = this->request(m_pollEndpoint, false);
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QByteArrayLiteral("application/x-www-form-urlencoded"));
    QByteArray body = "token=" + QUrl::toPercentEncoding(QString::fromUtf8(m_pollToken));
    m_pollReply = track(m_network->post(request, body), [this](QNetworkReply *reply) {
        m_pollReply = nullptr;
        if (m_pollToken.isEmpty())
            return;
        const Result result = resultOf(reply);
        if (result == CertificateUntrusted) {
            finishLogin(result, QString(), QByteArray());
            return;
        }
        if (result != Ok) {
            // Pending (404) or a passing network problem: ask again.
            m_pollTimer->start();
            return;
        }
        QByteArray answer = reply->readAll();
        const QJsonObject granted = QJsonDocument::fromJson(answer).object();
        secureWipe(answer);
        const QString loginName = granted.value(QStringLiteral("loginName")).toString();
        QByteArray appPassword = granted.value(QStringLiteral("appPassword")).toString().toUtf8();
        const QUrl server(granted.value(QStringLiteral("server")).toString());
        if (loginName.isEmpty() || appPassword.isEmpty() || !sameServer(server, m_account.server)) {
            secureWipe(appPassword);
            finishLogin(ServerError, QString(), QByteArray());
            return;
        }
        finishLogin(Ok, loginName, appPassword);
        secureWipe(appPassword);
    });
    secureWipe(body);
}

void NextcloudClient::finishLogin(Result result, const QString &loginName,
                                  const QByteArray &appPassword)
{
    const LoginGranted granted = m_granted;
    cancelLogin();
    if (granted)
        granted(result, loginName, appPassword);
}

void NextcloudClient::cancelLogin()
{
    m_pollTimer->stop();
    secureWipe(m_pollToken);
    m_granted = nullptr;
    if (m_pollReply) {
        QNetworkReply *reply = m_pollReply;
        m_pollReply = nullptr;
        reply->abort();
    }
}

void NextcloudClient::abortAll()
{
    cancelLogin();
    for (QNetworkReply *reply : m_network->findChildren<QNetworkReply *>())
        reply->abort();
}
