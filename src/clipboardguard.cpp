#include "clipboardguard.h"

#include <QClipboard>
#include <QCryptographicHash>
#include <QGuiApplication>

namespace {

const int ClearAfterMs = 30 * 1000;

} // namespace

ClipboardGuard::ClipboardGuard(QObject *parent)
    : QObject(parent)
{
    m_timer.setSingleShot(true);
    m_timer.setInterval(ClearAfterMs);
    connect(&m_timer, &QTimer::timeout, this, &ClipboardGuard::clear);
    connect(qApp, &QCoreApplication::aboutToQuit, this, &ClipboardGuard::clear);
}

void ClipboardGuard::copy(const QString &text)
{
    QGuiApplication::clipboard()->setText(text);
    m_digest = digest(text);
    m_timer.start();
}

void ClipboardGuard::clear()
{
    m_timer.stop();
    if (m_digest.isEmpty())
        return;
    QClipboard *clipboard = QGuiApplication::clipboard();
    if (digest(clipboard->text()) == m_digest)
        clipboard->clear();
    m_digest.clear();
}

QByteArray ClipboardGuard::digest(const QString &text)
{
    return QCryptographicHash::hash(text.toUtf8(), QCryptographicHash::Sha256);
}
