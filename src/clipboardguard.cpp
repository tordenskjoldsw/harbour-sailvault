#include "clipboardguard.h"

#include <QClipboard>
#include <QGuiApplication>

#include "boottime.h"

namespace {

const long long ClearAfterMs = 30 * 1000;
// Qt timers stop while the phone sleeps; checking the deadline on
// CLOCK_BOOTTIME this often bounds how late it is enforced after waking up.
const int WatchdogIntervalMs = 5 * 1000;

} // namespace

ClipboardGuard::ClipboardGuard(QObject *parent)
    : QObject(parent)
{
    m_watchdog.setInterval(WatchdogIntervalMs);
    connect(&m_watchdog, &QTimer::timeout, this, &ClipboardGuard::enforceDeadline);
    connect(qApp, &QGuiApplication::applicationStateChanged, this,
            [this](Qt::ApplicationState state) {
                if (state == Qt::ApplicationActive)
                    enforceDeadline();
            });
}

void ClipboardGuard::copy(const QString &text, ValueSource source)
{
    QGuiApplication::clipboard()->setText(text);
    m_source = std::move(source);
    m_deadlineMs = bootTimeMs() + ClearAfterMs;
    m_watchdog.start();
}

void ClipboardGuard::clear()
{
    if (!m_source)
        return;
    QClipboard *clipboard = QGuiApplication::clipboard();
    const QString current = clipboard->text();
    if (!current.isEmpty() && current == m_source()) {
        clipboard->clear();
        // aboutToQuit runs after the event loop has stopped; flush so the
        // compositor receives the cleared selection before the app exits.
        QGuiApplication::sync();
    }
    m_source = nullptr;
    m_deadlineMs = 0;
    m_watchdog.stop();
}

void ClipboardGuard::keepCopiedValue()
{
    if (!m_source)
        return;
    const QString current = QGuiApplication::clipboard()->text();
    if (current.isEmpty() || current != m_source()) {
        m_source = nullptr;
        m_deadlineMs = 0;
        m_watchdog.stop();
        return;
    }
    m_source = [current] { return current; };
}

void ClipboardGuard::enforceDeadline()
{
    if (m_source && bootTimeMs() >= m_deadlineMs)
        clear();
}
