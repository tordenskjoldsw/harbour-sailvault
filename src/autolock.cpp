#include "autolock.h"

#include <QEvent>
#include <QGuiApplication>

#include "boottime.h"

namespace {

const long long IdleLockMs = 5 * 60 * 1000;
const long long BackgroundLockMs = 60 * 1000;
// Bounds how late a deadline is enforced after the phone wakes up.
const int WatchdogIntervalMs = 5 * 1000;

} // namespace

AutoLock::AutoLock(QObject *parent)
    : QObject(parent)
{
    m_idleTimer.setSingleShot(true);
    m_idleTimer.setInterval(static_cast<int>(IdleLockMs));
    m_watchdog.setInterval(WatchdogIntervalMs);
    connect(&m_idleTimer, &QTimer::timeout, this, &AutoLock::check);
    connect(&m_watchdog, &QTimer::timeout, this, &AutoLock::check);
    connect(qApp, &QGuiApplication::applicationStateChanged, this,
            &AutoLock::onApplicationStateChanged);
    // Installed on the application, so input that goes to the input method
    // or any item counts as activity.
    qApp->installEventFilter(this);
}

AutoLock::~AutoLock()
{
    qApp->removeEventFilter(this);
}

void AutoLock::start()
{
    m_running = true;
    m_lastActivityMs = bootTimeMs();
    m_idleTimer.start();
    // The app may have left the foreground while the KDF ran.
    onApplicationStateChanged(QGuiApplication::applicationState());
}

void AutoLock::stop()
{
    m_running = false;
    m_idleTimer.stop();
    m_backgroundSinceMs = 0;
    updateWatchdog();
}

void AutoLock::check()
{
    if (!m_running)
        return;
    const long long now = bootTimeMs();
    const bool idle = now - m_lastActivityMs >= IdleLockMs;
    const bool background = m_backgroundSinceMs != 0
        && now - m_backgroundSinceMs >= BackgroundLockMs;
    if (idle || background)
        emit expired();
}

bool AutoLock::eventFilter(QObject *watched, QEvent *event)
{
    switch (event->type()) {
    case QEvent::TouchBegin:
    case QEvent::MouseButtonPress:
    case QEvent::KeyPress:
    case QEvent::InputMethod:
        if (m_running) {
            m_lastActivityMs = bootTimeMs();
            m_idleTimer.start();
        }
        break;
    default:
        break;
    }
    return QObject::eventFilter(watched, event);
}

void AutoLock::onApplicationStateChanged(Qt::ApplicationState state)
{
    if (state == Qt::ApplicationActive) {
        // Check before clearing the background stamp, so time spent asleep
        // in the background still counts.
        check();
        m_backgroundSinceMs = 0;
    } else if (m_running && m_backgroundSinceMs == 0) {
        m_backgroundSinceMs = bootTimeMs();
    }
    updateWatchdog();
}

void AutoLock::updateWatchdog()
{
    const bool needed = m_running && m_backgroundSinceMs != 0;
    if (needed && !m_watchdog.isActive())
        m_watchdog.start();
    else if (!needed)
        m_watchdog.stop();
}
