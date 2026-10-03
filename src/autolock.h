#ifndef AUTOLOCK_H
#define AUTOLOCK_H

#include <QObject>
#include <QTimer>

// Decides when an unlocked database locks by itself: after a time without
// input, or after a time in the background. Both are measured on
// CLOCK_BOOTTIME, because Qt timers stop while the phone sleeps; deadlines
// are also checked when the app becomes active, before every database
// access, and by a watchdog while the app is in the background.
class AutoLock : public QObject
{
    Q_OBJECT

public:
    explicit AutoLock(QObject *parent = nullptr);
    ~AutoLock() override;

    // Starts measuring for a database that was just unlocked.
    void start();
    void stop();
    // Emits expired when a deadline has passed.
    void check();

signals:
    void expired();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    void onApplicationStateChanged(Qt::ApplicationState state);
    void updateWatchdog();

    bool m_running = false;
    long long m_lastActivityMs = 0;
    long long m_backgroundSinceMs = 0;
    QTimer m_idleTimer;
    QTimer m_watchdog;
};

#endif // AUTOLOCK_H
