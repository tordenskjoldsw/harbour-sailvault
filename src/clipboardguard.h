#ifndef CLIPBOARDGUARD_H
#define CLIPBOARDGUARD_H

#include <QObject>
#include <QString>
#include <QTimer>

#include <functional>

// Puts a value on the clipboard and removes it again after a deadline, on
// lock and on exit, but only while the clipboard still holds that value.
// The deadline is measured on CLOCK_BOOTTIME and checked by a watchdog and
// when the app becomes active, because Qt timers stop while the phone
// sleeps.
// To compare, it asks the source for the value again, so it keeps no copy
// or hash of it while the source stays unchanged.
class ClipboardGuard : public QObject
{
    Q_OBJECT

public:
    using ValueSource = std::function<QString()>;

    explicit ClipboardGuard(QObject *parent = nullptr);

    void copy(const QString &text, ValueSource source);
    void clear();
    // Called before the source changes, which would hide that the clipboard
    // still holds the copied value: keeps a copy of it until the clipboard
    // is cleared. The clipboard holds the same value meanwhile.
    void keepCopiedValue();
    // Clears the clipboard once the deadline has passed, counting sleep time.
    void enforceDeadline();

private:
    ValueSource m_source;
    long long m_deadlineMs = 0;
    QTimer m_watchdog;
};

#endif // CLIPBOARDGUARD_H
