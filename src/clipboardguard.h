#ifndef CLIPBOARDGUARD_H
#define CLIPBOARDGUARD_H

#include <QObject>
#include <QString>

#include <functional>

// Puts a value on the clipboard and removes it again after a deadline, on
// lock and on exit, but only while the clipboard still holds that value.
// It keeps no copy or hash of the value: to compare, it asks the source
// for the value again.
class ClipboardGuard : public QObject
{
    Q_OBJECT

public:
    using ValueSource = std::function<QString()>;

    explicit ClipboardGuard(QObject *parent = nullptr);

    void copy(const QString &text, ValueSource source);
    void clear();
    bool isPending() const;
    // Clears the clipboard once the deadline has passed, counting sleep time.
    void enforceDeadline();

private:
    ValueSource m_source;
    long long m_deadlineMs = 0;
};

#endif // CLIPBOARDGUARD_H
