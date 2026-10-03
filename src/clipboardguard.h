#ifndef CLIPBOARDGUARD_H
#define CLIPBOARDGUARD_H

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTimer>

// Puts a value on the clipboard and removes it again after a timeout, on
// lock and on exit, but only while the clipboard still holds that value.
// It keeps a hash of the value, never the value itself.
class ClipboardGuard : public QObject
{
    Q_OBJECT

public:
    explicit ClipboardGuard(QObject *parent = nullptr);

    void copy(const QString &text);
    void clear();

private:
    static QByteArray digest(const QString &text);

    QTimer m_timer;
    QByteArray m_digest;
};

#endif // CLIPBOARDGUARD_H
