#include "clipboardguard.h"

#include <QClipboard>
#include <QGuiApplication>

#include "boottime.h"

namespace {

const long long ClearAfterMs = 30 * 1000;

} // namespace

ClipboardGuard::ClipboardGuard(QObject *parent)
    : QObject(parent)
{
}

void ClipboardGuard::copy(const QString &text, ValueSource source)
{
    QGuiApplication::clipboard()->setText(text);
    m_source = std::move(source);
    m_deadlineMs = bootTimeMs() + ClearAfterMs;
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
}

bool ClipboardGuard::isPending() const
{
    return static_cast<bool>(m_source);
}

void ClipboardGuard::enforceDeadline()
{
    if (m_source && bootTimeMs() >= m_deadlineMs)
        clear();
}
