#ifndef SECURE_H
#define SECURE_H

#include <QByteArray>
#include <QString>

#include <string.h>

#include "sailvault_core.h"

// Overwrites the buffer before releasing it. A copy that still shares the
// data with another QByteArray is detached first, so only this copy is
// wiped; callers keep secrets in a single, unshared buffer.
inline void secureWipe(QByteArray &bytes)
{
    if (!bytes.isEmpty()) {
        bytes.detach();
        explicit_bzero(bytes.data(), static_cast<size_t>(bytes.size()));
    }
    bytes.clear();
}

// Converts a core string and releases it; the core zeroizes its copy.
inline QString takeCoreString(SvString string)
{
    const QString text = QString::fromUtf8(reinterpret_cast<const char *>(string.data),
                                           static_cast<int>(string.length));
    sv_string_free(string);
    return text;
}

inline SvString emptyCoreString()
{
    SvString string;
    string.data = nullptr;
    string.length = 0;
    return string;
}

#endif // SECURE_H
