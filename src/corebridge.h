#ifndef COREBRIDGE_H
#define COREBRIDGE_H

#include <QByteArray>
#include <QDateTime>
#include <QString>

#include <memory>
#include <string.h>

#include "sailvault_core.h"

// Helpers for calling the Rust core: buffers, UUIDs, strings and handles.

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

inline const uint8_t *bytePointer(const QByteArray &bytes)
{
    return reinterpret_cast<const uint8_t *>(bytes.constData());
}

// The 16 bytes of the entry or group with the hex id QML uses, or empty for
// anything else.
inline QByteArray itemUuid(const QString &itemId)
{
    const QByteArray uuid = QByteArray::fromHex(itemId.toLatin1());
    return uuid.size() == SV_UUID_LENGTH ? uuid : QByteArray();
}

// For the core functions that take null as the root group.
inline const uint8_t *uuidOrRoot(const QByteArray &uuid)
{
    return uuid.isEmpty() ? nullptr : bytePointer(uuid);
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
    return SvString{nullptr, 0};
}

// The core takes times in seconds since the Unix epoch.
inline qint64 unixSeconds()
{
    return QDateTime::currentMSecsSinceEpoch() / 1000;
}

// Owners of core handles, which free them with the core's own function.
template <typename Handle, void (*Free)(Handle *)>
struct CoreFree {
    void operator()(Handle *handle) const { Free(handle); }
};
using CoreList = std::unique_ptr<SvList, CoreFree<SvList, sv_list_free>>;
using CoreFieldList = std::unique_ptr<SvFieldList, CoreFree<SvFieldList, sv_field_list_free>>;
using CoreImport = std::unique_ptr<SvImport, CoreFree<SvImport, sv_import_free>>;
using CoreDatabase = std::unique_ptr<SvDatabase, CoreFree<SvDatabase, sv_database_free>>;

// A file from the core, released when it goes out of scope.
class CoreBytes
{
public:
    CoreBytes() = default;
    CoreBytes(const CoreBytes &) = delete;
    CoreBytes &operator=(const CoreBytes &) = delete;
    ~CoreBytes() { sv_bytes_free(m_bytes); }

    SvBytes *out() { return &m_bytes; }
    // Valid while this object lives.
    QByteArray view() const
    {
        return QByteArray::fromRawData(reinterpret_cast<const char *>(m_bytes.data),
                                       static_cast<int>(m_bytes.length));
    }

private:
    SvBytes m_bytes{nullptr, 0};
};

#endif // COREBRIDGE_H
