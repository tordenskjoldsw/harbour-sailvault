#include "entrylistmodel.h"

#include "corebridge.h"

namespace {

QString listText(const SvList *list, size_t index, uint32_t column)
{
    SvString text = emptyCoreString();
    return sv_list_text(list, index, column, &text) == SV_OK ? takeCoreString(text) : QString();
}

} // namespace

EntryListModel::EntryListModel(QObject *parent)
    : QAbstractListModel(parent)
{
}

Vault *EntryListModel::source() const
{
    return m_vault;
}

void EntryListModel::setSource(Vault *source)
{
    if (m_vault == source)
        return;
    if (m_vault)
        disconnect(m_vault, nullptr, this, nullptr);
    m_vault = source;
    if (m_vault) {
        connect(m_vault, &Vault::stateChanged, this, &EntryListModel::reload);
        connect(m_vault, &Vault::contentChanged, this, &EntryListModel::reload);
    }
    emit sourceChanged();
    reload();
}

QString EntryListModel::groupId() const
{
    return m_groupId;
}

void EntryListModel::setGroupId(const QString &groupId)
{
    if (m_groupId == groupId)
        return;
    m_groupId = groupId;
    emit groupIdChanged();
    reload();
}

QString EntryListModel::query() const
{
    return m_query;
}

void EntryListModel::setQuery(const QString &query)
{
    if (m_query == query)
        return;
    m_query = query;
    emit queryChanged();
    reload();
}

bool EntryListModel::allGroups() const
{
    return m_allGroups;
}

void EntryListModel::setAllGroups(bool allGroups)
{
    if (m_allGroups == allGroups)
        return;
    m_allGroups = allGroups;
    emit allGroupsChanged();
    reload();
}

QString EntryListModel::excludeId() const
{
    return m_excludeId;
}

void EntryListModel::setExcludeId(const QString &excludeId)
{
    if (m_excludeId == excludeId)
        return;
    m_excludeId = excludeId;
    emit excludeIdChanged();
    reload();
}

int EntryListModel::count() const
{
    return m_items.size();
}

int EntryListModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_items.size();
}

QVariant EntryListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_items.size())
        return QVariant();
    const Item &item = m_items.at(index.row());
    switch (role) {
    case IdRole:
        return item.id;
    case TitleRole:
        return item.title;
    case UserNameRole:
        return item.userName;
    case GroupNameRole:
        return item.groupName;
    case IsGroupRole:
        return item.isGroup;
    default:
        return QVariant();
    }
}

QHash<int, QByteArray> EntryListModel::roleNames() const
{
    return {
        {IdRole, "id"},
        {TitleRole, "title"},
        {UserNameRole, "userName"},
        {GroupNameRole, "groupName"},
        {IsGroupRole, "isGroup"},
    };
}

void EntryListModel::reload()
{
    const int previousCount = m_items.size();
    beginResetModel();
    m_items.clear();

    const SvDatabase *database = m_vault ? m_vault->database() : nullptr;
    SvList *found = nullptr;
    int status = SV_INVALID_ARGUMENT;
    if (database && m_allGroups) {
        status = sv_database_groups(database, uuidOrRoot(itemUuid(m_excludeId)), &found);
    } else if (database && !m_query.trimmed().isEmpty()) {
        const QByteArray query = m_query.toUtf8();
        status = sv_database_search(database, bytePointer(query),
                                    static_cast<size_t>(query.size()), &found);
    } else if (database) {
        status = sv_database_group(database, uuidOrRoot(itemUuid(m_groupId)), &found);
    }
    const CoreList list(found);

    if (status == SV_OK) {
        const size_t length = sv_list_length(list.get());
        m_items.reserve(static_cast<int>(length));
        for (size_t index = 0; index < length; ++index) {
            QByteArray uuid(SV_UUID_LENGTH, Qt::Uninitialized);
            if (sv_list_uuid(list.get(), index, reinterpret_cast<uint8_t *>(uuid.data())) != SV_OK)
                continue;
            m_items.append(Item{QString::fromLatin1(uuid.toHex()),
                                sv_list_is_group(list.get(), index),
                                listText(list.get(), index, SV_COLUMN_TITLE),
                                listText(list.get(), index, SV_COLUMN_USER_NAME),
                                listText(list.get(), index, SV_COLUMN_GROUP)});
        }
    }
    endResetModel();
    if (m_items.size() != previousCount)
        emit countChanged();
}
