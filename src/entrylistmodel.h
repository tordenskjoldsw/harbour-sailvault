#ifndef ENTRYLISTMODEL_H
#define ENTRYLISTMODEL_H

#include <QAbstractListModel>
#include <QByteArray>
#include <QPointer>
#include <QString>
#include <QVector>

#include "vault.h"

// Lists one group (subgroups first) or, with a non-empty query, the search
// results across the whole database. With allGroups it lists every group
// outside the recycle bin instead, as move targets, without excludeId and
// its subgroups. Holds titles and user names only.
class EntryListModel : public QAbstractListModel
{
    Q_OBJECT
    // Named source, not vault: inside the model a binding "vault: vault" would
    // resolve to the model's own property instead of the context property.
    Q_PROPERTY(Vault *source READ source WRITE setSource NOTIFY sourceChanged)
    Q_PROPERTY(QString groupId READ groupId WRITE setGroupId NOTIFY groupIdChanged)
    Q_PROPERTY(QString query READ query WRITE setQuery NOTIFY queryChanged)
    Q_PROPERTY(bool allGroups READ allGroups WRITE setAllGroups NOTIFY allGroupsChanged)
    Q_PROPERTY(QString excludeId READ excludeId WRITE setExcludeId NOTIFY excludeIdChanged)
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    enum Role {
        IdRole = Qt::UserRole + 1,
        TitleRole,
        UserNameRole,
        GroupNameRole,
        IsGroupRole
    };

    explicit EntryListModel(QObject *parent = nullptr);

    Vault *source() const;
    void setSource(Vault *source);
    QString groupId() const;
    void setGroupId(const QString &groupId);
    QString query() const;
    void setQuery(const QString &query);
    bool allGroups() const;
    void setAllGroups(bool allGroups);
    QString excludeId() const;
    void setExcludeId(const QString &excludeId);
    int count() const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

signals:
    void sourceChanged();
    void groupIdChanged();
    void queryChanged();
    void allGroupsChanged();
    void excludeIdChanged();
    void countChanged();

private:
    struct Item {
        QString id;
        bool isGroup;
        QString title;
        QString userName;
        QString groupName;
    };

    void reload();

    QPointer<Vault> m_vault;
    QString m_groupId;
    QString m_query;
    bool m_allGroups = false;
    QString m_excludeId;
    QVector<Item> m_items;
};

#endif // ENTRYLISTMODEL_H
