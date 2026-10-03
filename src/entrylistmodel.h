#ifndef ENTRYLISTMODEL_H
#define ENTRYLISTMODEL_H

#include <QAbstractListModel>
#include <QByteArray>
#include <QPointer>
#include <QString>
#include <QVector>

#include "vault.h"

// Lists one group (subgroups first) or, with a non-empty query, the search
// results across the whole database. Holds titles and user names only.
class EntryListModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(Vault *vault READ vault WRITE setVault NOTIFY vaultChanged)
    Q_PROPERTY(QString groupId READ groupId WRITE setGroupId NOTIFY groupIdChanged)
    Q_PROPERTY(QString query READ query WRITE setQuery NOTIFY queryChanged)
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

    Vault *vault() const;
    void setVault(Vault *vault);
    QString groupId() const;
    void setGroupId(const QString &groupId);
    QString query() const;
    void setQuery(const QString &query);
    int count() const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

signals:
    void vaultChanged();
    void groupIdChanged();
    void queryChanged();
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
    QVector<Item> m_items;
};

#endif // ENTRYLISTMODEL_H
