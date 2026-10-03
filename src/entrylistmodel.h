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
    // Named source, not vault: inside the model a binding "vault: vault" would
    // resolve to the model's own property instead of the context property.
    Q_PROPERTY(Vault *source READ source WRITE setSource NOTIFY sourceChanged)
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

    Vault *source() const;
    void setSource(Vault *source);
    QString groupId() const;
    void setGroupId(const QString &groupId);
    QString query() const;
    void setQuery(const QString &query);
    int count() const;

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

signals:
    void sourceChanged();
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
