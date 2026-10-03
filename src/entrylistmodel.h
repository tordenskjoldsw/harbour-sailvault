#ifndef ENTRYLISTMODEL_H
#define ENTRYLISTMODEL_H

#include <QAbstractListModel>
#include <QByteArray>
#include <QPointer>
#include <QQmlParserStatus>
#include <QString>
#include <QVector>

#include "vault.h"

// Lists one group (subgroups first) or, with a non-empty query, the search
// results across the whole database. With allGroups it lists every group
// outside the recycle bin instead, as move targets, without excludeId and
// its subgroups. Holds titles and user names only. It loads once its QML
// properties are all set, then on every change.
class EntryListModel : public QAbstractListModel, public QQmlParserStatus
{
    Q_OBJECT
    Q_INTERFACES(QQmlParserStatus)
    // Named source, not vault: inside the model a binding "vault: vault" would
    // resolve to the model's own property instead of the context property.
    Q_PROPERTY(Vault *source READ source WRITE setSource NOTIFY sourceChanged)
    Q_PROPERTY(QString groupId READ groupId WRITE setGroupId NOTIFY groupIdChanged)
    Q_PROPERTY(QString query READ query WRITE setQuery NOTIFY queryChanged)
    Q_PROPERTY(bool allGroups READ allGroups WRITE setAllGroups NOTIFY allGroupsChanged)
    Q_PROPERTY(QString excludeId READ excludeId WRITE setExcludeId NOTIFY excludeIdChanged)

public:
    enum Role {
        IdRole = Qt::UserRole + 1,
        TitleRole,
        UserNameRole,
        // The group an entry is in, or the path of a group's parents.
        LocationRole,
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

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;
    void classBegin() override;
    void componentComplete() override;

signals:
    void sourceChanged();
    void groupIdChanged();
    void queryChanged();
    void allGroupsChanged();
    void excludeIdChanged();

private:
    struct Item {
        QString id;
        bool isGroup;
        QString title;
        QString userName;
        QString location;
    };

    void reload();

    bool m_complete = false;
    QPointer<Vault> m_vault;
    QString m_groupId;
    QString m_query;
    bool m_allGroups = false;
    QString m_excludeId;
    QVector<Item> m_items;
};

#endif // ENTRYLISTMODEL_H
