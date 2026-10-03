import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

Page {
    id: page

    property string groupId
    property string groupName

    allowedOrientations: Orientation.All

    SilicaListView {
        id: listView

        anchors.fill: parent
        currentIndex: -1

        model: EntryListModel {
            id: entries
            source: vault
            groupId: page.groupId
            query: listView.headerItem ? listView.headerItem.query : ""
        }

        header: Column {
            property alias query: searchField.text

            width: parent.width

            PageHeader {
                title: page.groupName
                description: vault.saving ? qsTr("Saving") : vault.dirty ? qsTr("Not saved") : ""
            }

            SearchField {
                id: searchField

                width: parent.width
                placeholderText: qsTr("Search")
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }
        }

        PullDownMenu {
            busy: vault.saving

            MenuItem {
                text: qsTr("Lock")
                onClicked: vault.lock()
            }
            MenuItem {
                text: qsTr("Save")
                visible: vault.dirty && !vault.saving
                onClicked: vault.save()
            }
            MenuItem {
                text: qsTr("New entry")
                enabled: !vault.saving
                onClicked: pageStack.push(Qt.resolvedUrl("EntryDialog.qml"),
                                          { "groupId": page.groupId })
            }
        }

        delegate: ListItem {
            id: item

            contentHeight: Theme.itemSizeMedium
            menu: model.isGroup ? groupMenu : entryMenu

            onClicked: {
                if (model.isGroup) {
                    pageStack.push(Qt.resolvedUrl("EntryListPage.qml"),
                                   { "groupId": model.id, "groupName": model.title })
                } else {
                    pageStack.push(Qt.resolvedUrl("EntryPage.qml"),
                                   { "entryId": model.id, "entryTitle": model.title })
                }
            }

            Image {
                id: icon

                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                source: (model.isGroup ? "image://theme/icon-m-folder" : "image://theme/icon-m-keys")
                        + (item.highlighted ? "?" + Theme.highlightColor : "")
            }

            Column {
                anchors {
                    left: icon.right
                    leftMargin: Theme.paddingMedium
                    right: parent.right
                    rightMargin: Theme.horizontalPageMargin
                    verticalCenter: parent.verticalCenter
                }

                Label {
                    width: parent.width
                    truncationMode: TruncationMode.Fade
                    color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                    text: model.title.length > 0 ? model.title : qsTr("(no title)")
                }

                Label {
                    width: parent.width
                    visible: text.length > 0
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: item.highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
                    text: entries.query.length > 0 && model.groupName.length > 0
                          ? model.userName + (model.userName.length > 0 ? " · " : "") + model.groupName
                          : model.userName
                }
            }

            Component {
                id: groupMenu

                ContextMenu {
                    MenuItem {
                        text: qsTr("Delete")
                        enabled: !vault.saving
                        onClicked: {
                            var groupId = model.id
                            item.remorseAction(vault.deletesPermanently(groupId)
                                               ? qsTr("Deleting group permanently")
                                               : qsTr("Moving group to the recycle bin"),
                                               function() { vault.deleteItem(groupId) })
                        }
                    }
                }
            }

            Component {
                id: entryMenu

                ContextMenu {
                    MenuItem {
                        text: qsTr("Edit")
                        enabled: !vault.saving
                        onClicked: pageStack.push(Qt.resolvedUrl("EntryDialog.qml"),
                                                  { "entryId": model.id })
                    }
                    MenuItem {
                        text: qsTr("Delete")
                        enabled: !vault.saving
                        onClicked: {
                            var entryId = model.id
                            item.remorseAction(vault.deletesPermanently(entryId)
                                               ? qsTr("Deleting permanently")
                                               : qsTr("Moving to the recycle bin"),
                                               function() { vault.deleteItem(entryId) })
                        }
                    }
                    MenuItem {
                        text: qsTr("Copy user name")
                        onClicked: {
                            if (vault.copyField(model.id, "UserName"))
                                Notices.show(qsTr("User name copied"), Notice.Short)
                        }
                    }
                    MenuItem {
                        text: qsTr("Copy password")
                        onClicked: {
                            if (vault.copyField(model.id, "Password"))
                                Notices.show(qsTr("Password copied, cleared in 30 seconds"),
                                             Notice.Short)
                        }
                    }
                }
            }
        }

        ViewPlaceholder {
            enabled: listView.count === 0
            text: entries.query.length > 0 ? qsTr("No matching entries") : qsTr("This group is empty")
        }

        VerticalScrollDecorator {}
    }
}
