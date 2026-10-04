import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import harbour.sailvault 1.0
import "../components"

Page {
    id: page

    property string groupId
    property string groupName
    // Nothing new is added in the recycle bin, as in KeePassXC.
    property bool inRecycleBin: vault.inRecycleBin(groupId)
    property string recycleBinId: vault.recycleBinId()
    // The file pickers close themselves after a selection; the import or
    // merge page opens once this page is back.
    property string pendingImportPath
    property string pendingMergePath

    onStatusChanged: {
        if (status !== PageStatus.Active)
            return
        if (pendingImportPath.length > 0) {
            var path = pendingImportPath
            pendingImportPath = ""
            pageStack.push(Qt.resolvedUrl("ImportPage.qml"), { "path": path })
        } else if (pendingMergePath.length > 0) {
            var mergePath = pendingMergePath
            pendingMergePath = ""
            pageStack.push(Qt.resolvedUrl("MergePage.qml"), { "path": mergePath })
        }
    }

    allowedOrientations: Orientation.All

    // A page-level remorse: the list reloads after the deletion, which
    // would destroy a remorse shown inside the deleted item's delegate.
    function deleteItem(itemId, isGroup) {
        var permanent = vault.deletesPermanently(itemId)
        var text = isGroup
                ? (permanent ? qsTr("Deleting group permanently")
                             : qsTr("Moving group to the recycle bin"))
                : (permanent ? qsTr("Deleting permanently")
                             : qsTr("Moving to the recycle bin"))
        remorse.execute(text, function() { vault.deleteItem(itemId) })
    }

    function restoreItem(itemId) {
        if (vault.restore(itemId))
            Notices.show(qsTr("Restored"), Notice.Short)
    }

    RemorsePopup {
        id: remorse
    }

    Component {
        id: exportPicker

        FilePickerPage {
            nameFilters: ["*.json"]
            onSelectedContentPropertiesChanged: page.pendingImportPath = selectedContentProperties.filePath
        }
    }

    Component {
        id: mergePicker

        FilePickerPage {
            nameFilters: ["*.kdbx"]
            onSelectedContentPropertiesChanged: page.pendingMergePath = selectedContentProperties.filePath
        }
    }

    Connections {
        target: vault
        onContentChanged: {
            page.inRecycleBin = vault.inRecycleBin(page.groupId)
            page.recycleBinId = vault.recycleBinId()
        }
    }

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
                text: qsTr("About")
                visible: page.groupId.length === 0
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))
            }

            MenuItem {
                text: qsTr("Lock")
                onClicked: vault.lock()
            }
            MenuItem {
                text: qsTr("Merge with file")
                visible: page.groupId.length === 0
                enabled: !vault.saving && !vault.merging
                onClicked: pageStack.push(mergePicker)
            }
            MenuItem {
                text: qsTr("Import from Bitwarden")
                visible: page.groupId.length === 0
                enabled: !vault.saving && !importer.busy
                onClicked: pageStack.push(exportPicker)
            }
            MenuItem {
                text: qsTr("Save")
                visible: vault.dirty && !vault.saving
                onClicked: vault.save()
            }
            MenuItem {
                text: qsTr("Empty recycle bin")
                visible: page.groupId.length > 0 && page.groupId === page.recycleBinId
                enabled: !vault.saving && listView.count > 0
                onClicked: remorse.execute(qsTr("Emptying the recycle bin"),
                                           function() { vault.emptyRecycleBin() })
            }
            MenuItem {
                text: qsTr("New group")
                visible: !page.inRecycleBin
                enabled: !vault.saving
                onClicked: pageStack.push(Qt.resolvedUrl("GroupDialog.qml"),
                                          { "parentId": page.groupId })
            }
            MenuItem {
                text: qsTr("New entry")
                visible: !page.inRecycleBin
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

            TwoLineLabel {
                anchors.fill: parent
                highlighted: item.highlighted
                iconSource: model.isGroup ? "image://theme/icon-m-folder" : "image://theme/icon-m-keys"
                title: model.title.length > 0 ? model.title : qsTr("(no title)")
                description: entries.query.length > 0 && model.location.length > 0
                             ? model.userName + (model.userName.length > 0 ? " · " : "")
                               + model.location
                             : model.userName
            }

            Component {
                id: groupMenu

                ContextMenu {
                    id: groupContextMenu

                    readonly property bool isRecycleBin: model.id === page.recycleBinId

                    MenuItem {
                        text: qsTr("Restore")
                        visible: page.inRecycleBin
                        enabled: !vault.saving
                        onClicked: page.restoreItem(model.id)
                    }
                    MenuItem {
                        text: qsTr("Rename")
                        visible: !page.inRecycleBin && !groupContextMenu.isRecycleBin
                        enabled: !vault.saving
                        onClicked: pageStack.push(Qt.resolvedUrl("GroupDialog.qml"),
                                                  { "groupId": model.id,
                                                    "currentName": model.title })
                    }
                    MenuItem {
                        text: qsTr("Move")
                        visible: !page.inRecycleBin && !groupContextMenu.isRecycleBin
                        enabled: !vault.saving
                        onClicked: pageStack.push(Qt.resolvedUrl("MovePage.qml"),
                                                  { "itemId": model.id, "isGroup": true })
                    }
                    MenuItem {
                        text: qsTr("Delete")
                        enabled: !vault.saving
                        onClicked: page.deleteItem(model.id, true)
                    }
                }
            }

            Component {
                id: entryMenu

                ContextMenu {
                    MenuItem {
                        text: qsTr("Restore")
                        visible: page.inRecycleBin
                        enabled: !vault.saving
                        onClicked: page.restoreItem(model.id)
                    }
                    MenuItem {
                        text: qsTr("Edit")
                        visible: !page.inRecycleBin
                        enabled: !vault.saving
                        onClicked: pageStack.push(Qt.resolvedUrl("EntryDialog.qml"),
                                                  { "entryId": model.id })
                    }
                    MenuItem {
                        text: qsTr("Move")
                        visible: !page.inRecycleBin
                        enabled: !vault.saving
                        onClicked: pageStack.push(Qt.resolvedUrl("MovePage.qml"),
                                                  { "itemId": model.id, "isGroup": false })
                    }
                    MenuItem {
                        text: qsTr("Delete")
                        enabled: !vault.saving
                        onClicked: page.deleteItem(model.id, false)
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
                            if (vault.copyField(model.id, "Password")) {
                                Notices.show(qsTr("Password copied, cleared in %1 seconds")
                                             .arg(vault.clipboardClearSeconds), Notice.Short)
                            }
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
