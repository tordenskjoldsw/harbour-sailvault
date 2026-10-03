import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

Page {
    id: page

    property string entryId
    property string entryTitle
    // -1 shows the entry; 0 and up show a history item, read-only.
    property int version: -1
    property string versionTime
    readonly property bool isHistory: version >= 0
    property bool inRecycleBin: vault.inRecycleBin(entryId)
    property int historyLength: isHistory ? 0 : vault.history(entryId).length

    readonly property var standardKeys: ["UserName", "Password", "URL", "Notes"]
    // Every value on this page depends on this, so a lock empties the page
    // even if the page stack cannot pop it right away.
    readonly property bool unlocked: vault.state === Vault.Unlocked

    function displayName(key) {
        switch (key) {
        case "UserName": return qsTr("User name")
        case "Password": return qsTr("Password")
        case "URL": return qsTr("Website")
        case "Notes": return qsTr("Notes")
        default: return key
        }
    }

    // Standard fields first in a fixed order, then custom fields; the title
    // is already in the page header.
    function orderedFields() {
        var all = vault.fields(entryId, version)
        var ordered = []
        standardKeys.forEach(function(key) {
            all.forEach(function(field) { if (field.key === key) ordered.push(field) })
        })
        all.forEach(function(field) {
            if (field.key !== "Title" && standardKeys.indexOf(field.key) < 0)
                ordered.push(field)
        })
        return ordered
    }

    allowedOrientations: Orientation.All

    Connections {
        target: vault
        onContentChanged: {
            if (page.unlocked && !page.isHistory) {
                page.entryTitle = vault.fieldValue(page.entryId, "Title")
                page.inRecycleBin = vault.inRecycleBin(page.entryId)
                page.historyLength = vault.history(page.entryId).length
                fieldsRepeater.model = page.orderedFields()
            }
        }
    }

    RemorsePopup {
        id: remorse
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        PullDownMenu {
            busy: vault.saving

            MenuItem {
                text: qsTr("Lock")
                onClicked: vault.lock()
            }
            MenuItem {
                text: qsTr("History")
                visible: page.historyLength > 0
                onClicked: pageStack.push(Qt.resolvedUrl("HistoryPage.qml"),
                                          { "entryId": page.entryId })
            }
            MenuItem {
                text: qsTr("Delete")
                visible: !page.isHistory
                enabled: !vault.saving
                onClicked: {
                    remorse.execute(vault.deletesPermanently(page.entryId)
                                    ? qsTr("Deleting permanently")
                                    : qsTr("Moving to the recycle bin"),
                                    function() {
                                        if (vault.deleteItem(page.entryId))
                                            pageStack.pop()
                                    })
                }
            }
            MenuItem {
                text: qsTr("Restore")
                visible: !page.isHistory && page.inRecycleBin
                enabled: !vault.saving
                onClicked: {
                    if (vault.restore(page.entryId))
                        Notices.show(qsTr("Restored"), Notice.Short)
                }
            }
            MenuItem {
                text: qsTr("Move")
                visible: !page.isHistory && !page.inRecycleBin
                enabled: !vault.saving
                onClicked: pageStack.push(Qt.resolvedUrl("MovePage.qml"),
                                          { "itemId": page.entryId, "isGroup": false })
            }
            MenuItem {
                text: qsTr("Edit")
                visible: !page.isHistory && !page.inRecycleBin
                enabled: !vault.saving
                onClicked: pageStack.push(Qt.resolvedUrl("EntryDialog.qml"),
                                          { "entryId": page.entryId })
            }
        }

        Column {
            id: column

            width: parent.width

            PageHeader {
                title: page.entryTitle
                description: page.isHistory ? qsTr("Version of %1").arg(page.versionTime) : ""
            }

            Repeater {
                id: fieldsRepeater

                model: page.orderedFields()

                delegate: ListItem {
                    id: fieldItem

                    property bool revealed: false
                    property string revealedValue
                    readonly property bool isProtected: modelData.protected
                    readonly property string plainValue: !page.unlocked || isProtected
                                                         ? ""
                                                         : vault.fieldValue(page.entryId, modelData.key,
                                                                            page.version)

                    Connections {
                        target: page
                        onUnlockedChanged: {
                            if (!page.unlocked) {
                                fieldItem.revealed = false
                                fieldItem.revealedValue = ""
                            }
                        }
                    }

                    contentHeight: fieldColumn.height + 2 * Theme.paddingMedium
                    visible: isProtected || plainValue.length > 0
                    menu: fieldMenu

                    onClicked: {
                        if (vault.copyField(page.entryId, modelData.key, page.version))
                            Notices.show(qsTr("Copied, cleared in 30 seconds"), Notice.Short)
                    }

                    Column {
                        id: fieldColumn

                        x: Theme.horizontalPageMargin
                        y: Theme.paddingMedium
                        width: parent.width - 2 * Theme.horizontalPageMargin

                        Label {

                            textFormat: Text.PlainText
                            width: parent.width
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: fieldItem.highlighted ? Theme.secondaryHighlightColor
                                                         : Theme.secondaryColor
                            text: page.displayName(modelData.key)
                        }

                        Label {

                            textFormat: Text.PlainText
                            width: parent.width
                            wrapMode: Text.Wrap
                            color: fieldItem.highlighted ? Theme.highlightColor : Theme.primaryColor
                            font.family: fieldItem.isProtected && fieldItem.revealed
                                         ? "monospace" : Theme.fontFamily
                            text: !fieldItem.isProtected ? fieldItem.plainValue
                                  : fieldItem.revealed ? fieldItem.revealedValue
                                  : "••••••••"
                        }
                    }

                    Component {
                        id: fieldMenu

                        ContextMenu {
                            MenuItem {
                                visible: fieldItem.isProtected
                                text: fieldItem.revealed ? qsTr("Hide") : qsTr("Show")
                                onClicked: {
                                    fieldItem.revealedValue = fieldItem.revealed
                                        ? "" : vault.fieldValue(page.entryId, modelData.key,
                                                                                page.version)
                                    fieldItem.revealed = !fieldItem.revealed
                                }
                            }
                            MenuItem {
                                text: qsTr("Copy")
                                onClicked: {
                                    if (vault.copyField(page.entryId, modelData.key,
                                                        page.version))
                                        Notices.show(qsTr("Copied, cleared in 30 seconds"),
                                                     Notice.Short)
                                }
                            }
                        }
                    }
                }
            }
        }

        VerticalScrollDecorator {}
    }
}
