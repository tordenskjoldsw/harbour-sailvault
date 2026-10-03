import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

Page {
    id: page

    property string entryId
    property string entryTitle

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
        var all = vault.fields(entryId)
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
            if (page.unlocked) {
                page.entryTitle = vault.fieldValue(page.entryId, "Title")
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
                text: qsTr("Delete")
                enabled: !vault.saving
                onClicked: {
                    remorse.execute(vault.deletesPermanently(page.entryId)
                                    ? qsTr("Deleting permanently")
                                    : qsTr("Moving to the recycle bin"),
                                    function() {
                                        if (vault.deleteEntry(page.entryId))
                                            pageStack.pop()
                                    })
                }
            }
            MenuItem {
                text: qsTr("Edit")
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
                                                         ? "" : vault.fieldValue(page.entryId, modelData.key)

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
                        if (vault.copyField(page.entryId, modelData.key))
                            Notices.show(qsTr("Copied, cleared in 30 seconds"), Notice.Short)
                    }

                    Column {
                        id: fieldColumn

                        x: Theme.horizontalPageMargin
                        y: Theme.paddingMedium
                        width: parent.width - 2 * Theme.horizontalPageMargin

                        Label {
                            width: parent.width
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: fieldItem.highlighted ? Theme.secondaryHighlightColor
                                                         : Theme.secondaryColor
                            text: page.displayName(modelData.key)
                        }

                        Label {
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
                                        ? "" : vault.fieldValue(page.entryId, modelData.key)
                                    fieldItem.revealed = !fieldItem.revealed
                                }
                            }
                            MenuItem {
                                text: qsTr("Copy")
                                onClicked: {
                                    if (vault.copyField(page.entryId, modelData.key))
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
