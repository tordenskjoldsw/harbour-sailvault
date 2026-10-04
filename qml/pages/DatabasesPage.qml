import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

// The databases SailVault stores; choosing one makes it the database the
// unlock page opens.
Page {
    id: page

    function saveCopy(name) {
        var dialog = pageStack.push(Qt.resolvedUrl("SaveCopyDialog.qml"), { "name": name })
        dialog.accepted.connect(function() {
            switch (databases.saveCopy(name, dialog.location, dialog.fileName, dialog.withKeyFile)) {
            case Databases.CopySaved:
                Notices.show(dialog.location === Databases.Downloads ? qsTr("Copy saved in Downloads")
                                                                     : qsTr("Copy saved in Documents"),
                             Notice.Short)
                break
            case Databases.CopyExists:
                Notices.show(qsTr("A file with this name already exists"), Notice.Short)
                break
            default:
                Notices.show(qsTr("The copy could not be saved"), Notice.Short)
            }
        })
    }

    allowedOrientations: Orientation.All

    SilicaListView {
        id: listView

        anchors.fill: parent
        model: databases.names()

        header: PageHeader {
            title: qsTr("Databases")
        }

        delegate: ListItem {
            id: item

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                text: modelData
                textFormat: Text.PlainText
                truncationMode: TruncationMode.Fade
                color: item.highlighted || modelData === vault.databaseName ? Theme.highlightColor
                                                                            : Theme.primaryColor
            }

            onClicked: {
                vault.databaseName = modelData
                pageStack.pop()
            }

            menu: ContextMenu {
                MenuItem {
                    text: qsTr("Save copy")
                    onClicked: page.saveCopy(modelData)
                }
            }
        }

        VerticalScrollDecorator { }
    }
}
