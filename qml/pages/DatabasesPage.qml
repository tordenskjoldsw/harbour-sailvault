import QtQuick 2.0
import Sailfish.Silica 1.0

// The databases SailVault stores; choosing one makes it the database the
// unlock page opens.
Page {
    id: page

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
        }

        VerticalScrollDecorator { }
    }
}
