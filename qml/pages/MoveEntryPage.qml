import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

Page {
    id: page

    property string entryId

    allowedOrientations: Orientation.All

    SilicaListView {
        id: listView

        anchors.fill: parent

        model: EntryListModel {
            source: vault
            allGroups: true
        }

        header: PageHeader {
            title: qsTr("Move to")
        }

        delegate: BackgroundItem {
            id: item

            height: Theme.itemSizeMedium
            enabled: !vault.saving

            onClicked: {
                if (vault.moveEntry(page.entryId, model.id)) {
                    Notices.show(qsTr("Moved to %1").arg(model.title), Notice.Short)
                    pageStack.pop()
                }
            }

            Image {
                id: icon

                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                source: "image://theme/icon-m-folder"
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
                    text: model.title.length > 0 ? model.title : qsTr("(no name)")
                }

                Label {
                    width: parent.width
                    visible: text.length > 0
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: item.highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
                    text: model.groupName
                }
            }
        }

        VerticalScrollDecorator {}
    }
}
