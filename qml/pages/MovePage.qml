import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "../components"

// Moves the entry or group itemId into a group picked from every group
// outside the recycle bin; a group is never offered as its own target.
Page {
    id: page

    property string itemId
    property bool isGroup

    // The move reloads the list, which destroys the tapped delegate, so the
    // page finishes the action instead of the delegate's handler.
    function moveTo(groupId, groupName) {
        var result = isGroup ? vault.moveGroup(itemId, groupId) : vault.moveEntry(itemId, groupId)
        if (result === Vault.MoveRefused) {
            Notices.show(qsTr("Cannot move to %1").arg(groupName), Notice.Short)
            return
        }
        Notices.show(result === Vault.Moved ? qsTr("Moved to %1").arg(groupName)
                                            : qsTr("Already in %1").arg(groupName), Notice.Short)
        pageStack.pop()
    }

    allowedOrientations: Orientation.All

    SilicaListView {
        id: listView

        anchors.fill: parent

        model: EntryListModel {
            source: vault
            allGroups: true
            excludeId: page.isGroup ? page.itemId : ""
        }

        header: PageHeader {
            title: qsTr("Move to")
        }

        delegate: BackgroundItem {
            id: item

            height: Theme.itemSizeMedium
            enabled: !vault.saving

            onClicked: page.moveTo(model.id, model.title)

            TwoLineLabel {
                anchors.fill: parent
                highlighted: item.highlighted
                iconSource: "image://theme/icon-m-folder"
                title: model.title.length > 0 ? model.title : qsTr("(no name)")
                description: model.location
            }
        }

        VerticalScrollDecorator {}
    }
}
