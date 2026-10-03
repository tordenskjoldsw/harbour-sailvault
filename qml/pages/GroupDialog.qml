import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

// Creates a group in parentId (empty for the root group), or renames the
// group groupId when it is set.
Dialog {
    id: dialog

    property string parentId
    property string groupId
    property string currentName
    readonly property bool renaming: groupId.length > 0

    canAccept: nameField.text.trim().length > 0 && vault.state === Vault.Unlocked
               && !vault.saving
    allowedOrientations: Orientation.All

    onAccepted: {
        var name = nameField.text.trim()
        if (!(renaming ? vault.renameGroup(groupId, name) : vault.addGroup(parentId, name)))
            Notices.show(qsTr("The group could not be saved"), Notice.Long)
    }

    Column {
        width: parent.width

        DialogHeader {
            title: dialog.renaming ? qsTr("Rename group") : qsTr("New group")
            acceptText: qsTr("Save")
        }

        TextField {
            id: nameField

            width: parent.width
            label: qsTr("Name")
            placeholderText: label
            text: dialog.currentName
            focus: true
            EnterKey.enabled: dialog.canAccept
            EnterKey.iconSource: "image://theme/icon-m-enter-accept"
            EnterKey.onClicked: dialog.accept()
        }
    }
}
