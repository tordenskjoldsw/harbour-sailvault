import QtQuick 2.0
import Sailfish.Silica 1.0

// Creates a group in parentId (empty for the root group).
Dialog {
    id: dialog

    property string parentId

    canAccept: nameField.text.trim().length > 0
    allowedOrientations: Orientation.All

    onAccepted: vault.addGroup(parentId, nameField.text.trim())

    Column {
        width: parent.width

        DialogHeader {
            title: qsTr("New group")
            acceptText: qsTr("Save")
        }

        TextField {
            id: nameField

            width: parent.width
            label: qsTr("Name")
            placeholderText: label
            focus: true
            EnterKey.enabled: dialog.canAccept
            EnterKey.iconSource: "image://theme/icon-m-enter-accept"
            EnterKey.onClicked: dialog.accept()
        }
    }
}
