import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

// Asks for the name and the master password of a new database. The caller
// creates it from these properties when accepted.
Dialog {
    id: dialog

    // NIST SP 800-63B rev. 4 asks for 15 characters when a password is the
    // only factor, as the master password is here.
    readonly property int minimumPasswordLength: 15
    readonly property string name: nameField.text.trim()
    readonly property bool validName: databases.isValidName(name)
    readonly property bool exists: databases.exists(name)
    property alias password: passwordField.text
    readonly property int kdfLevel: kdfBox.kdfLevel

    canAccept: validName && !exists
               && passwordField.text.length >= minimumPasswordLength
               && repeatField.text === passwordField.text
    allowedOrientations: Orientation.All

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width

            DialogHeader {
                title: qsTr("New database")
                acceptText: qsTr("Create")
            }

            TextField {
                id: nameField

                width: parent.width
                label: qsTr("Name")
                placeholderText: label
                text: qsTr("Passwords")
                errorHighlight: dialog.name.length > 0 && (!dialog.validName || dialog.exists)
                description: dialog.exists ? qsTr("A database with this name already exists")
                           : dialog.name.length > 0 && !dialog.validName ? qsTr("Not a valid name")
                           : ""
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: passwordField.focus = true
            }

            ProtectionComboBox {
                id: kdfBox
            }

            PasswordInput {
                id: passwordField

                label: qsTr("Master password")
                errorText: text.length > 0 && text.length < dialog.minimumPasswordLength
                           ? qsTr("At least %1 characters").arg(dialog.minimumPasswordLength) : ""
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: repeatField.focus = true
            }

            PasswordInput {
                id: repeatField

                label: qsTr("Repeat master password")
                errorText: text.length > 0 && text !== passwordField.text
                           ? qsTr("The passwords differ") : ""
                EnterKey.enabled: dialog.canAccept
                EnterKey.onClicked: dialog.accept()
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Use a long passphrase of several words. Nobody can open the database without it, and it cannot be recovered.")
            }

            Item {
                width: 1
                height: Theme.paddingMedium
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("SailVault keeps the database where other apps cannot read it. To open it in KeePassXC on a computer, save a copy from the list of databases.")
            }
        }
    }
}
