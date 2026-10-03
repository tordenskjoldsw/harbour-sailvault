import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "../components"

// Asks for the file name, the folder and the master password of a new
// database. The caller creates it from these properties when accepted.
Dialog {
    id: dialog

    // NIST SP 800-63B rev. 4 asks for 15 characters when a password is the
    // only factor, as the master password is here.
    readonly property int minimumPasswordLength: 15
    readonly property string fileName: nameField.text.trim()
    readonly property int location: locationBox.currentIndex === 1 ? Vault.Downloads
                                                                    : Vault.Documents
    readonly property string path: vault.newDatabasePath(location, fileName)
    readonly property bool exists: vault.databaseExists(location, fileName)
    property alias password: passwordField.text
    readonly property int kdfLevel: [Vault.KdfStandard, Vault.KdfHigh,
                                     Vault.KdfMaximum][kdfBox.currentIndex]

    canAccept: path.length > 0 && !exists
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
                label: qsTr("File name")
                placeholderText: label
                text: qsTr("Passwords")
                errorHighlight: dialog.fileName.length > 0 && (dialog.path.length === 0 || dialog.exists)
                description: dialog.exists ? qsTr("A file with this name already exists")
                           : dialog.fileName.length > 0 && dialog.path.length === 0
                             ? qsTr("Not a valid file name") : dialog.fileName + ".kdbx"
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: passwordField.focus = true
            }

            ComboBox {
                id: locationBox

                label: qsTr("Folder")
                menu: ContextMenu {
                    MenuItem { text: qsTr("Documents") }
                    MenuItem { text: qsTr("Downloads") }
                }
            }

            ComboBox {
                id: kdfBox

                label: qsTr("Protection")
                description: qsTr("Higher levels make each guess of the master password cost an attacker more. The time applies to every unlock and save on this phone.")
                menu: ContextMenu {
                    MenuItem { text: qsTr("Standard (about 1 s)") }
                    MenuItem { text: qsTr("High (about 2.5 s)") }
                    MenuItem { text: qsTr("Maximum (about 5 s)") }
                }
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
        }
    }
}
