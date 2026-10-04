import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "../components"

// Merges the copy of the database at path, such as the file from the
// computer, into the open database and offers to delete the file once the
// result is saved.
Page {
    id: page

    property string path
    readonly property bool merging: vault.merging
    property bool needsPassword
    property bool triedPassword
    property bool finished
    property string resultText
    property string errorText

    function fileName(path) {
        return path.substring(path.lastIndexOf("/") + 1)
    }

    function failureText(error) {
        switch (error) {
        case Vault.NotKdbx: return qsTr("This file is not a KeePass database")
        case Vault.UnsupportedFormat: return qsTr("This database uses an unsupported format")
        case Vault.InvalidKeyFile: return qsTr("The key file of this database does not open the file")
        case Vault.TooLarge: return qsTr("The file or its settings exceed the supported limits")
        case Vault.FileUnreadable: return qsTr("The file cannot be read")
        default: return qsTr("The file is damaged")
        }
    }

    function summary(added, modified, moved, deleted) {
        if (added + modified + moved + deleted === 0)
            return qsTr("The database already has every change from this file.")
        // No translations exist yet, so counts go after a label instead of
        // into %n plurals.
        var lines = []
        if (added > 0)
            lines.push(qsTr("Added: %1").arg(added))
        if (modified > 0)
            lines.push(qsTr("Changed: %1").arg(modified))
        if (moved > 0)
            lines.push(qsTr("Moved: %1").arg(moved))
        if (deleted > 0)
            lines.push(qsTr("Deleted: %1").arg(deleted))
        return lines.join("\n")
    }

    function mergeWithPassword() {
        if (passwordField.text.length > 0 && !merging) {
            needsPassword = false
            triedPassword = true
            vault.mergeFile(path, passwordField.text)
            passwordField.text = ""
        }
    }

    allowedOrientations: Orientation.All
    backNavigation: !merging

    Component.onCompleted: vault.mergeFile(path, "")

    RemorsePopup {
        id: remorse
    }

    Connections {
        target: vault
        onMergeNeedsPassword: page.needsPassword = true
        onMergeFinished: {
            page.finished = true
            page.resultText = page.summary(added, modified, moved, deleted)
        }
        onMergeFailed: page.errorText = page.failureText(error)
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader {
                title: qsTr("Merge with file")
                description: page.fileName(page.path)
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Medium
                running: page.merging || vault.saving
                visible: running
            }

            Paragraph {
                visible: page.needsPassword
                text: qsTr("This file does not open with the master password of this database. Enter the master password of the file.")
            }

            PasswordInput {
                id: passwordField

                visible: page.needsPassword
                label: qsTr("Master password of the file")
                errorText: page.triedPassword ? qsTr("Wrong password") : ""
                focus: visible
                EnterKey.enabled: text.length > 0
                EnterKey.onClicked: page.mergeWithPassword()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.needsPassword
                enabled: passwordField.text.length > 0
                text: qsTr("Merge")
                onClicked: page.mergeWithPassword()
            }

            Paragraph {
                visible: page.errorText.length > 0
                color: Theme.errorColor
                text: page.errorText
            }

            Paragraph {
                visible: page.finished
                text: page.resultText
            }

            Paragraph {
                visible: page.finished && !vault.saving && !vault.dirty
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("The file stays where it is, and other apps can read it. Delete it once you no longer need it.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.finished
                enabled: !vault.saving && !vault.dirty
                text: qsTr("Delete file")
                onClicked: remorse.execute(qsTr("Deleting the file"), function() {
                    Notices.show(vault.removeMergedFile() ? qsTr("File deleted")
                                                          : qsTr("The file could not be deleted"),
                                 Notice.Short)
                    pageStack.pop()
                })
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.finished || page.errorText.length > 0
                enabled: !page.merging
                text: page.finished ? qsTr("Keep file") : qsTr("Back")
                onClicked: pageStack.pop()
            }
        }
    }
}
