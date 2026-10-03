import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "../components"

// Imports the Bitwarden/Vaultwarden export at path into the import group,
// merging with an earlier import, and offers to delete an unencrypted export
// once its entries are saved.
Page {
    id: page

    property string path
    readonly property bool importable: importer.kind === Importer.Unencrypted
                                       || importer.kind === Importer.PasswordProtected
    property int error: -1
    property string resultText

    function statusText(status) {
        switch (status) {
        case Importer.UnsupportedFormat: return qsTr("This export is encrypted in a way SailVault cannot read")
        case Importer.NotAnExport: return qsTr("This file is not a Bitwarden JSON export")
        case Importer.FileUnreadable: return qsTr("The file cannot be read")
        case Importer.FileTooLarge: return qsTr("The export exceeds the supported limits")
        case Importer.WrongPassword: return qsTr("Wrong export password")
        case Importer.Corrupted: return qsTr("The export is damaged")
        case Importer.NotAdded: return qsTr("The entries could not be added to the database")
        case Importer.NotSaved: return qsTr("The entries were added but could not be saved. The export file is kept.")
        case Importer.FileChanged: return qsTr("The file changed while it was read. Select it again.")
        default: return ""
        }
    }

    function summary(added, updated) {
        if (added === 0 && updated === 0)
            return qsTr("Nothing new to import")
        // No translations exist yet, so %n plurals would read "1 entries".
        if (updated === 0)
            return added === 1 ? qsTr("1 entry imported") : qsTr("%1 entries imported").arg(added)
        return qsTr("%1 new, %2 updated").arg(added).arg(updated)
    }

    function startImport() {
        if (!importer.busy && (importer.kind === Importer.Unencrypted || passwordField.text.length > 0)) {
            error = -1
            importer.start(passwordField.text)
            passwordField.text = ""
        }
    }

    allowedOrientations: Orientation.All
    backNavigation: !importer.busy

    Component.onCompleted: importer.inspect(path)

    RemorsePopup {
        id: remorse
    }

    Connections {
        target: importer
        onFinished: {
            if (fileRemovable) {
                page.resultText = page.summary(added, updated)
            } else {
                Notices.show(page.summary(added, updated), Notice.Short)
                pageStack.pop()
            }
        }
        onFailed: page.error = status
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader {
                title: qsTr("Import from Bitwarden")
                description: page.path.substring(page.path.lastIndexOf("/") + 1)
            }

            Paragraph {
                color: importer.kind === Importer.AccountRestricted ? Theme.errorColor
                                                                    : Theme.highlightColor
                text: {
                    if (page.resultText.length > 0)
                        return page.resultText + ". "
                                + qsTr("The export file is not encrypted: anyone who can read it can read every password in it.")
                    switch (importer.kind) {
                    case Importer.Unencrypted:
                        return qsTr("This export is not encrypted. The entries go into the group \"%1\"; an earlier import there is updated. You can delete the file afterwards.").arg(importer.groupName)
                    case Importer.PasswordProtected:
                        return qsTr("Enter the password chosen for this export. The entries go into the group \"%1\"; an earlier import there is updated.").arg(importer.groupName)
                    case Importer.AccountRestricted:
                        return qsTr("This export is encrypted with your account key and cannot be read outside Bitwarden. Export again with the file type \"JSON (Password protected)\".")
                    default:
                        return ""
                    }
                }
            }

            PasswordInput {
                id: passwordField

                visible: importer.kind === Importer.PasswordProtected && page.resultText.length === 0
                enabled: !importer.busy
                label: qsTr("Export password")
                errorText: page.error === Importer.WrongPassword ? page.statusText(page.error) : ""
                focus: visible
                EnterKey.enabled: text.length > 0
                EnterKey.onClicked: page.startImport()
                onTextChanged: {
                    if (text.length > 0 && page.error === Importer.WrongPassword)
                        page.error = -1
                }
            }

            Paragraph {
                visible: page.error >= 0 && page.error !== Importer.WrongPassword
                         && page.error !== Importer.Locked
                color: Theme.errorColor
                text: page.statusText(page.error)
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Medium
                running: importer.busy || (importer.kind === Importer.Unknown && page.error < 0)
                visible: running
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.importable && page.resultText.length === 0 && !importer.busy
                enabled: importer.kind === Importer.Unencrypted || passwordField.text.length > 0
                text: qsTr("Import")
                onClicked: page.startImport()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.resultText.length > 0
                text: qsTr("Delete file")
                onClicked: remorse.execute(qsTr("Deleting the export file"), function() {
                    Notices.show(importer.removeImportedFile() ? qsTr("Export file deleted")
                                                               : qsTr("The export file could not be deleted"),
                                 Notice.Short)
                    pageStack.pop()
                })
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.resultText.length > 0
                text: qsTr("Keep file")
                onClicked: pageStack.pop()
            }
        }
    }
}
