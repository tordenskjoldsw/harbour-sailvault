import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "../components"

// Imports the Bitwarden/Vaultwarden export at path into a new group of the
// root group, and offers to delete an unencrypted export afterwards.
Page {
    id: page

    property string path
    readonly property int kind: importer.inspect(path)
    readonly property bool importable: kind === Importer.Unencrypted
                                       || kind === Importer.PasswordProtected
    property int error: -1
    property int importedCount: -1

    function statusText(status) {
        switch (status) {
        case Importer.AccountRestricted:
        case Importer.Unsupported:
            return qsTr("This export is encrypted with your account key and cannot be read outside Bitwarden. Export again with the file type \"JSON (Password protected)\".")
        case Importer.NotAnExport: return qsTr("This file is not a Bitwarden JSON export")
        case Importer.FileUnreadable: return qsTr("The file cannot be read")
        case Importer.FileTooLarge: return qsTr("The export exceeds the supported limits")
        case Importer.WrongPassword: return qsTr("Wrong export password")
        case Importer.Corrupted: return qsTr("The export is damaged")
        case Importer.NotAdded: return qsTr("The entries could not be added to the database")
        default: return ""
        }
    }

    function startImport() {
        if (!importer.busy && (kind === Importer.Unencrypted || passwordField.text.length > 0)) {
            error = -1
            importer.start(path, passwordField.text, qsTr("Bitwarden import"))
            passwordField.text = ""
        }
    }

    allowedOrientations: Orientation.All
    backNavigation: !importer.busy

    Connections {
        target: importer
        onFinished: {
            if (wasUnencrypted) {
                page.importedCount = entryCount
            } else {
                Notices.show(qsTr("%n entries imported", "", entryCount), Notice.Short)
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

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: page.importable ? Theme.highlightColor : Theme.errorColor
                text: {
                    if (page.importedCount >= 0)
                        return qsTr("%n entries imported. The export file is not encrypted: anyone who can read it can read every password in it.", "", page.importedCount)
                    if (page.kind === Importer.Unencrypted)
                        return qsTr("This export is not encrypted. The entries go into a new group \"Bitwarden import\". You can delete the file afterwards.")
                    if (page.kind === Importer.PasswordProtected)
                        return qsTr("Enter the password chosen for this export. The entries go into a new group \"Bitwarden import\".")
                    return page.statusText(page.kind)
                }
            }

            PasswordInput {
                id: passwordField

                visible: page.kind === Importer.PasswordProtected && page.importedCount < 0
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

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                visible: page.error >= 0 && page.error !== Importer.WrongPassword
                         && page.error !== Importer.Locked
                wrapMode: Text.Wrap
                color: Theme.errorColor
                text: page.statusText(page.error)
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Medium
                running: importer.busy
                visible: running
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.importable && page.importedCount < 0 && !importer.busy
                enabled: page.kind === Importer.Unencrypted || passwordField.text.length > 0
                text: qsTr("Import")
                onClicked: page.startImport()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.importedCount >= 0
                text: qsTr("Delete file")
                onClicked: {
                    Notices.show(importer.removeImportedFile() ? qsTr("Export file deleted")
                                                               : qsTr("The export file could not be deleted"),
                                 Notice.Short)
                    pageStack.pop()
                }
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.importedCount >= 0
                text: qsTr("Keep file")
                onClicked: pageStack.pop()
            }
        }
    }
}
