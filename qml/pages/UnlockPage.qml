import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import harbour.sailvault 1.0
import "../components"

Page {
    id: page

    readonly property bool isUnlockPage: true
    readonly property bool unlocking: vault.state === Vault.Unlocking
    property bool creating
    readonly property bool passwordError: vault.error === Vault.WrongCredentials
    readonly property bool keyFileError: vault.error === Vault.InvalidKeyFile
    readonly property bool databaseError: vault.error !== Vault.NoError && !passwordError
                                          && !keyFileError

    function fileName(path) {
        return path.substring(path.lastIndexOf("/") + 1)
    }

    function errorText(error) {
        switch (error) {
        case Vault.WrongCredentials: return qsTr("Wrong password or key file")
        case Vault.InvalidKeyFile: return qsTr("The key file is not valid")
        case Vault.Kdbx3Unsupported: return qsTr("This database uses the older KDBX 3 format. Please convert it to KDBX 4 in KeePassXC.")
        case Vault.NotKdbx: return qsTr("This file is not a KeePass database")
        case Vault.UnsupportedFormat: return qsTr("This database uses an unsupported format")
        case Vault.Corrupted: return qsTr("The database is damaged")
        case Vault.TooLarge: return qsTr("The database or its settings exceed the supported limits")
        case Vault.FileUnreadable: return qsTr("The file cannot be read")
        case Vault.FileUnwritable: return qsTr("The file cannot be written")
        case Vault.FileExists: return qsTr("A file with this name already exists")
        case Vault.ChangesDiscarded: return qsTr("Changes that could not be saved were discarded when the database locked")
        default: return ""
        }
    }

    function createDatabase() {
        var dialog = pageStack.push(Qt.resolvedUrl("NewDatabaseDialog.qml"))
        dialog.accepted.connect(function() {
            page.creating = true
            vault.createDatabase(dialog.location, dialog.fileName, dialog.password,
                                 dialog.kdfLevel)
        })
    }

    function unlock() {
        if (vault.databasePath.length > 0 && !unlocking) {
            vault.unlock(passwordField.text)
            passwordField.text = ""
        }
    }

    allowedOrientations: Orientation.All

    // Swiping back from the entry list leaves the database, so it locks
    // instead of staying open behind a page that looks locked.
    onStatusChanged: {
        if (status === PageStatus.Active && vault.state === Vault.Unlocked)
            vault.lock()
    }

    Connections {
        target: vault
        onStateChanged: {
            if (vault.state !== Vault.Unlocking)
                page.creating = false
            if (vault.state === Vault.Unlocked) {
                pageStack.push(Qt.resolvedUrl("EntryListPage.qml"),
                               { "groupId": "", "groupName": "SailVault" })
            }
        }
    }

    Component {
        id: databasePicker
        FilePickerPage {
            nameFilters: ["*.kdbx"]
            onSelectedContentPropertiesChanged: vault.databasePath = selectedContentProperties.filePath
        }
    }

    Component {
        id: keyFilePicker
        FilePickerPage {
            onSelectedContentPropertiesChanged: vault.keyFilePath = selectedContentProperties.filePath
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        PullDownMenu {
            visible: !page.unlocking

            MenuItem {
                text: qsTr("About")
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))
            }
            MenuItem {
                text: qsTr("New database")
                onClicked: page.createDatabase()
            }
            MenuItem {
                visible: vault.keyFilePath.length > 0
                text: qsTr("Remove key file")
                onClicked: vault.keyFilePath = ""
            }
        }

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingMedium
            enabled: !page.unlocking

            PageHeader {
                title: "SailVault"
                description: window.lockedAutomatically ? qsTr("Locked automatically") : ""
            }

            ValueButton {
                label: qsTr("Database")
                value: vault.databasePath.length > 0 ? page.fileName(vault.databasePath)
                                                     : qsTr("Select")
                descriptionColor: Theme.errorColor
                description: page.databaseError ? page.errorText(vault.error) : ""
                onClicked: pageStack.push(databasePicker)
            }

            ValueButton {
                label: qsTr("Key file")
                value: vault.keyFilePath.length > 0 ? page.fileName(vault.keyFilePath)
                                                    : qsTr("None")
                descriptionColor: Theme.errorColor
                description: page.keyFileError ? page.errorText(vault.error) : ""
                onClicked: pageStack.push(keyFilePicker)
            }

            PasswordInput {
                id: passwordField

                label: qsTr("Master password")
                errorText: page.passwordError ? page.errorText(vault.error) : ""
                EnterKey.enabled: vault.databasePath.length > 0
                EnterKey.onClicked: page.unlock()
                onTextChanged: {
                    if (text.length > 0)
                        vault.clearError()
                }
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Unlock")
                enabled: vault.databasePath.length > 0
                onClicked: page.unlock()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: vault.databasePath.length === 0
                text: qsTr("New database")
                onClicked: page.createDatabase()
            }
        }
    }

    BusyLabel {
        running: page.unlocking
        text: page.creating ? qsTr("Creating database") : qsTr("Unlocking")
    }
}
