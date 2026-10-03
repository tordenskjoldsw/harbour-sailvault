import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import harbour.sailvault 1.0

Page {
    id: page

    readonly property bool isUnlockPage: true
    readonly property bool unlocking: vault.state === Vault.Unlocking
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
        default: return ""
        }
    }

    function unlock() {
        if (vault.databasePath.length > 0 && !unlocking) {
            vault.unlock(passwordField.text)
            passwordField.text = ""
        }
    }

    allowedOrientations: Orientation.All

    Connections {
        target: vault
        onStateChanged: {
            if (vault.state === Vault.Unlocked) {
                pageStack.push(Qt.resolvedUrl("EntryListPage.qml"),
                               { "groupId": "", "groupName": qsTr("SailVault") })
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
            visible: vault.keyFilePath.length > 0
            MenuItem {
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
                title: qsTr("SailVault")
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

            PasswordField {
                id: passwordField

                width: parent.width
                label: qsTr("Master password")
                errorHighlight: page.passwordError
                description: page.passwordError ? page.errorText(vault.error) : ""
                EnterKey.enabled: vault.databasePath.length > 0
                EnterKey.iconSource: "image://theme/icon-m-enter-accept"
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
        }
    }

    BusyLabel {
        running: page.unlocking
        text: qsTr("Unlocking")
    }
}
