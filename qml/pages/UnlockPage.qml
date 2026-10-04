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
    // A file from outside the app is unlocked and stored, instead of a
    // stored database.
    readonly property bool adding: vault.sourcePath.length > 0
    property var storedNames: databases.names()
    readonly property string addName: nameField.text.trim()
    readonly property bool addNameTaken: databases.exists(addName)
    readonly property bool canUnlock: adding ? databases.isValidName(addName) && !addNameTaken
                                             : vault.databaseName.length > 0
    readonly property bool passwordError: vault.error === Vault.WrongCredentials
    readonly property bool keyFileError: adding && vault.error === Vault.InvalidKeyFile
    readonly property bool databaseError: vault.error !== Vault.NoError && !passwordError
                                          && !keyFileError

    function fileName(path) {
        return path.substring(path.lastIndexOf("/") + 1)
    }

    function baseName(path) {
        var name = fileName(path)
        var dot = name.lastIndexOf(".")
        return dot > 0 ? name.substring(0, dot) : name
    }

    function cancelAdding() {
        vault.sourcePath = ""
        vault.sourceKeyFilePath = ""
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
        case Vault.FileExists: return qsTr("A database with this name already exists")
        case Vault.ChangesDiscarded: return qsTr("Changes that could not be saved were discarded when the database locked")
        default: return ""
        }
    }

    function createDatabase() {
        var dialog = pageStack.push(Qt.resolvedUrl("NewDatabaseDialog.qml"))
        dialog.accepted.connect(function() {
            page.creating = true
            vault.createDatabase(dialog.name, dialog.password, dialog.kdfLevel)
        })
    }

    function unlock() {
        if (!canUnlock || unlocking)
            return
        if (adding)
            vault.addDatabase(addName, passwordField.text)
        else
            vault.unlock(passwordField.text)
        passwordField.text = ""
    }

    allowedOrientations: Orientation.All

    // Swiping back from the entry list leaves the database, so it locks
    // instead of staying open behind a page that looks locked.
    onStatusChanged: {
        if (status === PageStatus.Active) {
            if (vault.state === Vault.Unlocked)
                vault.lock()
            storedNames = databases.names()
        }
    }

    Component.onCompleted: nameField.text = baseName(vault.sourcePath)

    Connections {
        target: vault
        onSourcePathChanged: nameField.text = page.baseName(vault.sourcePath)
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
        id: sourcePicker
        FilePickerPage {
            nameFilters: ["*.kdbx"]
            onSelectedContentPropertiesChanged: vault.sourcePath = selectedContentProperties.filePath
        }
    }

    Component {
        id: keyFilePicker
        FilePickerPage {
            onSelectedContentPropertiesChanged: vault.sourceKeyFilePath = selectedContentProperties.filePath
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
                text: qsTr("Add existing database")
                onClicked: pageStack.push(sourcePicker)
            }
            MenuItem {
                visible: page.adding
                text: qsTr("Cancel adding")
                onClicked: page.cancelAdding()
            }
            MenuItem {
                visible: page.adding && vault.sourceKeyFilePath.length > 0
                text: qsTr("Remove key file")
                onClicked: vault.sourceKeyFilePath = ""
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
                visible: page.adding || page.storedNames.length > 0
                label: qsTr("Database")
                value: page.adding ? page.fileName(vault.sourcePath)
                                   : vault.databaseName.length > 0 ? vault.databaseName
                                                                   : qsTr("Select")
                descriptionColor: page.databaseError ? Theme.errorColor
                                                     : Theme.secondaryHighlightColor
                description: page.databaseError ? page.errorText(vault.error)
                           : page.adding ? qsTr("SailVault keeps its own copy, which other apps cannot read")
                           : databases.hasKeyFile(vault.databaseName) ? qsTr("Opens with its stored key file")
                           : ""
                onClicked: pageStack.push(page.adding ? sourcePicker
                                                      : Qt.resolvedUrl("DatabasesPage.qml"))
            }

            TextField {
                id: nameField

                visible: page.adding
                width: parent.width
                label: qsTr("Name in SailVault")
                placeholderText: label
                errorHighlight: page.addName.length > 0 && !page.canUnlock
                description: page.addNameTaken ? qsTr("A database with this name already exists")
                           : page.addName.length > 0 && !databases.isValidName(page.addName)
                             ? qsTr("Not a valid name") : ""
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: passwordField.focus = true
            }

            ValueButton {
                visible: page.adding
                label: qsTr("Key file")
                value: vault.sourceKeyFilePath.length > 0 ? page.fileName(vault.sourceKeyFilePath)
                                                          : qsTr("None")
                descriptionColor: Theme.errorColor
                description: page.keyFileError ? page.errorText(vault.error) : ""
                onClicked: pageStack.push(keyFilePicker)
            }

            PasswordInput {
                id: passwordField

                label: qsTr("Master password")
                errorText: page.passwordError ? page.errorText(vault.error) : ""
                EnterKey.enabled: page.canUnlock
                EnterKey.onClicked: page.unlock()
                onTextChanged: {
                    if (text.length > 0)
                        vault.clearError()
                }
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.adding ? qsTr("Add and unlock") : qsTr("Unlock")
                enabled: page.canUnlock
                onClicked: page.unlock()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !page.adding && page.storedNames.length === 0
                text: qsTr("New database")
                onClicked: page.createDatabase()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !page.adding && page.storedNames.length === 0
                text: qsTr("Add existing database")
                onClicked: pageStack.push(sourcePicker)
            }
        }
    }

    BusyLabel {
        running: page.unlocking
        text: page.creating ? qsTr("Creating database")
                            : page.adding ? qsTr("Adding database") : qsTr("Unlocking")
    }
}
