import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "../components"

// Sets up sync of the open database with a file on Nextcloud: through the
// Nextcloud login in the browser, or with an app password created by hand.
Page {
    id: page

    readonly property bool working: sync.setupState === Sync.WaitingForBrowser
                                    || sync.setupState === Sync.Checking
    readonly property bool ready: serverField.text.trim().length > 0
                                  && pathField.text.trim().length > 0 && !working

    function useAppPassword() {
        if (!manualButton.enabled)
            return
        sync.setUpManually(serverField.text, pathField.text, loginField.text,
                           appPasswordField.text)
        appPasswordField.text = ""
    }

    allowedOrientations: Orientation.All
    backNavigation: !working

    Component.onCompleted: sync.cancelSetup()

    SyncText {
        id: syncText
    }

    Connections {
        target: sync
        onSetupChanged: {
            if (sync.setupState === Sync.SetupDone) {
                Notices.show(qsTr("Sync set up"), Notice.Short)
                pageStack.pop()
            } else if (sync.setupState === Sync.SetupFailed
                       && sync.setupProblem === Sync.CertificateUnknown) {
                pageStack.push(Qt.resolvedUrl("CertificateDialog.qml"))
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: qsTr("Sync with Nextcloud")
            }

            TextField {
                id: serverField

                width: parent.width
                enabled: !page.working
                label: qsTr("Nextcloud address")
                placeholderText: "https://cloud.example.org"
                inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoAutoUppercase
                                  | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: pathField.focus = true
            }

            TextField {
                id: pathField

                width: parent.width
                enabled: !page.working
                label: qsTr("File on Nextcloud")
                placeholderText: label
                text: sync.defaultPath()
                description: qsTr("Missing folders and the file are created.")
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }

            Paragraph {
                visible: sync.setupState === Sync.SetupFailed
                color: Theme.errorColor
                text: syncText.problem(sync.setupProblem)
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Medium
                running: page.working
                visible: running
            }

            Paragraph {
                visible: sync.setupState === Sync.WaitingForBrowser
                text: qsTr("Log in to Nextcloud in the browser and grant access. Then come back here; SailVault waits for 20 minutes.")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: page.working
                text: qsTr("Cancel")
                onClicked: sync.cancelSetup()
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                visible: !page.working
                enabled: page.ready
                text: qsTr("Log in with the browser")
                onClicked: sync.startLogin(serverField.text, pathField.text)
            }

            SectionHeader {
                visible: !page.working
                text: qsTr("Or with an app password")
            }

            TextField {
                id: loginField

                visible: !page.working
                width: parent.width
                label: qsTr("Login name")
                placeholderText: label
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: appPasswordField.focus = true
            }

            PasswordInput {
                id: appPasswordField

                visible: !page.working
                label: qsTr("App password")
                EnterKey.enabled: page.ready && loginField.text.length > 0 && text.length > 0
                EnterKey.onClicked: page.useAppPassword()
            }

            Button {
                id: manualButton

                anchors.horizontalCenter: parent.horizontalCenter
                visible: !page.working
                enabled: page.ready && loginField.text.trim().length > 0
                         && appPasswordField.text.length > 0
                text: qsTr("Use app password")
                onClicked: page.useAppPassword()
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Create an app password in Nextcloud under Settings > Security. SailVault keeps it in this database as the entry \"Nextcloud sync (SailVault)\", protected by the master password. Anyone who can open the database can see it, also on your computer. You can revoke it in Nextcloud at any time.")
            }
        }
    }
}
