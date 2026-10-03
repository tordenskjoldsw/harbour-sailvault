import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

CoverBackground {
    readonly property bool unlocked: vault.state === Vault.Unlocked

    Column {
        anchors.centerIn: parent
        width: parent.width - 2 * Theme.paddingLarge
        spacing: Theme.paddingMedium

        Image {
            anchors.horizontalCenter: parent.horizontalCenter
            source: "image://theme/icon-m-keys"
        }

        Label {
            textFormat: Text.PlainText
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            text: "SailVault"
        }

        Label {
            textFormat: Text.PlainText
            width: parent.width
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.secondaryColor
            text: unlocked ? qsTr("Unlocked") : qsTr("Locked")
        }
    }

    CoverActionList {
        enabled: unlocked

        CoverAction {
            iconSource: "image://theme/icon-m-device-lock"
            onTriggered: vault.lock()
        }
    }
}
