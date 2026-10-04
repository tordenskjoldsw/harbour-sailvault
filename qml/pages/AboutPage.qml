import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

Page {
    id: page

    readonly property string repository: "https://github.com/tordenskjoldsw/harbour-sailvault"

    allowedOrientations: Orientation.All

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader {
                title: qsTr("About")
            }

            Image {
                anchors.horizontalCenter: parent.horizontalCenter
                width: Theme.iconSizeExtraLarge
                height: width
                sourceSize { width: width; height: height }
                source: "/usr/share/icons/hicolor/172x172/apps/harbour-sailvault.png"
            }

            Column {
                width: parent.width

                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    textFormat: Text.PlainText
                    font.pixelSize: Theme.fontSizeLarge
                    color: Theme.highlightColor
                    text: "SailVault"
                }

                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    textFormat: Text.PlainText
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.secondaryHighlightColor
                    text: qsTr("Version %1").arg(appVersion)
                }

                Label {
                    anchors.horizontalCenter: parent.horizontalCenter
                    visible: appBuild.length > 0
                    textFormat: Text.PlainText
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: qsTr("Development build %1").arg(appBuild)
                }
            }

            Repeater {
                model: [
                    qsTr("I built SailVault to keep my passwords on my Sailfish phone in a standard KeePass file: no account, no server, no lock-in. The same file opens in KeePassXC on my computer."),
                    qsTr("Security comes first. SailVault connects to nothing but your own Nextcloud, and only once you set up sync. It never writes decrypted data to disk and asks for the full master password every time. It does not generate TOTP codes: keeping them next to the passwords would turn two factors into one."),
                    qsTr("SailVault is free software under the MIT license. Read the code, check what I claim here and tell me what you find.")
                ]

                Paragraph {
                    color: Theme.highlightColor
                    text: modelData
                }
            }

            Column {
                width: parent.width

                Repeater {
                    model: [
                        { "text": qsTr("Source code"), "url": page.repository },
                        { "text": qsTr("How SailVault protects your data"),
                          "url": page.repository + "/blob/main/docs/threat-model.md" },
                        { "text": qsTr("Report a problem"), "url": page.repository + "/issues" },
                        { "text": qsTr("Report a security issue privately"),
                          "url": page.repository + "/security/advisories/new" },
                        { "text": qsTr("Third-party licenses"), "url": "" }
                    ]

                    BackgroundItem {
                        id: link

                        width: parent.width
                        onClicked: {
                            if (modelData.url.length > 0)
                                Qt.openUrlExternally(modelData.url)
                            else
                                pageStack.push(Qt.resolvedUrl("ThirdPartyPage.qml"))
                        }

                        Label {
                            x: Theme.horizontalPageMargin
                            width: parent.width - 2 * Theme.horizontalPageMargin
                            anchors.verticalCenter: parent.verticalCenter
                            textFormat: Text.PlainText
                            truncationMode: TruncationMode.Fade
                            color: link.highlighted ? Theme.highlightColor : Theme.primaryColor
                            text: modelData.text
                        }
                    }
                }
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("Copyright 2026 Tobias Kaminski. SailVault is an independent project and not affiliated with KeePass, KeePassXC, Bitwarden or Jolla.")
            }
        }

        VerticalScrollDecorator {}
    }
}
