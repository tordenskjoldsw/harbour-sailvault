import QtQuick 2.0
import Sailfish.Silica 1.0
import "thirdparty.js" as ThirdParty

Page {
    id: page

    allowedOrientations: Orientation.All

    Component {
        id: licensePage

        Page {
            property var package_

            allowedOrientations: Orientation.All

            SilicaFlickable {
                anchors.fill: parent
                contentHeight: textColumn.height + Theme.paddingLarge

                Column {
                    id: textColumn

                    width: parent.width

                    PageHeader {
                        title: package_.name
                        description: package_.version + " · " + package_.license
                    }

                    Label {
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        textFormat: Text.PlainText
                        wrapMode: Text.Wrap
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.highlightColor
                        text: ThirdParty.texts[package_.text]
                    }
                }

                VerticalScrollDecorator {}
            }
        }
    }

    SilicaListView {
        id: listView

        anchors.fill: parent
        model: ThirdParty.packages

        header: Column {
            width: parent.width
            spacing: Theme.paddingLarge

            PageHeader {
                title: qsTr("Third-party licenses")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                textFormat: Text.PlainText
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.highlightColor
                text: qsTr("SailVault includes these libraries. Where a library offers a choice of licenses, SailVault uses the MIT license.")
            }

            Item {
                width: 1
                height: 1
            }
        }

        delegate: BackgroundItem {
            id: item

            height: Theme.itemSizeSmall
            onClicked: pageStack.push(licensePage, { "package_": modelData })

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                textFormat: Text.PlainText
                truncationMode: TruncationMode.Fade
                color: item.highlighted ? Theme.highlightColor : Theme.primaryColor
                text: modelData.name + " " + modelData.version + " · " + modelData.license
            }
        }

        VerticalScrollDecorator {}
    }
}
