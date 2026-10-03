import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

Page {
    id: page

    readonly property int lockMode: lockModeBox.currentIndex === 0 ? SystemKeyStore.VerifyLock
                                                                   : SystemKeyStore.Relock

    allowedOrientations: Orientation.All

    SystemKeyStore {
        id: keyStore
    }

    RemorsePopup {
        id: remorse
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: page.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: qsTr("SailVault")
            }

            DetailItem {
                label: qsTr("Core version")
                value: coreVersion
            }

            SectionHeader {
                text: qsTr("System authentication test")
            }

            ComboBox {
                id: lockModeBox

                label: qsTr("Unlock semantic")
                enabled: !keyStore.busy
                menu: ContextMenu {
                    MenuItem { text: "DeviceLockVerifyLock" }
                    MenuItem { text: "DeviceLockRelock" }
                }
            }

            ButtonLayout {
                Button {
                    text: qsTr("Store")
                    enabled: !keyStore.busy
                    onClicked: keyStore.storeTestKey(page.lockMode)
                }
                Button {
                    text: qsTr("Read")
                    enabled: !keyStore.busy
                    onClicked: keyStore.readTestKey(page.lockMode)
                }
                Button {
                    text: qsTr("Delete")
                    enabled: !keyStore.busy
                    onClicked: {
                        var mode = page.lockMode
                        remorse.execute(qsTr("Deleting test key"), function() {
                            keyStore.deleteTestKey(mode)
                        })
                    }
                }
            }

            BusyIndicator {
                anchors.horizontalCenter: parent.horizontalCenter
                size: BusyIndicatorSize.Medium
                running: keyStore.busy
                visible: running
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: keyStore.status
            }
        }
    }
}
