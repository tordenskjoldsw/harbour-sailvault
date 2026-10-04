import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import harbour.sailvault 1.0
import "../components"

// Settings and occasional actions: sync, merging a copy and importing for
// the open database, and the About page. The entry list keeps its pulley
// menu for the frequent actions.
Page {
    id: page

    // The file pickers close themselves after a selection; the import or
    // merge page opens once this page is back.
    property string pendingImportPath
    property string pendingMergePath

    function syncDescription() {
        if (!sync.configured)
            return qsTr("Not set up")
        switch (sync.state) {
        case Sync.Syncing:
            return qsTr("Syncing")
        case Sync.Failed:
            return syncText.problem(sync.problem)
        default:
            return isNaN(sync.lastSynced.getTime())
                    ? qsTr("Set up")
                    : qsTr("Last synced %1").arg(Qt.formatDateTime(sync.lastSynced,
                                                                   Qt.DefaultLocaleShortDate))
        }
    }

    onStatusChanged: {
        if (status !== PageStatus.Active)
            return
        if (pendingImportPath.length > 0) {
            var path = pendingImportPath
            pendingImportPath = ""
            pageStack.push(Qt.resolvedUrl("ImportPage.qml"), { "path": path })
        } else if (pendingMergePath.length > 0) {
            var mergePath = pendingMergePath
            pendingMergePath = ""
            pageStack.push(Qt.resolvedUrl("MergePage.qml"), { "path": mergePath })
        }
    }

    allowedOrientations: Orientation.All

    SyncText {
        id: syncText
    }

    Component {
        id: exportPicker

        FilePickerPage {
            nameFilters: ["*.json"]
            onSelectedContentPropertiesChanged: page.pendingImportPath = selectedContentProperties.filePath
        }
    }

    Component {
        id: mergePicker

        FilePickerPage {
            nameFilters: ["*.kdbx"]
            onSelectedContentPropertiesChanged: page.pendingMergePath = selectedContentProperties.filePath
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column

            width: parent.width

            PageHeader {
                title: qsTr("Settings")
            }

            SectionHeader {
                text: qsTr("This database")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                textFormat: Text.PlainText
                truncationMode: TruncationMode.Fade
                color: Theme.highlightColor
                text: vault.databaseName
            }

            BackgroundItem {
                id: syncItem

                height: Theme.itemSizeMedium
                enabled: !vault.saving && !vault.merging
                onClicked: pageStack.push(Qt.resolvedUrl("SyncSetupPage.qml"))

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: syncItem.highlighted
                    title: qsTr("Sync with Nextcloud")
                    description: page.syncDescription()
                }
            }

            BackgroundItem {
                id: mergeItem

                height: Theme.itemSizeMedium
                enabled: !vault.saving && !vault.merging
                onClicked: pageStack.push(mergePicker)

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: mergeItem.highlighted
                    title: qsTr("Merge with file")
                    description: qsTr("Bring in the changes of another copy, such as one from your computer")
                }
            }

            BackgroundItem {
                id: importItem

                height: Theme.itemSizeMedium
                enabled: !vault.saving && !importer.busy
                onClicked: pageStack.push(exportPicker)

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: importItem.highlighted
                    title: qsTr("Import from Bitwarden")
                    description: qsTr("A JSON export from Bitwarden or Vaultwarden")
                }
            }

            SectionHeader {
                text: qsTr("SailVault")
            }

            BackgroundItem {
                id: aboutItem

                height: Theme.itemSizeMedium
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))

                TwoLineLabel {
                    anchors.fill: parent
                    highlighted: aboutItem.highlighted
                    title: qsTr("About SailVault")
                    description: qsTr("Version, license and security")
                }
            }
        }

        VerticalScrollDecorator { }
    }
}
