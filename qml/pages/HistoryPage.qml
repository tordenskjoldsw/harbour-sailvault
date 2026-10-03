import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "../components"

// The history items of entryId, newest first; each opens read-only.
Page {
    id: page

    property string entryId

    allowedOrientations: Orientation.All

    SilicaListView {
        id: listView

        anchors.fill: parent
        // Empties on lock even if the page stack cannot pop the page at once.
        model: vault.state === Vault.Unlocked ? vault.history(page.entryId) : []

        header: PageHeader {
            title: qsTr("History")
        }

        delegate: BackgroundItem {
            id: item

            readonly property string time: Qt.formatDateTime(modelData.modified,
                                                             Qt.DefaultLocaleShortDate)

            height: Theme.itemSizeMedium

            onClicked: pageStack.push(Qt.resolvedUrl("EntryPage.qml"),
                                      { "entryId": page.entryId,
                                        "entryTitle": modelData.title,
                                        "version": modelData.version,
                                        "versionTime": item.time })

            TwoLineLabel {
                anchors.fill: parent
                highlighted: item.highlighted
                title: item.time
                description: modelData.title
                             + (modelData.userName.length > 0 ? " · " + modelData.userName : "")
            }
        }

        ViewPlaceholder {
            enabled: listView.count === 0
            text: qsTr("No history")
        }

        VerticalScrollDecorator {}
    }
}
