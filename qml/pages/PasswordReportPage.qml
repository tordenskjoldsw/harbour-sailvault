import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "../components"

// Lists the entries whose password is weak or used more than once. The vault
// rates all passwords in the background; nothing of a password comes here.
Page {
    id: page

    property var entries: []
    // How many passwords the last report rated; -1 before the first one.
    property int checked: -1
    property bool failed
    // The entries changed since the last report, or there is none yet.
    property bool stale: true
    readonly property bool unlocked: vault.state === Vault.Unlocked

    // A report waits for a running save or merge and runs again once an
    // entry was changed from here.
    function refresh() {
        if (stale && status === PageStatus.Active && unlocked && !vault.saving && !vault.merging
                && !vault.reporting && vault.startPasswordReport())
            stale = false
    }

    function qualityText(quality) {
        return quality === PasswordStrength.Poor ? qsTr("Poor") : qsTr("Weak")
    }

    function describe(entry) {
        var parts = []
        if (entry.quality <= PasswordStrength.Weak) {
            //: Password quality and estimated entropy, e.g. "Weak (52 bits)"
            parts.push(qsTr("%1 (%2 bits)").arg(qualityText(entry.quality))
                                           .arg(Math.floor(entry.bits)))
        }
        if (entry.sharedWith > 0) {
            //: %1 is 2 or more
            parts.push(qsTr("same password in %1 entries").arg(entry.sharedWith + 1))
        }
        return parts.join(" · ")
    }

    allowedOrientations: Orientation.All
    onStatusChanged: refresh()
    Component.onDestruction: vault.cancelPasswordReport()

    Connections {
        target: vault
        onPasswordReportFinished: {
            page.entries = entries
            page.checked = checked
            page.failed = false
        }
        onPasswordReportFailed: page.failed = true
        onContentChanged: {
            page.stale = true
            page.refresh()
        }
        onSavingChanged: page.refresh()
        onMergingChanged: page.refresh()
        onReportingChanged: page.refresh()
        onStateChanged: {
            if (!page.unlocked) {
                page.entries = []
                page.checked = -1
            }
        }
    }

    SilicaListView {
        id: listView

        anchors.fill: parent
        model: page.entries

        PullDownMenu {
            MenuItem {
                text: qsTr("Lock")
                onClicked: vault.lock()
            }
            MenuItem {
                text: qsTr("Check again")
                enabled: !vault.reporting
                onClicked: {
                    page.stale = true
                    page.refresh()
                }
            }
        }

        header: Column {
            width: listView.width

            PageHeader {
                title: qsTr("Password report")
                description: page.checked >= 0 ? qsTr("Passwords checked: %1").arg(page.checked) : ""
            }

            Paragraph {
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryHighlightColor
                text: qsTr("Passwords rated Poor or Weak, and passwords used in more than one entry. Entries in the recycle bin are left out. The rating knows English words only.")
            }

            Item {
                width: 1
                height: Theme.paddingLarge
            }
        }

        delegate: ListItem {
            id: item

            contentHeight: Theme.itemSizeMedium
            onClicked: pageStack.push(Qt.resolvedUrl("EntryPage.qml"),
                                      { "entryId": modelData.id, "entryTitle": modelData.title })

            TwoLineLabel {
                anchors.fill: parent
                highlighted: item.highlighted
                iconSource: "image://theme/icon-m-keys"
                title: modelData.title.length > 0 ? modelData.title : qsTr("(no title)")
                description: page.describe(modelData)
            }
        }

        ViewPlaceholder {
            enabled: !vault.reporting && page.entries.length === 0
                     && (page.failed || page.checked >= 0)
            text: page.failed ? qsTr("The passwords could not be checked")
                              : qsTr("No weak or reused passwords")
        }

        VerticalScrollDecorator {}
    }

    BusyLabel {
        running: vault.reporting && page.entries.length === 0
        text: qsTr("Checking passwords")
    }
}
