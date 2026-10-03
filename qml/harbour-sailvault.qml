import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "pages"

ApplicationWindow {
    id: window

    // A notice would expire while the app is in the background, so the
    // unlock page shows the reason until the next unlock.
    property bool lockedAutomatically: false

    initialPage: Component { UnlockPage { } }
    cover: Qt.resolvedUrl("cover/CoverPage.qml")
    allowedOrientations: defaultAllowedOrientations

    Connections {
        target: vault
        onStateChanged: {
            if (vault.state === Vault.Unlocked)
                window.lockedAutomatically = false
            if (vault.state === Vault.Locked && pageStack.depth > 1) {
                pageStack.pop(pageStack.find(function(page) { return page.isUnlockPage === true }),
                              PageStackAction.Immediate)
            }
        }
        onLockedAutomatically: window.lockedAutomatically = true
    }
}
