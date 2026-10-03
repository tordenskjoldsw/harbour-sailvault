import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0
import "pages"

ApplicationWindow {
    id: window

    initialPage: Component { UnlockPage { } }
    cover: Qt.resolvedUrl("cover/CoverPage.qml")
    allowedOrientations: defaultAllowedOrientations

    Connections {
        target: vault
        onStateChanged: {
            if (vault.state === Vault.Locked && pageStack.depth > 1) {
                pageStack.pop(pageStack.find(function(page) { return page.isUnlockPage === true }),
                              PageStackAction.Immediate)
            }
        }
        onLockedAutomatically: Notices.show(qsTr("Locked automatically"), Notice.Short)
    }
}
