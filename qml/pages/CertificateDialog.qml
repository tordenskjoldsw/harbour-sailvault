import QtQuick 2.0
import Sailfish.Silica 1.0
import "../components"

// Asks whether to trust a server certificate the phone does not, shown by
// its SHA-256 fingerprint. Accepting pins exactly this certificate.
Dialog {
    allowedOrientations: Orientation.All

    onAccepted: sync.trustCertificate()

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width
            spacing: Theme.paddingLarge

            DialogHeader {
                title: sync.certificateReplaced ? qsTr("Certificate changed")
                                                : qsTr("Untrusted certificate")
                acceptText: qsTr("Trust")
            }

            Paragraph {
                text: sync.certificateReplaced
                      ? qsTr("The server presents another certificate than the one you trusted before. That happens when the certificate was renewed, but also when someone intercepts the connection and could read your Nextcloud app password. Only trust it if this fingerprint matches the one your server shows.")
                      : qsTr("This phone does not trust the certificate of the server, as with a self-signed certificate. Only trust it if this fingerprint matches the one your server shows. SailVault then accepts exactly this certificate and no other.")
            }

            Paragraph {
                font.family: "monospace"
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.highlightColor
                wrapMode: Text.WrapAnywhere
                text: sync.certificateFingerprint
            }
        }
    }
}
