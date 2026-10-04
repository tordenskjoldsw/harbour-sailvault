import QtQuick 2.0
import harbour.sailvault 1.0

// Texts for sync problems, shared by the pages that show them.
QtObject {
    function problem(problem) {
        switch (problem) {
        case Sync.Offline: return qsTr("Not synced: no connection to Nextcloud")
        case Sync.LoginFailed: return qsTr("Nextcloud did not accept the login")
        case Sync.CertificateUnknown: return qsTr("The server certificate is not trusted")
        case Sync.FolderMissing: return qsTr("The folder does not exist on Nextcloud")
        case Sync.OtherCredentials: return qsTr("The file on Nextcloud does not open with the credentials of this database")
        case Sync.NotDatabase: return qsTr("The file on Nextcloud is not a KeePass database")
        case Sync.InvalidServer: return qsTr("Enter the https address of your Nextcloud")
        case Sync.LoginExpired: return qsTr("The login in the browser was not completed in time")
        case Sync.ServerProblem: return qsTr("Nextcloud reported a problem")
        default: return ""
        }
    }
}
