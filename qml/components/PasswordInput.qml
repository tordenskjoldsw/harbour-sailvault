import QtQuick 2.0
import Sailfish.Silica 1.0

// A password field that shows errorText below itself and highlights the
// field while there is an error.
PasswordField {
    property string errorText

    width: parent ? parent.width : 0
    errorHighlight: errorText.length > 0
    description: errorText
    EnterKey.iconSource: "image://theme/icon-m-enter-accept"
}
