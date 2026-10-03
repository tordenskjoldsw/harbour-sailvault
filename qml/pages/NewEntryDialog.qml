import QtQuick 2.0
import Sailfish.Silica 1.0

Dialog {
    id: dialog

    property string groupId

    canAccept: titleField.text.trim().length > 0
    allowedOrientations: Orientation.All

    onAccepted: {
        vault.addEntry(groupId, {
            "Title": titleField.text.trim(),
            "UserName": userNameField.text,
            "Password": passwordField.text,
            "URL": urlField.text.trim(),
            "Notes": notesField.text
        })
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        Column {
            id: column

            width: parent.width

            DialogHeader {
                title: qsTr("New entry")
                acceptText: qsTr("Save")
            }

            TextField {
                id: titleField

                width: parent.width
                label: qsTr("Title")
                placeholderText: label
                focus: true
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: userNameField.focus = true
            }

            TextField {
                id: userNameField

                width: parent.width
                label: qsTr("User name")
                placeholderText: label
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: passwordField.focus = true
            }

            PasswordField {
                id: passwordField

                width: parent.width
                label: qsTr("Password")
                placeholderText: label
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: urlField.focus = true
            }

            TextField {
                id: urlField

                width: parent.width
                label: qsTr("Website")
                placeholderText: label
                inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: notesField.focus = true
            }

            TextArea {
                id: notesField

                width: parent.width
                label: qsTr("Notes")
                placeholderText: label
            }

            SectionHeader {
                text: qsTr("Password generator")
            }

            Slider {
                id: lengthSlider

                width: parent.width
                label: qsTr("Length")
                minimumValue: 8
                maximumValue: 64
                stepSize: 1
                value: 20
                valueText: value
            }

            TextSwitch {
                id: lowerSwitch
                text: qsTr("Lower case letters")
                checked: true
            }

            TextSwitch {
                id: upperSwitch
                text: qsTr("Upper case letters")
                checked: true
            }

            TextSwitch {
                id: digitsSwitch
                text: qsTr("Digits")
                checked: true
            }

            TextSwitch {
                id: symbolsSwitch
                text: qsTr("Symbols")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Generate password")
                enabled: lowerSwitch.checked || upperSwitch.checked || digitsSwitch.checked
                         || symbolsSwitch.checked
                onClicked: {
                    var generated = vault.generatePassword(lengthSlider.value, lowerSwitch.checked,
                                                           upperSwitch.checked, digitsSwitch.checked,
                                                           symbolsSwitch.checked)
                    if (generated.length > 0)
                        passwordField.text = generated
                }
            }
        }

        VerticalScrollDecorator {}
    }
}
