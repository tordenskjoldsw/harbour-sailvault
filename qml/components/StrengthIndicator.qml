import QtQuick 2.0
import Sailfish.Silica 1.0
import harbour.sailvault 1.0

// Rates a password below its field: a bar, the quality in words and the
// estimated bits. The rating arrives a moment after the text; until then
// rated is false and the last rating stays on screen.
Column {
    id: indicator

    property alias password: strength.password
    readonly property alias bits: strength.bits
    readonly property alias quality: strength.quality
    readonly property alias rated: strength.current
    readonly property bool poor: quality === PasswordStrength.Poor
    readonly property color barColor: poor ? Theme.errorColor : Theme.highlightColor

    function qualityText(quality) {
        switch (quality) {
        case PasswordStrength.Poor: return qsTr("Poor")
        case PasswordStrength.Weak: return qsTr("Weak")
        case PasswordStrength.Good: return qsTr("Good")
        default: return qsTr("Excellent")
        }
    }

    x: Theme.horizontalPageMargin
    width: parent.width - 2 * Theme.horizontalPageMargin
    spacing: Theme.paddingSmall
    visible: password.length > 0

    PasswordStrength {
        id: strength
    }

    Rectangle {
        width: parent.width
        height: Theme.paddingSmall
        radius: height / 2
        color: Theme.rgba(indicator.barColor, Theme.opacityFaint)

        Rectangle {
            width: parent.width * Math.min(indicator.bits / strength.excellentBits, 1)
            height: parent.height
            radius: parent.radius
            color: indicator.barColor
        }
    }

    Label {
        width: parent.width
        wrapMode: Text.Wrap
        font.pixelSize: Theme.fontSizeSmall
        color: indicator.poor ? Theme.errorColor : Theme.secondaryHighlightColor
        //: Password quality and estimated entropy, e.g. "Weak (52 bits)"
        text: qsTr("%1 (%2 bits)").arg(indicator.qualityText(indicator.quality))
                                  .arg(Math.floor(indicator.bits))
    }
}
