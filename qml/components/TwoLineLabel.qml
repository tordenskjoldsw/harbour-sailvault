import QtQuick 2.0
import Sailfish.Silica 1.0

// The content of a list row: an optional icon, a title and a smaller second
// line, both plain text.
Item {
    id: row

    property string iconSource
    property string title
    property string description
    property bool highlighted

    Image {
        id: icon

        x: Theme.horizontalPageMargin
        anchors.verticalCenter: parent.verticalCenter
        visible: row.iconSource.length > 0
        source: visible ? row.iconSource + (row.highlighted ? "?" + Theme.highlightColor : "") : ""
    }

    Column {
        anchors {
            left: icon.visible ? icon.right : parent.left
            leftMargin: icon.visible ? Theme.paddingMedium : Theme.horizontalPageMargin
            right: parent.right
            rightMargin: Theme.horizontalPageMargin
            verticalCenter: parent.verticalCenter
        }

        Label {
            width: parent.width
            textFormat: Text.PlainText
            truncationMode: TruncationMode.Fade
            color: row.highlighted ? Theme.highlightColor : Theme.primaryColor
            text: row.title
        }

        Label {
            width: parent.width
            visible: text.length > 0
            textFormat: Text.PlainText
            truncationMode: TruncationMode.Fade
            font.pixelSize: Theme.fontSizeExtraSmall
            color: row.highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
            text: row.description
        }
    }
}
