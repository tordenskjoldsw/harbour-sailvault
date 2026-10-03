import QtQuick 2.0
import Sailfish.Silica 1.0

// A paragraph of plain text within the page margins.
Label {
    x: Theme.horizontalPageMargin
    width: parent.width - 2 * Theme.horizontalPageMargin
    textFormat: Text.PlainText
    wrapMode: Text.Wrap
}
