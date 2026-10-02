#include <QGuiApplication>
#include <QQmlContext>
#include <QQuickView>
#include <QScopedPointer>
#include <QString>

#include <sailfishapp.h>

#include "sailvault_core.h"

int main(int argc, char *argv[])
{
    QScopedPointer<QGuiApplication> app(SailfishApp::application(argc, argv));
    QScopedPointer<QQuickView> view(SailfishApp::createView());

    view->rootContext()->setContextProperty(
        QStringLiteral("coreVersion"),
        QString::fromUtf8(sailvault_core_version()));

    view->setSource(SailfishApp::pathToMainQml());
    view->show();

    return app->exec();
}
