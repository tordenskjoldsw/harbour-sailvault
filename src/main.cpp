#include <QGuiApplication>
#include <QQmlContext>
#include <QQuickView>
#include <QScopedPointer>
#include <QString>
#include <qqml.h>

#include <sailfishapp.h>

#include "sailvault_core.h"
#include "systemkeystore.h"

int main(int argc, char *argv[])
{
    QScopedPointer<QGuiApplication> app(SailfishApp::application(argc, argv));

    qmlRegisterType<SystemKeyStore>("harbour.sailvault", 1, 0, "SystemKeyStore");

    QScopedPointer<QQuickView> view(SailfishApp::createView());
    view->rootContext()->setContextProperty(
        QStringLiteral("coreVersion"),
        QString::fromUtf8(sailvault_core_version()));

    view->setSource(SailfishApp::pathToMainQml());
    view->show();

    return app->exec();
}
