#include <QGuiApplication>
#include <QQmlContext>
#include <QQuickView>
#include <QScopedPointer>
#include <QString>
#include <qqml.h>

#include <cstdio>
#include <memory>

#include <sailfishapp.h>

#include "boottime.h"
#include "entrylistmodel.h"
#include "importer.h"
#include "vault.h"

namespace {

void printFirstFrameTimestamp(QQuickWindow *window)
{
    auto connection = std::make_shared<QMetaObject::Connection>();
    *connection = QObject::connect(window, &QQuickWindow::frameSwapped, [connection] {
        QObject::disconnect(*connection);
        std::printf("first-frame-boottime-ms=%lld\n", bootTimeMs());
        std::fflush(stdout);
    });
}

} // namespace

int main(int argc, char *argv[])
{
    QScopedPointer<QGuiApplication> app(SailfishApp::application(argc, argv));
    // Must match the Sailjail OrganizationName and ApplicationName, which
    // decide the writable data and config directories.
    QCoreApplication::setOrganizationName(QStringLiteral("de.tordenskjold"));
    QCoreApplication::setApplicationName(QStringLiteral("sailvault"));

    qmlRegisterType<EntryListModel>("harbour.sailvault", 1, 0, "EntryListModel");
    qmlRegisterUncreatableType<Vault>("harbour.sailvault", 1, 0, "Vault",
                                      QStringLiteral("Use the vault context property"));
    qmlRegisterUncreatableType<Importer>("harbour.sailvault", 1, 0, "Importer",
                                         QStringLiteral("Use the importer context property"));

    Vault vault;
    Importer importer(&vault);
    QScopedPointer<QQuickView> view(SailfishApp::createView());
    view->rootContext()->setContextProperty(QStringLiteral("vault"), &vault);
    view->rootContext()->setContextProperty(QStringLiteral("importer"), &importer);
    view->rootContext()->setContextProperty(QStringLiteral("appVersion"),
                                            QStringLiteral(APP_VERSION));

    if (app->arguments().contains(QStringLiteral("--startup-trace")))
        printFirstFrameTimestamp(view.data());

    view->setSource(SailfishApp::pathToMainQml());
    view->show();

    return app->exec();
}
