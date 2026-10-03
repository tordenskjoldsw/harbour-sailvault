#include <QGuiApplication>
#include <QQmlContext>
#include <QQuickView>
#include <QScopedPointer>
#include <QString>
#include <qqml.h>

#include <cstdio>
#include <ctime>
#include <memory>

#include <sailfishapp.h>

#include "entrylistmodel.h"
#include "sailvault_core.h"
#include "vault.h"

namespace {

// CLOCK_BOOTTIME matches /proc/uptime, which the measurement script reads on the device.
long long bootTimeMs()
{
    timespec now;
    clock_gettime(CLOCK_BOOTTIME, &now);
    return static_cast<long long>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

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

    Vault vault;
    QScopedPointer<QQuickView> view(SailfishApp::createView());
    view->rootContext()->setContextProperty(QStringLiteral("vault"), &vault);
    view->rootContext()->setContextProperty(
        QStringLiteral("coreVersion"),
        QString::fromUtf8(sailvault_core_version()));

    if (app->arguments().contains(QStringLiteral("--startup-trace")))
        printFirstFrameTimestamp(view.data());

    view->setSource(SailfishApp::pathToMainQml());
    view->show();

    return app->exec();
}
