#include <QGuiApplication>
#include <QQmlContext>
#include <QQuickView>
#include <QScopedPointer>
#include <QString>

#include <cstdio>
#include <ctime>
#include <memory>

#include <sailfishapp.h>

#include "sailvault_core.h"

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

    QScopedPointer<QQuickView> view(SailfishApp::createView());
    view->rootContext()->setContextProperty(
        QStringLiteral("coreVersion"),
        QString::fromUtf8(sailvault_core_version()));

    if (app->arguments().contains(QStringLiteral("--startup-trace")))
        printFirstFrameTimestamp(view.data());

    view->setSource(SailfishApp::pathToMainQml());
    view->show();

    return app->exec();
}
