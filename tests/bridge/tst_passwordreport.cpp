// The password report through the real Vault: the core's walk on the wiped
// stack with the real estimator, and how a lock treats a report that is
// still running (security review 2026-11, condition C3).
#include <QElapsedTimer>
#include <QGuiApplication>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtTest>

#include "estimator.h"
#include "vault.h"

namespace {

const int UnlockTimeoutMs = 120000;

// Neighbours on the number pad that change direction at every step: the
// estimator's slow case, about a second per password on a desktop.
QString slowPassword()
{
    return QStringLiteral("12").repeated(50);
}

} // namespace

class PasswordReportTest : public QObject
{
    Q_OBJECT

private slots:
    void init();
    void cleanup();
    void listsWeakAndSharedPasswords();
    void refusesEditsWhileItRuns();
    void aLockCancelsARunningReport();

private:
    void add(const QString &title, const QString &password);

    QScopedPointer<QTemporaryDir> m_home;
    QScopedPointer<Vault> m_vault;
};

void PasswordReportTest::init()
{
    m_home.reset(new QTemporaryDir);
    QVERIFY(m_home->isValid());
    qputenv("XDG_DATA_HOME", m_home->path().toLocal8Bit() + "/data");
    qputenv("XDG_CONFIG_HOME", m_home->path().toLocal8Bit() + "/config");
    m_vault.reset(new Vault);
    m_vault->createDatabase(QStringLiteral("Test"), QStringLiteral("made-up master password"),
                            Vault::KdfStandard);
    QTRY_COMPARE_WITH_TIMEOUT(m_vault->state(), Vault::Unlocked, UnlockTimeoutMs);
}

void PasswordReportTest::cleanup()
{
    m_vault.reset();
    m_home.reset();
}

void PasswordReportTest::add(const QString &title, const QString &password)
{
    QVariantMap fields;
    fields.insert(QStringLiteral("Title"), title);
    fields.insert(QStringLiteral("Password"), password);
    QVERIFY(m_vault->addEntry(QString(), fields));
    QTRY_VERIFY_WITH_TIMEOUT(!m_vault->saving(), UnlockTimeoutMs);
}

void PasswordReportTest::listsWeakAndSharedPasswords()
{
    add(QStringLiteral("Pin"), QStringLiteral("pin1"));
    add(QStringLiteral("Strong"), QStringLiteral("Xk9#mQ2$vL7!pR4zWq8&nB3"));
    add(QStringLiteral("Twin one"), QStringLiteral("7f3a9c1e5b2d8046af19c37e"));
    add(QStringLiteral("Twin two"), QStringLiteral("7f3a9c1e5b2d8046af19c37e"));
    add(QStringLiteral("Empty"), QString());

    QSignalSpy finished(m_vault.data(), &Vault::passwordReportFinished);
    QSignalSpy failed(m_vault.data(), &Vault::passwordReportFailed);
    QVERIFY(m_vault->startPasswordReport());
    QVERIFY(m_vault->reporting());
    QVERIFY(finished.wait(UnlockTimeoutMs));
    QVERIFY(!m_vault->reporting());
    QCOMPARE(failed.count(), 0);

    const QVariantList entries = finished.first().at(0).toList();
    QCOMPARE(finished.first().at(1).toInt(), 4);
    QCOMPARE(entries.size(), 3);

    const QVariantMap pin = entries.at(0).toMap();
    QCOMPARE(pin.value(QStringLiteral("title")).toString(), QStringLiteral("Pin"));
    QCOMPARE(pin.value(QStringLiteral("quality")).toInt(), int(SV_QUALITY_POOR));
    QCOMPARE(pin.value(QStringLiteral("sharedWith")).toInt(), 0);
    QCOMPARE(pin.value(QStringLiteral("id")).toString().size(), 32);
    // What the estimator itself says about it.
    QCOMPARE(pin.value(QStringLiteral("bits")).toDouble(), sv_estimate("pin1"));

    for (int index = 1; index < 3; ++index) {
        const QVariantMap twin = entries.at(index).toMap();
        QVERIFY(twin.value(QStringLiteral("title")).toString().startsWith(QStringLiteral("Twin")));
        QCOMPARE(twin.value(QStringLiteral("quality")).toInt(), int(SV_QUALITY_EXCELLENT));
        QCOMPARE(twin.value(QStringLiteral("sharedWith")).toInt(), 1);
    }
}

void PasswordReportTest::refusesEditsWhileItRuns()
{
    add(QStringLiteral("Slow"), slowPassword());

    QSignalSpy finished(m_vault.data(), &Vault::passwordReportFinished);
    QVERIFY(m_vault->startPasswordReport());
    QVERIFY(!m_vault->startPasswordReport());
    QVariantMap fields;
    fields.insert(QStringLiteral("Title"), QStringLiteral("Too early"));
    QVERIFY(!m_vault->addEntry(QString(), fields));
    QVERIFY(finished.wait(UnlockTimeoutMs));
    QVERIFY(m_vault->addEntry(QString(), fields));
    QTRY_VERIFY_WITH_TIMEOUT(!m_vault->saving(), UnlockTimeoutMs);
}

void PasswordReportTest::aLockCancelsARunningReport()
{
    const int entries = 8;
    for (int index = 0; index < entries; ++index)
        add(QStringLiteral("Slow %1").arg(index), slowPassword());

    QElapsedTimer timer;
    timer.start();
    sv_estimate(slowPassword().toLatin1().constData());
    const qint64 oneEstimateMs = timer.elapsed();
    // The test needs a report that is still running when the lock comes.
    QVERIFY2(oneEstimateMs >= 200, "the slow password is not slow here");

    QSignalSpy finished(m_vault.data(), &Vault::passwordReportFinished);
    QSignalSpy failed(m_vault.data(), &Vault::passwordReportFailed);
    QVERIFY(m_vault->startPasswordReport());
    QTest::qWait(int(oneEstimateMs / 2));
    QVERIFY(m_vault->reporting());

    timer.restart();
    m_vault->lock();
    // The task still reads the database, so the lock waits for it.
    QCOMPARE(m_vault->state(), Vault::Unlocked);
    QTRY_COMPARE_WITH_TIMEOUT(m_vault->state(), Vault::Locked, UnlockTimeoutMs);
    const qint64 waitedMs = timer.elapsed();

    // The report stopped at its next entry: the lock waited for the one
    // estimate that was running, not for the other seven.
    QVERIFY2(waitedMs < 2 * oneEstimateMs,
             qPrintable(QStringLiteral("the lock waited %1 ms, one estimate takes %2 ms")
                            .arg(waitedMs).arg(oneEstimateMs)));
    QVERIFY(!m_vault->reporting());
    QCOMPARE(finished.count(), 0);
    QCOMPARE(failed.count(), 0);
    QVERIFY(!m_vault->startPasswordReport());
    qInfo("one estimate %lld ms, the full report would take about %lld ms, the lock waited %lld ms",
          oneEstimateMs, oneEstimateMs * entries, waitedMs);
}

int main(int argc, char *argv[])
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QGuiApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("de.tordenskjold"));
    QCoreApplication::setApplicationName(QStringLiteral("sailvault-tests"));
    PasswordReportTest test;
    return QTest::qExec(&test, argc, argv);
}

#include "tst_passwordreport.moc"
