#ifndef PASSWORDSTRENGTH_H
#define PASSWORDSTRENGTH_H

#include <QObject>
#include <QRunnable>
#include <QString>

#include "sailvault_core.h"

// Estimates how hard a password is to guess, with the estimator and the
// quality levels of KeePassXC, so both rate a password the same. The core
// bounds what the estimator gets and holds the levels.
//
// The estimate runs on a pool thread: the estimator needs up to two seconds
// for some passwords of 100 characters, which must not block the UI. While
// current is false, bits and quality still belong to an earlier password.
class PasswordStrength : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString password READ password WRITE setPassword NOTIFY passwordChanged)
    Q_PROPERTY(double bits READ bits NOTIFY ratingChanged)
    Q_PROPERTY(Quality quality READ quality NOTIFY ratingChanged)
    Q_PROPERTY(bool current READ current NOTIFY currentChanged)
    // From this many bits on a password is Excellent; the full scale of a
    // strength bar.
    Q_PROPERTY(double excellentBits READ excellentBits CONSTANT)

public:
    enum Quality {
        Poor = SV_QUALITY_POOR,
        Weak = SV_QUALITY_WEAK,
        Good = SV_QUALITY_GOOD,
        Excellent = SV_QUALITY_EXCELLENT
    };
    Q_ENUM(Quality)

    explicit PasswordStrength(QObject *parent = nullptr);

    QString password() const;
    void setPassword(const QString &password);
    double bits() const;
    Quality quality() const;
    bool current() const;

    static double excellentBits();
    static double entropyBits(const QString &password);
    static Quality qualityOf(double entropyBits);

signals:
    void passwordChanged();
    void ratingChanged();
    void currentChanged();

private slots:
    void estimated(const QString &password, double bits);

private:
    void startEstimate();
    void setRating(double bits);
    void setCurrent(bool current);

    QString m_password;
    double m_bits = 0;
    bool m_current = true;
    bool m_estimating = false;
};

// One estimate on a pool thread. It reports through a signal, so a result
// for a PasswordStrength that is gone by then is dropped.
class EstimateTask : public QObject, public QRunnable
{
    Q_OBJECT

public:
    explicit EstimateTask(const QString &password);

    void run() override;

signals:
    void estimated(const QString &password, double bits);

private:
    QString m_password;
};

#endif // PASSWORDSTRENGTH_H
