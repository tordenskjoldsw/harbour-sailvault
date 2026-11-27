#ifndef PASSWORDSTRENGTH_H
#define PASSWORDSTRENGTH_H

#include <QObject>
#include <QString>

// Estimates how hard a password is to guess, with the estimator and the
// quality levels of KeePassXC, so both rate a password the same.
class PasswordStrength : public QObject
{
    Q_OBJECT
    // From this many bits on a password is Excellent; the full scale of a
    // strength bar.
    Q_PROPERTY(double excellentBits READ excellentBits CONSTANT)

public:
    enum Quality {
        Poor,
        Weak,
        Good,
        Excellent
    };
    Q_ENUM(Quality)

    explicit PasswordStrength(QObject *parent = nullptr);

    static double excellentBits();
    Q_INVOKABLE static double entropyBits(const QString &password);
    Q_INVOKABLE static PasswordStrength::Quality quality(double entropyBits);
};

#endif // PASSWORDSTRENGTH_H
