#include "passwordstrength.h"

#include <QByteArray>

#include <zxcvbn.h>

#include "corebridge.h"

namespace {

// As KeePassXC: the estimator rates the first characters, and each further
// one counts with their average.
const int EstimatedCharacters = 256;

const double WeakBits = 40;
const double GoodBits = 75;
const double ExcellentBits = 100;

} // namespace

PasswordStrength::PasswordStrength(QObject *parent)
    : QObject(parent)
{
}

double PasswordStrength::excellentBits()
{
    return ExcellentBits;
}

double PasswordStrength::entropyBits(const QString &password)
{
    if (password.isEmpty())
        return 0;
    QByteArray utf8 = password.leftRef(EstimatedCharacters).toUtf8();
    double bits = ZxcvbnMatch(utf8.constData(), nullptr, nullptr);
    secureWipe(utf8);
    const int furtherCharacters = password.size() - EstimatedCharacters;
    if (furtherCharacters > 0)
        bits += bits / EstimatedCharacters * furtherCharacters;
    return bits;
}

PasswordStrength::Quality PasswordStrength::quality(double entropyBits)
{
    if (entropyBits < WeakBits)
        return Poor;
    if (entropyBits < GoodBits)
        return Weak;
    if (entropyBits < ExcellentBits)
        return Good;
    return Excellent;
}
