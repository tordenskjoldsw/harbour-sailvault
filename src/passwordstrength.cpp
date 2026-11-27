#include "passwordstrength.h"

#include <QByteArray>
#include <QThreadPool>

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

QString PasswordStrength::password() const
{
    return m_password;
}

void PasswordStrength::setPassword(const QString &password)
{
    if (password == m_password)
        return;
    m_password = password;
    emit passwordChanged();
    if (m_password.isEmpty()) {
        setRating(0);
        setCurrent(true);
        return;
    }
    setCurrent(false);
    // One estimate at a time; the one that is running starts the next for
    // the password that is set by then.
    if (!m_estimating)
        startEstimate();
}

double PasswordStrength::bits() const
{
    return m_bits;
}

PasswordStrength::Quality PasswordStrength::quality() const
{
    return qualityOf(m_bits);
}

bool PasswordStrength::current() const
{
    return m_current;
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

PasswordStrength::Quality PasswordStrength::qualityOf(double entropyBits)
{
    if (entropyBits < WeakBits)
        return Poor;
    if (entropyBits < GoodBits)
        return Weak;
    if (entropyBits < ExcellentBits)
        return Good;
    return Excellent;
}

void PasswordStrength::estimated(const QString &password, double bits)
{
    m_estimating = false;
    if (m_password.isEmpty())
        return;
    if (password != m_password) {
        startEstimate();
        return;
    }
    setRating(bits);
    setCurrent(true);
}

void PasswordStrength::startEstimate()
{
    m_estimating = true;
    auto *task = new EstimateTask(m_password);
    connect(task, &EstimateTask::estimated, this, &PasswordStrength::estimated,
            Qt::QueuedConnection);
    QThreadPool::globalInstance()->start(task);
}

void PasswordStrength::setRating(double bits)
{
    if (bits == m_bits)
        return;
    m_bits = bits;
    emit ratingChanged();
}

void PasswordStrength::setCurrent(bool current)
{
    if (current == m_current)
        return;
    m_current = current;
    emit currentChanged();
}

EstimateTask::EstimateTask(const QString &password)
    : m_password(password)
{
}

void EstimateTask::run()
{
    emit estimated(m_password, PasswordStrength::entropyBits(m_password));
}
