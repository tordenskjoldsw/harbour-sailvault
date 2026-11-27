#include "passwordstrength.h"

#include <QByteArray>
#include <QThreadPool>

#include "corebridge.h"
#include "estimator.h"

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
    return sv_password_excellent_bits();
}

double PasswordStrength::entropyBits(const QString &password)
{
    QByteArray utf8 = password.toUtf8();
    const double bits = sv_password_entropy(bytePointer(utf8), static_cast<size_t>(utf8.size()),
                                            sv_estimate);
    secureWipe(utf8);
    return bits > 0 ? bits : 0;
}

PasswordStrength::Quality PasswordStrength::qualityOf(double entropyBits)
{
    return static_cast<Quality>(sv_password_quality(entropyBits));
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
