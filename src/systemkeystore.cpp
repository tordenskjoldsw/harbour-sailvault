#include "systemkeystore.h"

#include <QByteArray>

#include <Sailfish/Secrets/createcollectionrequest.h>
#include <Sailfish/Secrets/deletecollectionrequest.h>
#include <Sailfish/Secrets/secret.h>
#include <Sailfish/Secrets/storedsecretrequest.h>
#include <Sailfish/Secrets/storesecretrequest.h>

#include "sailvault_core.h"

using Sailfish::Secrets::CreateCollectionRequest;
using Sailfish::Secrets::DeleteCollectionRequest;
using Sailfish::Secrets::Request;
using Sailfish::Secrets::Result;
using Sailfish::Secrets::Secret;
using Sailfish::Secrets::SecretManager;
using Sailfish::Secrets::StoredSecretRequest;
using Sailfish::Secrets::StoreSecretRequest;

namespace {

const int TestKeyLength = 32;

QString collectionName(SystemKeyStore::LockMode mode)
{
    return mode == SystemKeyStore::VerifyLock ? QStringLiteral("sailvaultspikeverify")
                                              : QStringLiteral("sailvaultspikerelock");
}

SecretManager::DeviceLockUnlockSemantic unlockSemantic(SystemKeyStore::LockMode mode)
{
    return mode == SystemKeyStore::VerifyLock ? SecretManager::DeviceLockVerifyLock
                                              : SecretManager::DeviceLockRelock;
}

Secret::Identifier testKeyIdentifier(SystemKeyStore::LockMode mode)
{
    return Secret::Identifier(QStringLiteral("testkey"), collectionName(mode),
                              SecretManager::DefaultEncryptedStoragePluginName);
}

bool succeeded(const Result &result)
{
    return result.code() == Result::Succeeded;
}

} // namespace

SystemKeyStore::SystemKeyStore(QObject *parent)
    : QObject(parent)
{
}

bool SystemKeyStore::busy() const
{
    return m_busy;
}

QString SystemKeyStore::status() const
{
    return m_status;
}

void SystemKeyStore::storeTestKey(LockMode mode)
{
    if (!canStart())
        return;

    auto *request = new CreateCollectionRequest;
    request->setCollectionName(collectionName(mode));
    request->setCollectionLockType(CreateCollectionRequest::DeviceLock);
    request->setDeviceLockUnlockSemantic(unlockSemantic(mode));
    request->setAccessControlMode(SecretManager::OwnerOnlyMode);
    request->setUserInteractionMode(SecretManager::SystemInteraction);
    request->setStoragePluginName(SecretManager::DefaultEncryptedStoragePluginName);
    request->setEncryptionPluginName(SecretManager::DefaultEncryptedStoragePluginName);
    request->setAuthenticationPluginName(SecretManager::DefaultAuthenticationPluginName);

    run(request, tr("Creating collection"), [this, mode](const Result &result) {
        if (succeeded(result) || result.errorCode() == Result::CollectionAlreadyExistsError)
            storeGeneratedKey(mode);
        else
            finishWithError(tr("Create collection"), result);
    });
}

void SystemKeyStore::storeGeneratedKey(LockMode mode)
{
    QByteArray key(TestKeyLength, Qt::Uninitialized);
    if (!sailvault_fill_random(reinterpret_cast<uint8_t *>(key.data()),
                               static_cast<size_t>(key.size()))) {
        finish(tr("Random number generator unavailable"));
        return;
    }

    Secret secret(testKeyIdentifier(mode));
    secret.setData(key);

    auto *request = new StoreSecretRequest;
    request->setSecretStorageType(StoreSecretRequest::CollectionSecret);
    request->setUserInteractionMode(SecretManager::SystemInteraction);
    request->setSecret(secret);

    run(request, tr("Storing test key"), [this](const Result &result) {
        if (succeeded(result))
            finish(tr("Test key stored"));
        else
            finishWithError(tr("Store"), result);
    });
}

void SystemKeyStore::readTestKey(LockMode mode)
{
    if (!canStart())
        return;

    auto *request = new StoredSecretRequest;
    request->setIdentifier(testKeyIdentifier(mode));
    request->setUserInteractionMode(SecretManager::SystemInteraction);

    run(request, tr("Reading test key"), [this, request](const Result &result) {
        if (!succeeded(result)) {
            finishWithError(tr("Read"), result);
            return;
        }
        const int length = request->secret().data().size();
        finish(length == TestKeyLength ? tr("Test key read back (%1 bytes)").arg(length)
                                       : tr("Unexpected key length: %1 bytes").arg(length));
    });
}

void SystemKeyStore::deleteTestKey(LockMode mode)
{
    if (!canStart())
        return;

    auto *request = new DeleteCollectionRequest;
    request->setCollectionName(collectionName(mode));
    request->setStoragePluginName(SecretManager::DefaultEncryptedStoragePluginName);
    request->setUserInteractionMode(SecretManager::SystemInteraction);

    run(request, tr("Deleting test key"), [this](const Result &result) {
        if (succeeded(result))
            finish(tr("Test key deleted"));
        else
            finishWithError(tr("Delete"), result);
    });
}

bool SystemKeyStore::canStart()
{
    if (m_busy)
        return false;
    if (!m_manager.isInitialized()) {
        setStatus(tr("Secrets service not ready"));
        return false;
    }
    return true;
}

void SystemKeyStore::run(Request *request, const QString &activity,
                         std::function<void(const Result &)> onFinished)
{
    // The previous request may still be emitting, so it must be deleted later.
    m_request.reset(request);
    request->setManager(&m_manager);
    connect(request, &Request::statusChanged, this, [request, onFinished] {
        if (request->status() == Request::Finished)
            onFinished(request->result());
    });

    setStatus(activity);
    setBusy(true);
    request->startRequest();
}

void SystemKeyStore::finish(const QString &status)
{
    m_request.reset();
    setStatus(status);
    setBusy(false);
}

void SystemKeyStore::finishWithError(const QString &operation, const Result &result)
{
    finish(tr("%1 failed (error %2): %3")
               .arg(operation, QString::number(result.errorCode()), result.errorMessage()));
}

void SystemKeyStore::setBusy(bool busy)
{
    if (m_busy == busy)
        return;
    m_busy = busy;
    emit busyChanged();
}

void SystemKeyStore::setStatus(const QString &status)
{
    if (m_status == status)
        return;
    m_status = status;
    emit statusChanged();
}
