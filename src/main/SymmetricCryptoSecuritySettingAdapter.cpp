/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/SymmetricCryptoSecuritySettingAdapter.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/core/util/cpp/Arrays.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Arrays;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

const std::string SymmetricCryptoSecuritySettingAdapter::WRITE_ACCESS_LEVEL
    = "writeAccessLevel";

SymmetricCryptoSecuritySettingAdapter::SymmetricCryptoSecuritySettingAdapter(
    std::shared_ptr<SymmetricCryptoCardTransactionManagerFactorySpi>
        cryptoCardTransactionManagerFactorySpi)
: mCryptoCardTransactionManagerFactorySpi(
      cryptoCardTransactionManagerFactorySpi)
{
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::enableMultipleSession()
{
    mIsMultipleSessionEnabled = true;

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::enableRatificationMechanism()
{
    mIsRatificationMechanismEnabled = true;

    return *this;
}
SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::enablePinPlainTransmission()
{
    mIsPinPlainTransmissionEnabled = true;

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::enableSvLoadAndDebitLog()
{
    mIsSvLoadAndDebitLogEnabled = true;

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::authorizeSvNegativeBalance()
{
    mIsSvNegativeBalanceAuthorized = true;

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::disableReadOnSessionOpening()
{
    mIsReadOnSessionOpeningDisabled = true;

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::assignKif(
    WriteAccessLevel writeAccessLevel, std::uint8_t kvc, std::uint8_t kif)
{
    /*
     * C++ operator[] auto inserts default value if not present.
     * Don't need the "if (map == null) Java section.
     */
    mKifMap[writeAccessLevel][kvc] = kif;

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::assignDefaultKif(
    WriteAccessLevel writeAccessLevel, std::uint8_t kif)
{
    mDefaultKifMap[writeAccessLevel] = kif;

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::assignDefaultKvc(
    WriteAccessLevel writeAccessLevel, std::uint8_t kvc)
{
    mDefaultKvcMap[writeAccessLevel] = kvc;

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::addAuthorizedSessionKey(
    std::uint8_t kif, std::uint8_t kvc)
{
    mAuthorizedSessionKeys.push_back(((kif << 8) & 0xff00) | (kvc & 0x00ff));

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::addAuthorizedSvKey(
    std::uint8_t kif, std::uint8_t kvc)
{
    mAuthorizedSvKeys.push_back(((kif << 8) & 0xff00) | (kvc & 0x00ff));

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::setPinVerificationCipheringKey(
    std::uint8_t kif, std::uint8_t kvc)
{
    mPinVerificationCipheringKif = std::make_shared<std::uint8_t>(kif);
    mPinVerificationCipheringKvc = std::make_shared<std::uint8_t>(kvc);

    return *this;
}

SymmetricCryptoSecuritySetting&
SymmetricCryptoSecuritySettingAdapter::setPinModificationCipheringKey(
    std::uint8_t kif, std::uint8_t kvc)
{
    mPinModificationCipheringKif = std::make_shared<std::uint8_t>(kif);
    mPinModificationCipheringKvc = std::make_shared<std::uint8_t>(kvc);

    return *this;
}

void
SymmetricCryptoSecuritySettingAdapter::initCryptoContextForNextTransaction()
{
    try {
        mCryptoCardTransactionManagerFactorySpi
            ->preInitTerminalSessionContext();

    } catch (const SymmetricCryptoException& e) {
        throw CryptoException(e.what(), e);

    } catch (const SymmetricCryptoIOException& e) {
        throw CryptoIOException(e.what(), e);
    }
}

bool
SymmetricCryptoSecuritySettingAdapter::isMultipleSessionEnabled() const
{
    return mIsMultipleSessionEnabled;
}

bool
SymmetricCryptoSecuritySettingAdapter::isRatificationMechanismEnabled() const
{
    return mIsRatificationMechanismEnabled;
}

bool
SymmetricCryptoSecuritySettingAdapter::isPinPlainTransmissionEnabled() const
{
    return mIsPinPlainTransmissionEnabled;
}

bool
SymmetricCryptoSecuritySettingAdapter::isSvLoadAndDebitLogEnabled() const
{
    return mIsSvLoadAndDebitLogEnabled;
}

bool
SymmetricCryptoSecuritySettingAdapter::isSvNegativeBalanceAuthorized() const
{
    return mIsSvNegativeBalanceAuthorized;
}

bool
SymmetricCryptoSecuritySettingAdapter::isReadOnSessionOpeningDisabled() const
{
    return mIsReadOnSessionOpeningDisabled;
}

std::unique_ptr<std::uint8_t>
SymmetricCryptoSecuritySettingAdapter::getKif(
    WriteAccessLevel writeAccessLevel, std::uint8_t kvc) const
{
    const auto it = mKifMap.find(writeAccessLevel);
    if (it != mKifMap.end()) {
        const auto _it = it->second.find(kvc);
        if (_it == it->second.end()) {
            return nullptr;
        }
        return std::unique_ptr<std::uint8_t>(new std::uint8_t(_it->second));
    } else {
        return nullptr;
    }
}

std::shared_ptr<std::uint8_t>
SymmetricCryptoSecuritySettingAdapter::getDefaultKif(
    WriteAccessLevel writeAccessLevel) const
{
    const auto it = mDefaultKifMap.find(writeAccessLevel);
    if (it != mDefaultKifMap.end()) {
        return std::make_shared<std::uint8_t>(it->second);
    } else {
        return nullptr;
    }
}

std::shared_ptr<std::uint8_t>
SymmetricCryptoSecuritySettingAdapter::getDefaultKvc(
    WriteAccessLevel writeAccessLevel) const
{
    const auto it = mDefaultKvcMap.find(writeAccessLevel);
    if (it != mDefaultKvcMap.end()) {
        return std::make_shared<std::uint8_t>(it->second);
    } else {
        return nullptr;
    }
}

bool
SymmetricCryptoSecuritySettingAdapter::isSessionKeyAuthorized(
    std::shared_ptr<std::uint8_t> kif, std::shared_ptr<std::uint8_t> kvc) const
{
    if (kif == nullptr || kvc == nullptr) {
        return false;
    }

    if (mAuthorizedSessionKeys.empty()) {
        return true;
    }

    return Arrays::contains(
        mAuthorizedSessionKeys, ((*kif << 8) & 0xff00) | (*kvc & 0x00ff));
}

bool
SymmetricCryptoSecuritySettingAdapter::isSvKeyAuthorized(
    std::shared_ptr<std::uint8_t> kif, std::shared_ptr<std::uint8_t> kvc) const
{
    if (kif == nullptr || kvc == nullptr) {
        return false;
    }

    if (mAuthorizedSvKeys.empty()) {
        return true;
    }

    return Arrays::contains(
        mAuthorizedSvKeys, ((*kif << 8) & 0xff00) | (*kvc & 0x00ff));
}

std::shared_ptr<std::uint8_t>
SymmetricCryptoSecuritySettingAdapter::getPinVerificationCipheringKif() const
{
    return mPinVerificationCipheringKif;
}

std::shared_ptr<std::uint8_t>
SymmetricCryptoSecuritySettingAdapter::getPinVerificationCipheringKvc() const
{
    return mPinVerificationCipheringKvc;
}

std::shared_ptr<std::uint8_t>
SymmetricCryptoSecuritySettingAdapter::getPinModificationCipheringKif() const
{
    return mPinModificationCipheringKif;
}

std::shared_ptr<std::uint8_t>
SymmetricCryptoSecuritySettingAdapter::getPinModificationCipheringKvc() const
{
    return mPinModificationCipheringKvc;
}

std::shared_ptr<SymmetricCryptoCardTransactionManagerFactorySpi>
SymmetricCryptoSecuritySettingAdapter ::
    getCryptoCardTransactionManagerFactorySpi() const
{
    return mCryptoCardTransactionManagerFactorySpi;
}

const std::map<WriteAccessLevel, std::map<std::uint8_t, std::uint8_t>>&
SymmetricCryptoSecuritySettingAdapter::getKifMap() const
{
    return mKifMap;
}

const std::map<WriteAccessLevel, std::uint8_t>&
SymmetricCryptoSecuritySettingAdapter::getDefaultKifMap() const
{
    return mDefaultKifMap;
}

const std::map<WriteAccessLevel, std::uint8_t>&
SymmetricCryptoSecuritySettingAdapter::getDefaultKvcMap() const
{
    return mDefaultKvcMap;
}

const std::vector<int>&
SymmetricCryptoSecuritySettingAdapter::getAuthorizedSessionKeys() const
{
    return mAuthorizedSessionKeys;
}

const std::vector<int>&
SymmetricCryptoSecuritySettingAdapter::getAuthorizedSvKeys() const
{
    return mAuthorizedSvKeys;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
