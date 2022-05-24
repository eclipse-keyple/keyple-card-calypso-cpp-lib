/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CardSecuritySettingAdapter.h"

/* Keyple Core Util */
#include "Arrays.h"
#include "KeypleAssert.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

using ProductType = CalypsoSam::ProductType;

const std::string CardSecuritySettingAdapter::WRITE_ACCESS_LEVEL = "writeAccessLevel";

CardSecuritySettingAdapter::CardSecuritySettingAdapter() {}

CardSecuritySetting& CardSecuritySettingAdapter::setSamResource(
    const std::shared_ptr<CardReader> samReader, const std::shared_ptr<CalypsoSam> calypsoSam)
{

    Assert::getInstance().notNull(samReader, "samReader")
                         .notNull(calypsoSam, "calypsoSam")
                         .isTrue(calypsoSam->getProductType() != ProductType::UNKNOWN, "productType");

    mSamReader = samReader;
    mCalypsoSam = calypsoSam;

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::enableMultipleSession()
{
    mIsMultipleSessionEnabled = true;

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::enableRatificationMechanism()
{
    mIsRatificationMechanismEnabled = true;

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::enablePinPlainTransmission()
{
    mIsPinPlainTransmissionEnabled = true;

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::enableTransactionAudit()
{
    mIsTransactionAuditEnabled = true;

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::enableSvLoadAndDebitLog()
{
    mIsSvLoadAndDebitLogEnabled = true;

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::authorizeSvNegativeBalance()
{
    mIsSvNegativeBalanceAuthorized = true;

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::assignKif(
    const WriteAccessLevel writeAccessLevel, const uint8_t kvc, const uint8_t kif)
{
    /* Map will be auto-created if not existing */
    mKifMap[writeAccessLevel].insert({kvc, kif});

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::assignDefaultKif(
    const WriteAccessLevel writeAccessLevel, const uint8_t kif)
{
    mDefaultKifMap.insert({writeAccessLevel, kif});

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::assignDefaultKvc(
    const WriteAccessLevel writeAccessLevel, const uint8_t kvc)
{
    mDefaultKvcMap.insert({writeAccessLevel, kvc});

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::addAuthorizedSessionKey(const uint8_t kif,
                                                                                const uint8_t kvc)
{
    mAuthorizedSessionKeys.push_back(((kif << 8) & 0xff00) | (kvc & 0x00ff));

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::addAuthorizedSvKey(const uint8_t kif,
                                                                           const uint8_t kvc)
{
    mAuthorizedSvKeys.push_back(((kif << 8) & 0xff00) | (kvc & 0x00ff));

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::setPinVerificationCipheringKey(
    const uint8_t kif, const uint8_t kvc)
{
    mPinVerificationCipheringKif = std::make_shared<uint8_t>(kif);
    mPinVerificationCipheringKvc = std::make_shared<uint8_t>(kvc);

    return *this;
}

CardSecuritySettingAdapter& CardSecuritySettingAdapter::setPinModificationCipheringKey(
    const uint8_t kif, const uint8_t kvc)
{
    mPinModificationCipheringKif = std::make_shared<uint8_t>(kif);
    mPinModificationCipheringKvc = std::make_shared<uint8_t>(kvc);

    return *this;
}

std::shared_ptr<CardReader> CardSecuritySettingAdapter::getSamReader() const
{
    return mSamReader;
}

std::shared_ptr<CalypsoSam> CardSecuritySettingAdapter::getCalypsoSam() const
{
    return mCalypsoSam;
}

bool CardSecuritySettingAdapter::isMultipleSessionEnabled() const
{
    return mIsMultipleSessionEnabled;
}

bool CardSecuritySettingAdapter::isRatificationMechanismEnabled() const
{
    return mIsRatificationMechanismEnabled;
}

bool CardSecuritySettingAdapter::isPinPlainTransmissionEnabled() const
{
    return mIsPinPlainTransmissionEnabled;
}

bool CardSecuritySettingAdapter::isTransactionAuditEnabled() const
{
    return mIsTransactionAuditEnabled;
}

bool CardSecuritySettingAdapter::isSvLoadAndDebitLogEnabled() const
{
    return mIsSvLoadAndDebitLogEnabled;
}

bool CardSecuritySettingAdapter::isSvNegativeBalanceAuthorized() const
{
    return mIsSvNegativeBalanceAuthorized;
}

const std::shared_ptr<uint8_t> CardSecuritySettingAdapter::getKif(
    const WriteAccessLevel writeAccessLevel, const uint8_t kvc) const
{
    const auto it = mKifMap.find(writeAccessLevel);
    if (it == mKifMap.end()) {
        return nullptr;
    } else {
        const auto itt = it->second.find(kvc);
        if (itt == it->second.end()) {
            return nullptr;
        } else {
            return std::make_shared<uint8_t>(itt->second);
        }
    }
}

const std::shared_ptr<uint8_t> CardSecuritySettingAdapter::getDefaultKif(
    const WriteAccessLevel writeAccessLevel) const
{
    const auto it = mDefaultKifMap.find(writeAccessLevel);
    if (it == mDefaultKifMap.end()) {
        return nullptr;
    } else {
        return std::make_shared<uint8_t>(it->second);
    }
}

const std::shared_ptr<uint8_t> CardSecuritySettingAdapter::getDefaultKvc(
    const WriteAccessLevel writeAccessLevel) const
{
    const auto it = mDefaultKvcMap.find(writeAccessLevel);
    if (it == mDefaultKvcMap.end()) {
        return nullptr;
    } else {
        return std::make_shared<uint8_t>(it->second);
    }
}

bool CardSecuritySettingAdapter::isSessionKeyAuthorized(const std::shared_ptr<uint8_t> kif,
                                                        const std::shared_ptr<uint8_t> kvc) const
{
    if (kif == nullptr || kvc == nullptr) {
        return false;
    }

    if (mAuthorizedSessionKeys.empty()) {
        return true;
    }

    return Arrays::contains(mAuthorizedSessionKeys,
                            ((*kif.get() << 8) & 0xff00) | (*kvc.get() & 0x00ff));
}

bool CardSecuritySettingAdapter::isSvKeyAuthorized(const std::shared_ptr<uint8_t> kif,
                                                   const std::shared_ptr<uint8_t> kvc) const
{
    if (kif == nullptr || kvc == nullptr) {
        return false;
    }

    if (mAuthorizedSvKeys.empty()) {
        return true;
    }

    return Arrays::contains(mAuthorizedSvKeys,
                            ((*kif.get() << 8) & 0xff00) | (*kvc.get() & 0x00ff));
}

const std::shared_ptr<uint8_t> CardSecuritySettingAdapter::getPinVerificationCipheringKif() const
{
    return mPinVerificationCipheringKif;
}

const std::shared_ptr<uint8_t> CardSecuritySettingAdapter::getPinVerificationCipheringKvc() const
{
    return mPinVerificationCipheringKvc;
}

const std::shared_ptr<uint8_t> CardSecuritySettingAdapter::getPinModificationCipheringKif() const
{
    return mPinModificationCipheringKif;
}

const std::shared_ptr<uint8_t> CardSecuritySettingAdapter::getPinModificationCipheringKvc() const
{
    return mPinModificationCipheringKvc;
}

}
}
}
