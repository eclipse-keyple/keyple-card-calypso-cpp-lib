/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CalypsoExtensionService.h"

/* Calypsonet Terminal Calypso */
#include "CardTransactionManagerAdapter.h"

/* Calypsonet Terminal Card */
#include "CardApiProperties.h"

/* Calypsonet Terminal Reader */
#include "ReaderApiProperties.h"

/* Keyple Card Calypso */
#include "CalypsoSamResourceProfileExtensionAdapter.h"
#include "CardSecuritySettingAdapter.h"

/* Keyple Core Common */
#include "CommonApiProperties.h"

/* Keyple Core Util */
#include "KeypleAssert.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::reader;
using namespace keyple::core::common;
using namespace keyple::core::util;

const std::string CalypsoExtensionService::PRODUCT_TYPE = "productType";
std::shared_ptr<CalypsoExtensionService> CalypsoExtensionService::mInstance;

CalypsoExtensionService::CalypsoExtensionService() {}

std::shared_ptr<CalypsoExtensionService> CalypsoExtensionService::getInstance()
{
    if (mInstance == nullptr) {
        mInstance = std::shared_ptr<CalypsoExtensionService>(new CalypsoExtensionService());
    }

    return mInstance;
}

const std::string& CalypsoExtensionService::getReaderApiVersion() const
{
    return ReaderApiProperties_VERSION;
}

const std::string& CalypsoExtensionService::getCardApiVersion() const
{
    return CardApiProperties_VERSION;
}

const std::string& CalypsoExtensionService::getCommonApiVersion() const
{
    return CommonApiProperties_VERSION;
}

std::shared_ptr<SearchCommandData> CalypsoExtensionService::createSearchCommandData() const
{
    return std::make_shared<SearchCommandDataAdapter>();
}

std::shared_ptr<SignatureComputationData> CalypsoExtensionService::createSignatureComputationData() 
    const 
{
    return std::make_shared<SignatureComputationDataAdapter>();
}

std::shared_ptr<SignatureVerificationData> 
    CalypsoExtensionService::createSignatureVerificationData() const 
{
    return std::make_shared<SignatureVerificationDataAdapter>();
}

std::shared_ptr<CalypsoCardSelection> CalypsoExtensionService::createCardSelection() const
{
    return std::make_shared<CalypsoCardSelectionAdapter>();
}

std::shared_ptr<CalypsoSamSelection> CalypsoExtensionService::createSamSelection() const
{
    return std::make_shared<CalypsoSamSelectionAdapter>();
}

std::shared_ptr<CardResourceProfileExtension>
    CalypsoExtensionService::createSamResourceProfileExtension(
        const std::shared_ptr<CalypsoSamSelection> calypsoSamSelection) const
{
    Assert::getInstance().notNull(calypsoSamSelection, "calypsoSamSelection");

    return std::make_shared<CalypsoSamResourceProfileExtensionAdapter>(calypsoSamSelection);
}

std::shared_ptr<CardSecuritySetting> CalypsoExtensionService::createCardSecuritySetting() const
{
    return std::make_shared<CardSecuritySettingAdapter>();
}

std::shared_ptr<CardTransactionManager> CalypsoExtensionService::createCardTransaction(
        std::shared_ptr<CardReader> cardReader,
        const std::shared_ptr<CalypsoCard> calypsoCard,
        const std::shared_ptr<CardSecuritySetting> cardSecuritySetting) const
{
    return createCardTransactionManagerAdapter(cardReader, calypsoCard, cardSecuritySetting, true);
}

std::shared_ptr<CardTransactionManager> 
    CalypsoExtensionService::createCardTransactionWithoutSecurity(
        std::shared_ptr<CardReader> cardReader,
        const std::shared_ptr<CalypsoCard> calypsoCard) const
{
    return createCardTransactionManagerAdapter(cardReader, calypsoCard, nullptr, false);
}

std::shared_ptr<CardTransactionManagerAdapter> 
    CalypsoExtensionService::createCardTransactionManagerAdapter(
        std::shared_ptr<CardReader> cardReader,
        const std::shared_ptr<CalypsoCard> calypsoCard,
        const std::shared_ptr<CardSecuritySetting> cardSecuritySetting,
        const bool isSecureMode) const
{
    Assert::getInstance().notNull(cardReader, "card reader")
                         .notNull(calypsoCard, "calypso card")
                         .notNull(cardSecuritySetting, "cardSecuritySetting");

    /*
     * C++: check args data *after* nullity has been ruled out. Calls order doesn't seem
     * respected by MSVC
     */
    Assert::getInstance().isTrue(calypsoCard->getProductType() != CalypsoCard::ProductType::UNKNOWN,
                                 "product type is known")
                         .isTrue(!isSecureMode || cardSecuritySetting != nullptr, 
                                 "security setting is not null");

    const auto proxy = std::dynamic_pointer_cast<ProxyReaderApi>(cardReader);
    if (!proxy) {
        throw IllegalArgumentException("The provided 'cardReader' must implement 'ProxyReaderApi'");
    }

    const auto calypso = std::dynamic_pointer_cast<CalypsoCardAdapter>(calypsoCard);
    if (!calypso) {
        throw IllegalArgumentException("The provided 'calypsoCard' must be an instance of " \
                                       "'CalypsoCardAdapter'");
    }

    const setting = std::dynamic_point_cast<CardSecuritySettingAdapter>(cardSecuritySetting);
    if (isSecureMode && !setting) {
        throw IllegalArgumentException("The provided 'cardSecuritySetting' must be an instance of" \
                                       " 'CardSecuritySettingAdapter'");
    }

    return std::make_shared<CardTransactionManagerAdapter>(cardReader, 
                                                           calypsoCard, 
                                                           cardSecuritySetting);
}

std::shared_ptr<CardTransactionManager>
    CalypsoExtensionService::createCardTransactionWithoutSecurity(
        std::shared_ptr<CardReader> reader, const std::shared_ptr<CalypsoCard> calypsoCard)
{
    Assert::getInstance().notNull(reader, "reader")
                         .notNull(calypsoCard, "calypsoCard");

    /*
     * C++: check args data *after* nullity has been ruled out. Calls order doesn't seem
     * respected by MSVC
     */
    Assert::getInstance().isTrue(calypsoCard->getProductType() != CalypsoCard::ProductType::UNKNOWN,
                                 PRODUCT_TYPE);

    return std::make_shared<CardTransactionManagerAdapter>(reader, calypsoCard);
}

std::shared_ptr<SamSecuritySetting> CalypsoExtensionService::createSamSecuritySetting() const 
{
    return std::make_shared<SamSecuritySettingAdapter>();
}

std::shared_ptr<SamTransactionManager> CalypsoExtensionService::createSamTransaction(
    std::shared_ptr<CardReader> samReader, 
    const std::shared_ptr<CalypsoSam> calypsoSam, 
    const std::shared_ptr<SamSecuritySetting> samSecuritySetting) const 
{
    return createSamTransactionManagerAdapter(samReader, calypsoSam, samSecuritySetting, true);
}

std::shared_ptr<SamTransactionManager> CalypsoExtensionService::createSamTransactionWithoutSecurity(
    std::shared_ptr<CardReader> samReader, 
    const std::shared_ptr<CalypsoSam> calypsoSam) const 
{
    return createSamTransactionManagerAdapter(samReader, calypsoSam, nullptr, false);
}

std::shared_ptr<SamTransactionManagerAdapter> 
    CalypsoExtensionService::createSamTransactionManagerAdapter(
        std::shared_ptr<CardReader> samReader,
        const std::shared_ptr<CalypsoSam> calypsoSam,
        const std::shared_ptr<SamSecuritySetting> samSecuritySetting,
        const bool isSecureMode) const 
{
    Assert.getInstance().notNull(samReader, "sam reader")
                        .notNull(calypsoSam, "calypso SAM")
                        .notNull(calypsoSam->getProductType(), "product type");
    
    Assert.getInstance().isTrue(calypsoSam->getProductType() != CalypsoSam::ProductType::UNKNOWN, 
                                "product type is known")
                        .isTrue(!isSecureMode || samSecuritySetting != nullptr, 
                                "security setting is not null");

    const auto proxy = std::dynamic_pointer_cast<ProxyReaderApi>(samReader);
    if (!proxy) {
        throw IllegalArgumentException("The provided 'samReader' must implement 'ProxyReaderApi'");
    }

    const auto sam = std::dynamic_pointer_cast<CalypsoSamAdapter>(calypsoSam);
    if (!sam) {
        throw IllegalArgumentException("The provided 'calypsoSam' must be an instance of " \
                                       "'CalypsoSamAdapter'");
    }

    const auto setting = std::dynamic_pointer_cast<SamSecuritySettingAdapter>(samSecuritySetting);
    if (isSecureMode && !setting) {
        throw IllegalArgumentException("The provided 'samSecuritySetting' must be an instance of " \
                                       "'SamSecuritySettingAdapter'");
    }

    return std::make_shared<SamTransactionManagerAdapter>(samReader, 
                                                          calypsoSam, 
                                                          samSecuritySetting);
  }

}
}
}
