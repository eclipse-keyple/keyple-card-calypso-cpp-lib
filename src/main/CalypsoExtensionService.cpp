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
        std::shared_ptr<CardReader> reader,
        const std::shared_ptr<CalypsoCard> calypsoCard,
        const std::shared_ptr<CardSecuritySetting> cardSecuritySetting)
{

    Assert::getInstance().notNull(reader, "reader")
                         .notNull(calypsoCard, "calypsoCard")
                         .isTrue(calypsoCard->getProductType() !=
                                 CalypsoCard::ProductType::UNKNOWN, PRODUCT_TYPE)
                         .notNull(cardSecuritySetting, "cardSecuritySetting");

    return std::make_shared<CardTransactionManagerAdapter>(reader,
                                                           calypsoCard,
                                                           cardSecuritySetting);
}

std::shared_ptr<CardTransactionManager>
    CalypsoExtensionService::createCardTransactionWithoutSecurity(
        std::shared_ptr<CardReader> reader, const std::shared_ptr<CalypsoCard> calypsoCard)
{
    Assert::getInstance().notNull(reader, "reader")
                         .notNull(calypsoCard, "calypsoCard")
                         .isTrue(calypsoCard->getProductType() != CalypsoCard::ProductType::UNKNOWN,
                                 PRODUCT_TYPE);

    return std::make_shared<CardTransactionManagerAdapter>(reader, calypsoCard);
}


}
}
}
