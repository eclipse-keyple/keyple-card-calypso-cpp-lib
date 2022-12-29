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

#include "CalypsoSamSelectionAdapter.h"

/* Calypsonet Terminal Calypso */
#include "InconsistentDataException.h"

/* Calypsonet Terminal Card */
#include "ParseException.h"

/* Keyple Core Util */
#include "ByteArrayUtil.h"
#include "HexUtil.h"
#include "KeypleAssert.h"
#include "Pattern.h"
#include "PatternSyntaxException.h"

/* Keyple Card Calypso */
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamAdapter.h"
#include "CalypsoSamCommandException.h"
#include "CardRequestAdapter.h"
#include "CardSelectionRequestAdapter.h"
#include "CmdSamUnlock.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;
using namespace calypsonet::terminal::card::spi;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const int CalypsoSamSelectionAdapter::SW_NOT_LOCKED = 0x6985;

CalypsoSamSelectionAdapter::CalypsoSamSelectionAdapter()
: mSamCardSelector(std::make_shared<CardSelectorAdapter>()) {}

const std::shared_ptr<CardSelectionRequestSpi> CalypsoSamSelectionAdapter::getCardSelectionRequest()
{
    mSamCardSelector->filterByPowerOnData(buildAtrRegex(mProductType, mSerialNumberRegex));

    /* Prepare the UNLOCK command if unlock data has been defined */
    if (mUnlockCommand != nullptr) {
        std::vector<std::shared_ptr<ApduRequestSpi>> cardSelectionApduRequests;
        std::shared_ptr<ApduRequestAdapter> request = mUnlockCommand->getApduRequest();
        request->addSuccessfulStatusWord(SW_NOT_LOCKED);
        cardSelectionApduRequests.push_back(request);
        return std::make_shared<CardSelectionRequestAdapter>(
                   mSamCardSelector,
                   std::make_shared<CardRequestAdapter>(cardSelectionApduRequests, false));
    } else {
        return std::make_shared<CardSelectionRequestAdapter>(mSamCardSelector, nullptr);
    }
}

const std::shared_ptr<SmartCardSpi> CalypsoSamSelectionAdapter::parse(
    const std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse)
{
    if (mUnlockCommand != nullptr) {
        /* An unlock command has been requested */
        if (cardSelectionResponse->getCardResponse() == nullptr ||
            cardSelectionResponse->getCardResponse()->getApduResponses().empty()) {
            throw InconsistentDataException("Mismatch in the number of requests/responses");
        }

        const std::shared_ptr<ApduResponseApi> apduResponse =
            cardSelectionResponse->getCardResponse()->getApduResponses()[0];

        /* Check the SAM response to the unlock command */
        try {
            mUnlockCommand->setApduResponse(apduResponse).checkStatus();
        } catch (const CalypsoSamAccessForbiddenException& e) {
            mLogger->warn("SAM not locked or already unlocked\n");
        } catch (const CalypsoSamCommandException& e) {
            throw ParseException("An exception occurred while parse the SAM responses.",
                                 std::make_shared<CalypsoSamCommandException>(e));
        }
    }

    return std::make_shared<CalypsoSamAdapter>(cardSelectionResponse);
}

CalypsoSamSelection& CalypsoSamSelectionAdapter::filterByProductType(
    const CalypsoSam::ProductType productType)
{
    mProductType = productType;

    return *this;
}

CalypsoSamSelection& CalypsoSamSelectionAdapter::filterBySerialNumber(
    const std::string& serialNumberRegex)
{
    try {
        Pattern::compile(serialNumberRegex);
    } catch (const PatternSyntaxException& exception) {
        (void)exception;
        throw IllegalArgumentException("Invalid regular expression: '" +
                                       serialNumberRegex +
                                       "'.");
    }

    mSerialNumberRegex = serialNumberRegex;

    return *this;
}

CalypsoSamSelection& CalypsoSamSelectionAdapter::setUnlockData(const std::string& unlockData)
{
    Assert::getInstance().isTrue(unlockData.size() == 16 || unlockData.size() == 32,
                                 "unlock data length == 16 or 32")
                         .isHexString(unlockData, "unlockData");

    if (!ByteArrayUtil::isValidHexString(unlockData)) {
        throw IllegalArgumentException("Invalid hexadecimal string.");
    }

    mUnlockCommand = std::make_shared<CmdSamUnlock>(mProductType, HexUtil::toByteArray(unlockData));

    return *this;
}

const std::string CalypsoSamSelectionAdapter::buildAtrRegex(
    const CalypsoSam::ProductType productType,
    const std::string& samSerialNumberRegex)
{
    std::string atrRegex;
    std::string snRegex;

    /* Check if serialNumber is defined */
    if (samSerialNumberRegex.empty()) {
        /* Match all serial numbers */
        snRegex = ".{8}";
    } else {
        /* Match the provided serial number (could be a regex substring) */
        snRegex = samSerialNumberRegex;
    }

    /*
     * Build the final Atr regex according to the SAM subtype and serial number if any.
     *
     * The header is starting with 3B, its total length is 4 or 6 bytes (8 or 10 hex digits)
     */
    std::string applicationTypeMask;
    if (productType != CalypsoSam::ProductType::UNKNOWN) {
        switch (productType) {
        case CalypsoSam::ProductType::SAM_C1:
            applicationTypeMask = "C1";
            break;
        case CalypsoSam::ProductType::SAM_S1DX:
            applicationTypeMask = "D?";
            break;
        case CalypsoSam::ProductType::SAM_S1E1:
            applicationTypeMask = "E1";
            break;
        case CalypsoSam::ProductType::CSAM_F:
            /* TODO Check what is the expected mask here */
            applicationTypeMask = "??";
            break;
        default:
            throw IllegalArgumentException("Unknown SAM subtype.");
        }

        atrRegex = "3B(.{6}|.{10})805A..80" + applicationTypeMask + "20.{4}" + snRegex + "829000";
    } else {
        /* Match any ATR */
        atrRegex = ".*";
    }

    return atrRegex;
}

}
}
}
