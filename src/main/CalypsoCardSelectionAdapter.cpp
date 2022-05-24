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

#include "CalypsoCardSelectionAdapter.h"

/* Calypsonet Terminal Card */
#include "ParseException.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CalypsoCardClass.h"
#include "CalypsoCardConstant.h"
#include "CalypsoCardUtilAdapter.h"
#include "CardSelectionRequestAdapter.h"
#include "CmdCardGetDataFci.h"
#include "CmdCardGetDataFcp.h"
#include "CmdCardGetDataEfList.h"
#include "CmdCardGetDataTraceabilityInformation.h"
#include "CmdCardReadRecords.h"
#include "CmdCardSelectFile.h"
#include "UnsupportedOperationException.h"

/* Keyple Card Generic */
#include "CardRequestAdapter.h"

/* Keyple Core Util */
#include "ByteArrayUtil.h"
#include "IllegalArgumentException.h"
#include "KeypleAssert.h"
#include "Pattern.h"
#include "PatternSyntaxException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card::spi;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const int CalypsoCardSelectionAdapter::AID_MIN_LENGTH = 5;
const int CalypsoCardSelectionAdapter::AID_MAX_LENGTH = 16;
const int CalypsoCardSelectionAdapter::SW_CARD_INVALIDATED = 0x6283;

CalypsoCardSelectionAdapter::CalypsoCardSelectionAdapter()
: mCardSelector(std::make_shared<CardSelectorAdapter>()) {}

CalypsoCardSelection& CalypsoCardSelectionAdapter::filterByCardProtocol(
    const std::string& cardProtocol)
{
    Assert::getInstance().notEmpty(cardProtocol, "cardProtocol");

    mCardSelector->filterByCardProtocol(cardProtocol);

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::filterByPowerOnData(
    const std::string& powerOnDataRegex)
{
    Assert::getInstance().notEmpty(powerOnDataRegex, "powerOnDataRegex");

    try {
        Pattern::compile(powerOnDataRegex);
    } catch (const PatternSyntaxException& exception) {
        throw IllegalArgumentException("Invalid regular expression: '" +
                                       powerOnDataRegex +
                                       "'.");
    }

    mCardSelector->filterByPowerOnData(powerOnDataRegex);

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::filterByDfName(const std::vector<uint8_t>& aid)
{
    Assert::getInstance().notEmpty(aid, "aid")
                         .isInRange(aid.size(), AID_MIN_LENGTH, AID_MAX_LENGTH, "aid");

    mCardSelector->filterByDfName(aid);

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::filterByDfName(const std::string& aid)
{
    Assert::getInstance().isTrue(ByteArrayUtil::isValidHexString(aid), "aid format");

    filterByDfName(ByteArrayUtil::fromHex(aid));

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::setFileOccurrence(
    const FileOccurrence fileOccurrence)
{
    switch (fileOccurrence) {
    case FileOccurrence::FIRST:
        mCardSelector->setFileOccurrence(CardSelectorSpi::FileOccurrence::FIRST);
        break;
    case FileOccurrence::LAST:
        mCardSelector->setFileOccurrence(CardSelectorSpi::FileOccurrence::LAST);
        break;
    case FileOccurrence::NEXT:
        mCardSelector->setFileOccurrence(CardSelectorSpi::FileOccurrence::NEXT);
        break;
    case FileOccurrence::PREVIOUS:
        mCardSelector->setFileOccurrence(CardSelectorSpi::FileOccurrence::PREVIOUS);
        break;
    }

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::setFileControlInformation(
    const FileControlInformation fileControlInformation)
{
    if (fileControlInformation == FileControlInformation::FCI) {
        mCardSelector->setFileControlInformation(CardSelectorSpi::FileControlInformation::FCI);
    } else if (fileControlInformation == FileControlInformation::NO_RESPONSE) {
        mCardSelector->setFileControlInformation(
            CardSelectorSpi::FileControlInformation::NO_RESPONSE);
    }

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::addSuccessfulStatusWord(const int statusWord)
{
    Assert::getInstance().isInRange(statusWord, 0, 0xFFFF, "statusWord");

    mCardSelector->addSuccessfulStatusWord(statusWord);

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::acceptInvalidatedCard()
{
    mCardSelector->addSuccessfulStatusWord(SW_CARD_INVALIDATED);

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::prepareReadRecordFile(const uint8_t sfi,
                                                                         const int recordNumber)
{
    return prepareReadRecord(sfi, recordNumber);
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::prepareReadRecord(const uint8_t sfi,
                                                                     const int recordNumber)
{
    Assert::getInstance().isInRange(sfi,
                                    CalypsoCardConstant::SFI_MIN,
                                    CalypsoCardConstant::SFI_MAX,
                                    "sfi")
                         .isInRange(recordNumber,
                                    CalypsoCardConstant::NB_REC_MIN,
                                    CalypsoCardConstant::NB_REC_MAX,
                                    "recordNumber");

    mCommands.push_back(
        std::make_shared<CmdCardReadRecords>(CalypsoCardClass::ISO,
                                             sfi,
                                             recordNumber,
                                             CmdCardReadRecords::ReadMode::ONE_RECORD, 0));

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::prepareGetData(const GetDataTag tag)
{
   /* Create the command and add it to the list of commands */
    switch (tag) {
    case GetDataTag::FCI_FOR_CURRENT_DF:
        mCommands.push_back(std::make_shared<CmdCardGetDataFci>(CalypsoCardClass::ISO));
        break;
    case GetDataTag::FCP_FOR_CURRENT_FILE:
        mCommands.push_back(std::make_shared<CmdCardGetDataFcp>(CalypsoCardClass::ISO));
        break;
    case GetDataTag::EF_LIST:
        mCommands.push_back(std::make_shared<CmdCardGetDataEfList>(CalypsoCardClass::ISO));
        break;
    case GetDataTag::TRACEABILITY_INFORMATION:
        mCommands.push_back(
            std::make_shared<CmdCardGetDataTraceabilityInformation>(CalypsoCardClass::ISO));
        break;
    default:
        throw UnsupportedOperationException("Unsupported Get Data tag: "); // FIXME: + tag.name());
    }

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::prepareSelectFile(
    const std::vector<uint8_t>& lid)
{
    Assert::getInstance().isEqual(lid.size(), 2, "lid length");

    return prepareSelectFile(ByteArrayUtil::twoBytesToInt(lid, 0));
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::prepareSelectFile(const uint16_t lid)
{
    mCommands.push_back(
        std::make_shared<CmdCardSelectFile>(CalypsoCardClass::ISO,
                                            CalypsoCard::ProductType::PRIME_REVISION_3, lid));

    return *this;
}

CalypsoCardSelection& CalypsoCardSelectionAdapter::prepareSelectFile(
    const SelectFileControl selectControl)
{
    mCommands.push_back(std::make_shared<CmdCardSelectFile>(CalypsoCardClass::ISO, selectControl));

    return *this;
}

const std::shared_ptr<CardSelectionRequestSpi>
    CalypsoCardSelectionAdapter::getCardSelectionRequest()
{
    std::vector<std::shared_ptr<ApduRequestSpi>> cardSelectionApduRequests;

    if (!mCommands.empty()) {
        for (const auto& command : mCommands) {
            cardSelectionApduRequests.push_back(command->getApduRequest());
        }

        return std::make_shared<CardSelectionRequestAdapter>(
                   mCardSelector,
                   std::make_shared<CardRequestAdapter>(cardSelectionApduRequests, false));
    } else {
        return std::make_shared<CardSelectionRequestAdapter>(mCardSelector, nullptr);
    }
}

const std::shared_ptr<SmartCardSpi> CalypsoCardSelectionAdapter::parse(
    const std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse)
{
    const std::shared_ptr<CardResponseApi> cardResponse = cardSelectionResponse->getCardResponse();
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses;

    if (cardResponse != nullptr) {
        apduResponses = cardResponse->getApduResponses();
    } else {
        apduResponses = {};
    }

    if (mCommands.size() != apduResponses.size()) {
        throw ParseException("Mismatch in the number of requests/responses.");
    }

    std::shared_ptr<CalypsoCardAdapter> calypsoCard;
    try {
        calypsoCard = std::make_shared<CalypsoCardAdapter>();
        if (cardSelectionResponse->getSelectApplicationResponse() != nullptr) {
            calypsoCard->initializeWithFci(cardSelectionResponse->getSelectApplicationResponse());
        } else if (cardSelectionResponse->getPowerOnData() != "") {
            calypsoCard->initializeWithPowerOnData(cardSelectionResponse->getPowerOnData());
        }

        if (!mCommands.empty()) {
            CalypsoCardUtilAdapter::updateCalypsoCard(calypsoCard, mCommands, apduResponses, false);
        }

    } catch (const Exception& e) {
        throw ParseException("Invalid card response: " + e.getMessage(),
                             std::make_shared<Exception>(e));
    }

    if (calypsoCard->getProductType() == CalypsoCard::ProductType::UNKNOWN &&
        cardSelectionResponse->getSelectApplicationResponse() == nullptr &&
        cardSelectionResponse->getPowerOnData() == "") {
        throw ParseException("Unable to create a CalypsoCard: no power-on data and no FCI " \
                             "provided.");
    }

    return calypsoCard;
}

}
}
}
