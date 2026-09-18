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

#include "keyple/card/calypso/CalypsoCardSelectionExtensionAdapter.hpp"

#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CommandGetDataEfList.hpp"
#include "keyple/card/calypso/CommandGetDataFci.hpp"
#include "keyple/card/calypso/CommandGetDataFcp.hpp"
#include "keyple/card/calypso/CommandGetDataTraceabilityInformation.hpp"
#include "keyple/card/calypso/CommandOpenSecureSession.hpp"
#include "keyple/card/calypso/CommandReadBinary.hpp"
#include "keyple/card/calypso/CommandReadRecords.hpp"
#include "keyple/card/calypso/CommandSelectFile.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/calypso/card/transaction/InconsistentDataException.hpp"
#include "keypop/calypso/card/transaction/SelectFileException.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/ParseException.hpp"
#include "keypop/reader/selection/InvalidCardResponseException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::Assert;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::calypso::card::transaction::InconsistentDataException;
using keypop::calypso::card::transaction::SelectFileException;
using keypop::card::CardResponseApi;
using keypop::card::ParseException;
using keypop::reader::selection::InvalidCardResponseException;

const int CalypsoCardSelectionExtensionAdapter::SW_CARD_INVALIDATED = 0x6283;

CalypsoCardSelectionExtensionAdapter::CalypsoCardSelectionExtensionAdapter()
: mTransactionContext(
      std::unique_ptr<DtoAdapters::TransactionContextDto>(
          new DtoAdapters::TransactionContextDto()))
, mCommandContext(
      std::unique_ptr<DtoAdapters::CommandContextDto>(
          new DtoAdapters::CommandContextDto(false, false)))
, mIsPreOpenPrepared(false)
, mIsInvalidatedCardAccepted(false)
{
}

CalypsoCardSelectionExtension&
CalypsoCardSelectionExtensionAdapter::acceptInvalidatedCard()
{
    mIsInvalidatedCardAccepted = true;

    return *this;
}

CalypsoCardSelectionExtension&
CalypsoCardSelectionExtensionAdapter::prepareReadRecord(
    std::uint8_t sfi, int recordNumber)
{
    Assert::getInstance()
        .isInRange(
            sfi,
            CalypsoCardConstant::SFI_MIN,
            CalypsoCardConstant::SFI_MAX,
            "sfi")
        .isInRange(
            recordNumber,
            CalypsoCardConstant::NB_REC_MIN,
            CalypsoCardConstant::NB_REC_MAX,
            "recordNumber");

    mCommands.push_back(
        std::make_shared<CommandReadRecords>(
            mTransactionContext,
            mCommandContext,
            sfi,
            recordNumber,
            CommandReadRecords::ReadMode::ONE_RECORD,
            nullptr,
            0));

    return *this;
}

CalypsoCardSelectionExtension&
CalypsoCardSelectionExtensionAdapter::prepareSelectFile(std::uint16_t lid)
{
    mCommands.push_back(
        std::make_shared<CommandSelectFile>(
            mTransactionContext, mCommandContext, lid));

    return *this;
}

CalypsoCardSelectionExtension&
CalypsoCardSelectionExtensionAdapter::prepareSelectFile(
    SelectFileControl selectControl)
{
    mCommands.push_back(
        std::make_shared<CommandSelectFile>(
            mTransactionContext, mCommandContext, selectControl));

    return *this;
}

std::unique_ptr<CardSelectionRequestSpi>
CalypsoCardSelectionExtensionAdapter::getCardSelectionRequest()
{
    std::unique_ptr<DtoAdapters::CardSelectionRequestAdapter>
        cardSelectionRequest;

    if (mCommands.empty()) {
        cardSelectionRequest
            = std::unique_ptr<DtoAdapters::CardSelectionRequestAdapter>(
                new DtoAdapters::CardSelectionRequestAdapter(nullptr));

    } else {
        std::vector<std::shared_ptr<ApduRequestSpi>> cardSelectionApduRequests;
        for (const auto& command : mCommands) {
            cardSelectionApduRequests.push_back(command->getApduRequest());
        }
        cardSelectionRequest
            = std::unique_ptr<DtoAdapters::CardSelectionRequestAdapter>(
                new DtoAdapters::CardSelectionRequestAdapter(
                    std::unique_ptr<DtoAdapters::CardRequestAdapter>(
                        new DtoAdapters::CardRequestAdapter(
                            cardSelectionApduRequests, false))));
    }

    if (mIsInvalidatedCardAccepted) {
        cardSelectionRequest->addSuccessfulSelectionStatusWord(
            SW_CARD_INVALIDATED);
    }

    return cardSelectionRequest;
}

CalypsoCardSelectionExtension&
CalypsoCardSelectionExtensionAdapter::prepareReadBinary(
    std::uint8_t sfi, int offset, int nbBytesToRead)
{
    Assert::getInstance()
        .isInRange(
            static_cast<int>(sfi),
            CalypsoCardConstant::SFI_MIN,
            CalypsoCardConstant::SFI_MAX,
            "sfi")
        .isInRange(
            offset,
            CalypsoCardConstant::OFFSET_MIN,
            CalypsoCardConstant::OFFSET_BINARY_MAX,
            "offset")
        .greaterOrEqual(nbBytesToRead, 1, "nbBytesToRead");

    if (sfi > 0 && offset > 255) {  // FFh
        /*
         * Tips to select the file: add a "Read Binary" command (read one byte
         * at offset 0).
         */
        mCommands.push_back(
            std::make_shared<CommandReadBinary>(
                mTransactionContext, mCommandContext, sfi, 0, 1));
    }

    int currentOffset = offset;
    int nbBytesRemainingToRead = nbBytesToRead;

    do {
        int currentLength = std::min(
            nbBytesRemainingToRead,
            CalypsoCardConstant::DEFAULT_PAYLOAD_CAPACITY);

        mCommands.push_back(
            std::make_shared<CommandReadBinary>(
                mTransactionContext,
                mCommandContext,
                sfi,
                currentOffset,
                currentLength));

        currentOffset += currentLength;
        nbBytesRemainingToRead -= currentLength;

    } while (nbBytesRemainingToRead > 0);

    return *this;
}

CalypsoCardSelectionExtension&
CalypsoCardSelectionExtensionAdapter::prepareReadCounter(
    std::uint8_t sfi, int nbCountersToRead)
{
    Assert::getInstance()
        .isInRange(
            static_cast<int>(sfi),
            CalypsoCardConstant::SFI_MIN,
            CalypsoCardConstant::SFI_MAX,
            "sfi")
        .isInRange(
            nbCountersToRead,
            0,
            CalypsoCardConstant::DEFAULT_PAYLOAD_CAPACITY / 3,
            "nbCountersToRead");

    mCommands.push_back(
        std::make_shared<CommandReadRecords>(
            mTransactionContext,
            mCommandContext,
            sfi,
            1,
            CommandReadRecords::ReadMode::ONE_RECORD,
            std::unique_ptr<int>(new int(nbCountersToRead * 3)),
            0));

    return *this;
}

CalypsoCardSelectionExtension&
CalypsoCardSelectionExtensionAdapter::preparePreOpenSecureSession(
    WriteAccessLevel writeAccessLevel)
{
    if (mIsPreOpenPrepared) {
        throw IllegalStateException(
            "'Pre-Open Secure Session' command is already prepared");
    }

    mCommands.push_back(
        std::make_shared<CommandOpenSecureSession>(
            mTransactionContext, mCommandContext, writeAccessLevel));

    mIsPreOpenPrepared = true;

    return *this;
}

CalypsoCardSelectionExtension&
CalypsoCardSelectionExtensionAdapter::prepareGetData(GetDataTag tag)
{
    switch (tag) {
    case GetDataTag::FCI_FOR_CURRENT_DF:
        mCommands.push_back(
            std::make_shared<CommandGetDataFci>(
                mTransactionContext, mCommandContext));
        break;
    case GetDataTag::FCP_FOR_CURRENT_FILE:
        mCommands.push_back(
            std::make_shared<CommandGetDataFcp>(
                mTransactionContext, mCommandContext));
        break;
    case GetDataTag::EF_LIST:
        mCommands.push_back(
            std::make_shared<CommandGetDataEfList>(
                mTransactionContext, mCommandContext));
        break;
    case GetDataTag::TRACEABILITY_INFORMATION:
        mCommands.push_back(
            std::make_shared<CommandGetDataTraceabilityInformation>(
                mTransactionContext, mCommandContext));
        break;
    default:
        throw UnsupportedOperationException(
            "Unsupported GetDataTag: " + std::to_string(static_cast<int>(tag)));
    }

    return *this;
}

std::shared_ptr<SmartCardSpi>
CalypsoCardSelectionExtensionAdapter::parse(
    const std::shared_ptr<CardSelectionResponseApi>& cardSelectionResponse)
{
    std::shared_ptr<CardResponseApi> cardResponse
        = cardSelectionResponse->getCardResponse();

    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses
        = cardResponse != nullptr
              ? cardResponse->getApduResponses()
              : std::vector<std::shared_ptr<ApduResponseApi>> {};

    if (mCommands.size() != apduResponses.size()) {
        throw ParseException(
            "The number of commands/responses does not match. Expected "
            + std::to_string(mCommands.size()) + " responses, got "
            + std::to_string(apduResponses.size()));
    }

    std::shared_ptr<CalypsoCardAdapter> calypsoCard;

    try {
        calypsoCard = std::make_shared<CalypsoCardAdapter>();
        calypsoCard->initialize(cardSelectionResponse);
        if (!mCommands.empty()) {
            parseApduResponses(calypsoCard, mCommands, apduResponses);
        }

    } catch (const Exception& e) {
        throw ParseException(
            "Invalid card response", std::make_shared<Exception>(e));
    }

    if (calypsoCard->getProductType() == CalypsoCard::ProductType::UNKNOWN
        && cardSelectionResponse->getSelectApplicationResponse() == nullptr
        && cardSelectionResponse->getPowerOnData() == "") {
        throw ParseException(
            std::string("No power-on data and no FCI provided. Unable to ")
            + "create a CalypsoCard");
    }

    return calypsoCard;
}

void
CalypsoCardSelectionExtensionAdapter::parseApduResponses(
    const std::shared_ptr<CalypsoCardAdapter>& calypsoCard,
    const std::vector<std::shared_ptr<Command>>& commands,
    const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses)
{
    /*
     * If there are more responses than requests, then we are unable to fill the
     * card image. In this case we stop processing immediately because it may be
     * a case of fraud, and we throw a desynchronized exception.
     */
    if (apduResponses.size() > commands.size()) {
        throw InconsistentDataException(
            std::string("The number of commands/responses does not match. ")
            + "Expected " + std::to_string(commands.size()) + " responses, "
            + "got " + std::to_string(apduResponses.size()));
    }

    /*
     * We go through all the responses (and not the requests) because there may
     * be fewer in the case of an error that occurred in strict mode. In this
     * case the last response will raise an exception.
     */
    for (int i = 0; i < static_cast<int>(apduResponses.size()); i++) {
        try {
            commands[i]->parseResponseForSelection(
                apduResponses[i], calypsoCard);

        } catch (const CardCommandException& e) {
            CardCommandRef commandRef = commands[i]->getCommandRef();
            if (commandRef == CardCommandRef::READ_RECORDS
                || commandRef == CardCommandRef::READ_BINARY
                || commandRef == CardCommandRef::OPEN_SECURE_SESSION) {
                continue;
            }

            try {
                auto cardDataAccessException
                    = dynamic_cast<const CardDataAccessException&>(e);
                if (commandRef == CardCommandRef::SELECT_FILE) {
                    throw SelectFileException("File not found", e);

                } else {
                    /* Go to the catch section to avoid code duplication. */
                    throw std::bad_cast();
                }

            } catch (const std::bad_cast&) {
                const std::string sw = commands[i]->getApduResponse() != nullptr
                                           ? HexUtil::toHex(
                                                 static_cast<std::uint16_t>(
                                                     commands[i]
                                                         ->getApduResponse()
                                                         ->getStatusWord()))
                                           : "null";
                throw InvalidCardResponseException(
                    std::string("Failed to process SAM response. ")
                        + "Command: " + commandRef.getName() + ", "
                        + "SW: " + sw,
                    e);
            }
        }
    }

    /*
     * Finally, if no error has occurred and there are fewer responses than
     * requests, then we throw a desynchronized exception.
     */
    if (apduResponses.size() < commands.size()) {
        throw InconsistentDataException(
            std::string("The number of commands/responses does not match. ")
            + "Expected " + std::to_string(commands.size()) + " responses, "
            + "got " + std::to_string(apduResponses.size()));
    }
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
