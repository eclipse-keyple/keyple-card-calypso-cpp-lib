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

#include "keyple/card/calypso/TransactionManagerAdapter.hpp"

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CommandAppendRecord.hpp"
#include "keyple/card/calypso/CommandGenerateAsymmetricKeyPair.hpp"
#include "keyple/card/calypso/CommandGetDataCardPublicKey.hpp"
#include "keyple/card/calypso/CommandGetDataCertificate.hpp"
#include "keyple/card/calypso/CommandGetDataEfList.hpp"
#include "keyple/card/calypso/CommandGetDataFcp.hpp"
#include "keyple/card/calypso/CommandGetDataTraceabilityInformation.hpp"
#include "keyple/card/calypso/CommandIncreaseOrDecrease.hpp"
#include "keyple/card/calypso/CommandIncreaseOrDecreaseMultiple.hpp"
#include "keyple/card/calypso/CommandOpenSecureSession.hpp"
#include "keyple/card/calypso/CommandPutData.hpp"
#include "keyple/card/calypso/CommandReadBinary.hpp"
#include "keyple/card/calypso/CommandReadRecordMultiple.hpp"
#include "keyple/card/calypso/CommandReadRecords.hpp"
#include "keyple/card/calypso/CommandSearchRecordMultiple.hpp"
#include "keyple/card/calypso/CommandSelectFile.hpp"
#include "keyple/card/calypso/CommandUpdateOrWriteBinary.hpp"
#include "keyple/card/calypso/CommandUpdateRecord.hpp"
#include "keyple/card/calypso/CommandVerifyPin.hpp"
#include "keyple/card/calypso/CommandWriteRecord.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keyple/core/util/cpp/exception/RuntimeException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/calypso/card/transaction/InconsistentDataException.hpp"
#include "keypop/card/CardBrokenCommunicationException.hpp"
#include "keypop/card/ReaderBrokenCommunicationException.hpp"
#include "keypop/card/UnexpectedStatusWordException.hpp"
#include "keypop/reader/CardCommunicationException.hpp"
#include "keypop/reader/ReaderCommunicationException.hpp"
#include "keypop/reader/selection/InvalidCardResponseException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::Assert;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keyple::core::util::cpp::exception::RuntimeException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::calypso::card::transaction::InconsistentDataException;
using keypop::card::CardBrokenCommunicationException;
using keypop::card::ReaderBrokenCommunicationException;
using keypop::card::UnexpectedStatusWordException;
using keypop::reader::CardCommunicationException;
using keypop::reader::ReaderCommunicationException;
using keypop::reader::selection::InvalidCardResponseException;

template <typename T>
const std::string TransactionManagerAdapter<
    T>::MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_EXPECTED
    = "The number of commands/responses does not match. Expected ";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_RESPONSES_GOT
    = " responses, got ";
template <typename T>
const std::string
    TransactionManagerAdapter<T>::MSG_CARD_READER_COMMUNICATION_ERROR
    = "Failed to communicate with card reader";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_CARD_COMMUNICATION_ERROR
    = "Failed to communicate with card";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_WHILE_TRANSMITTING_COMMANDS
    = " while transmitting commands.";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_PIN_NOT_AVAILABLE
    = "PIN is not available for this card";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_RECORD_NUMBER
    = "record number";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_OFFSET = "offset";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_RECORD_DATA = "record data";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_RECORD_DATA_LENGTH
    = "record data length";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_SECURE_SESSION_OPEN
    = "Secure session is open";
template <typename T>
const std::string
    TransactionManagerAdapter<T>::MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD
    = "PKI mode is not available for this card";
template <typename T>
const std::string TransactionManagerAdapter<T>::MSG_DATA_LENGTH = "data length";

template <typename T>
TransactionManagerAdapter<T>::TransactionManagerAdapter(
    std::shared_ptr<ProxyReaderApi> cardReader,
    std::shared_ptr<CalypsoCardAdapter> card)
: mCard(card)
, mCardReader(cardReader)
{
}

template <typename T>
void
TransactionManagerAdapter<T>::executeCardCommands(
    const std::vector<std::shared_ptr<Command>>& commands,
    ChannelControl channelControl)
{
    /* Retrieve the list of C-APDUs */
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests
        = getApduRequests(commands);

    /* Wrap the list of C-APDUs into a card request */
    auto cardRequest
        = std::make_shared<DtoAdapters::CardRequestAdapter>(apduRequests, true);

    /* Transmit the commands to the card */
    std::shared_ptr<CardResponseApi> cardResponse
        = transmitCardRequest(cardRequest, channelControl);

    /* Retrieve the list of R-APDUs */
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses
        = cardResponse->getApduResponses();

    /*
     * If there are more responses than requests, then we are unable to fill the
     * card image. In this case we stop processing immediately because it may be
     * a case of fraud, and we throw a desynchronized exception.
     */
    if (apduResponses.size() > commands.size()) {
        throw InconsistentDataException(
            MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_EXPECTED
            + std::to_string(commands.size()) + MSG_RESPONSES_GOT
            + std::to_string(apduResponses.size())
            + getTransactionAuditDataAsString());
    }

    /*
     * We go through all the responses (and not the requests) because there may
     * be fewer in the case of an error that occurred in strict mode. In this
     * case the last response will raise an exception.
     */
    for (int i = 0; i < static_cast<int>(apduResponses.size()); i++) {
        std::shared_ptr<Command> command = commands[i];
        try {
            parseCommandResponse(command, apduResponses[i]);
            handleCommandPostProcessing(i, commands);
        } catch (const CardCommandException& e) {
            const std::string sw
                = command->getApduResponse() != nullptr
                      ? HexUtil::toHex(
                            static_cast<std::uint16_t>(
                                command->getApduResponse()->getStatusWord()))
                      : "null";
            throw InvalidCardResponseException(
                "Failed to process card response. Command: "
                    + command->getCommandRef().getName() + ", SW: " + sw
                    + getTransactionAuditDataAsString(),
                e);
        }
    }

    /*
     * Finally, if no error has occurred and there are fewer responses than
     * requests, then we throw a desynchronized exception.
     */
    if (apduResponses.size() < commands.size()) {
        throw InconsistentDataException(
            MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_EXPECTED
            + std::to_string(commands.size()) + MSG_RESPONSES_GOT
            + std::to_string(apduResponses.size())
            + getTransactionAuditDataAsString());
    }
}

template <typename T>
void
TransactionManagerAdapter<T>::parseCommandResponse(
    const std::shared_ptr<Command>& command,
    const std::shared_ptr<ApduResponseApi>& apduResponse)
{
    command->parseResponse(apduResponse);
}

template <typename T>
void
TransactionManagerAdapter<T>::handleCommandPostProcessing(
    int /*commandIndex*/,
    const std::vector<std::shared_ptr<Command>>& /*commands*/)
{
}

template <typename T>
std::vector<std::shared_ptr<ApduRequestSpi>>
TransactionManagerAdapter<T>::getApduRequests(
    const std::vector<std::shared_ptr<Command>>& commands)
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;
    if (!commands.empty()) {
        for (const auto& command : commands) {
            apduRequests.push_back(command->getApduRequest());
        }
    }

    return apduRequests;
}

template <typename T>
std::shared_ptr<CardResponseApi>
TransactionManagerAdapter<T>::transmitCardRequest(
    std::shared_ptr<CardRequestSpi> cardRequest, ChannelControl channelControl)
{
    std::shared_ptr<CardResponseApi> cardResponse;

    try {
        cardResponse = mCardReader->transmitCardRequest(
            cardRequest, mapToInternalChannelControl(channelControl));

    } catch (const ReaderBrokenCommunicationException& e) {
        saveTransactionAuditData(cardRequest, e.getCardResponse());
        throw ReaderCommunicationException(
            MSG_CARD_READER_COMMUNICATION_ERROR
                + MSG_WHILE_TRANSMITTING_COMMANDS
                + getTransactionAuditDataAsString(),
            e);

    } catch (const CardBrokenCommunicationException& e) {
        saveTransactionAuditData(cardRequest, e.getCardResponse());
        throw CardCommunicationException(
            MSG_CARD_COMMUNICATION_ERROR + MSG_WHILE_TRANSMITTING_COMMANDS
                + getTransactionAuditDataAsString(),
            e);

    } catch (const UnexpectedStatusWordException& e) {
        cardResponse = e.getCardResponse();
    }

    saveTransactionAuditData(cardRequest, cardResponse);

    return cardResponse;
}

template <typename T>
std::string
TransactionManagerAdapter<T>::getTransactionAuditDataAsString() const
{
    return std::string("\nTransaction audit JSON data: {")
           + "\"targetSmartCard\":" + "FIXME"  // JsonUtil.toJson(card)
           + ","
           + "\"apdus\":" + " FIXME"  // JsonUtil.toJson(transactionAuditData)
           + "}";
}

template <typename T>
keypop::card::ChannelControl
TransactionManagerAdapter<T>::mapToInternalChannelControl(
    ChannelControl channelControl) const
{
    return keypop::card::valueOf(static_cast<int>(channelControl));
}

template <typename T>
void
TransactionManagerAdapter<T>::saveTransactionAuditData(
    const std::shared_ptr<CardRequestSpi>& cardRequest,
    const std::shared_ptr<CardResponseApi>& cardResponse)
{
    if (cardResponse != nullptr) {
        std::vector<std::shared_ptr<ApduRequestSpi>> requests
            = cardRequest->getApduRequests();
        std::vector<std::shared_ptr<ApduResponseApi>> responses
            = cardResponse->getApduResponses();

        int responsesSize = responses.size();

        for (int i = 0; i < static_cast<int>(requests.size()); i++) {
            const std::vector<std::uint8_t> empty;
            mTransactionAuditData.push_back(requests[i]->getApdu());
            mTransactionAuditData.push_back(
                (i < responsesSize) ? responses[i]->getApdu() : empty);
        }
    }
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareSelectFile(std::uint16_t lid)
{
    try {
        mCommands.push_back(
            std::unique_ptr<CommandSelectFile>(new CommandSelectFile(
                getTransactionContext(), getCommandContext(), lid)));

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareSelectFile(
    SelectFileControl selectFileControl)
{
    try {
        mCommands.push_back(
            std::unique_ptr<CommandSelectFile>(new CommandSelectFile(
                getTransactionContext(),
                getCommandContext(),
                selectFileControl)));

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareGetData(GetDataTag tag)
{
    try {
        if (getCommandContext()->isSecureSessionOpen()) {
            throw IllegalStateException(MSG_SECURE_SESSION_OPEN);
        }

        switch (tag) {
        case GetDataTag::FCI_FOR_CURRENT_DF:
            mCommands.push_back(
                std::make_shared<CommandGetDataFci>(
                    getTransactionContext(), getCommandContext()));
            break;
        case GetDataTag::FCP_FOR_CURRENT_FILE:
            mCommands.push_back(
                std::make_shared<CommandGetDataFcp>(
                    getTransactionContext(), getCommandContext()));
            break;
        case GetDataTag::EF_LIST:
            mCommands.push_back(
                std::make_shared<CommandGetDataEfList>(
                    getTransactionContext(), getCommandContext()));
            break;
        case GetDataTag::TRACEABILITY_INFORMATION:
            mCommands.push_back(
                std::make_shared<CommandGetDataTraceabilityInformation>(
                    getTransactionContext(), getCommandContext()));
            break;
        case GetDataTag::CARD_PUBLIC_KEY:
            mCommands.push_back(
                std::make_shared<CommandGetDataCardPublicKey>(
                    getTransactionContext(), getCommandContext()));
            break;
        case GetDataTag::CARD_CERTIFICATE:
            mCommands.push_back(
                std::make_shared<CommandGetDataCertificate>(
                    getTransactionContext(), getCommandContext(), true, true));
            mCommands.push_back(
                std::make_shared<CommandGetDataCertificate>(
                    getTransactionContext(), getCommandContext(), true, false));
            break;
        case GetDataTag::CA_CERTIFICATE:
            mCommands.push_back(
                std::make_shared<CommandGetDataCertificate>(
                    getTransactionContext(), getCommandContext(), false, true));
            mCommands.push_back(
                std::make_shared<CommandGetDataCertificate>(
                    getTransactionContext(),
                    getCommandContext(),
                    false,
                    false));
            break;
        default:
            throw UnsupportedOperationException(
                "Unsupported GetDataTag: "
                + std::to_string(static_cast<int>(tag)));
        }

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::preparePutData(
    PutDataTag putDataTag, const std::vector<std::uint8_t>& data)
{
    if (getCommandContext()->isSecureSessionOpen()) {
        throw IllegalStateException(MSG_SECURE_SESSION_OPEN);
    }

    switch (putDataTag) {
    case PutDataTag::CARD_KEY_PAIR:
        preparePutDataCardKeyPair(putDataTag, data);
        break;
    case PutDataTag::CARD_CERTIFICATE:
        preparePutDataCertificate(
            putDataTag, data, CalypsoCardConstant::CARD_CERTIFICATE_SIZE);
        break;
    case PutDataTag::CA_CERTIFICATE:
        preparePutDataCertificate(
            putDataTag, data, CalypsoCardConstant::CA_CERTIFICATE_SIZE);
        break;
    default:
        throw UnsupportedOperationException(
            "Unsupported PutDataTag: "
            + std::to_string(static_cast<int>(putDataTag)));
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
void
TransactionManagerAdapter<T>::preparePutDataCardKeyPair(
    PutDataTag putDataTag, const std::vector<std::uint8_t>& data)
{
    if (!mCard->isPkiModeSupported()) {
        throw UnsupportedOperationException(
            MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD);
    }

    Assert::getInstance().isEqual(
        data.size(), CalypsoCardConstant::CARD_KEY_PAIR_SIZE, MSG_DATA_LENGTH);

    mCommands.push_back(
        std::make_shared<CommandPutData>(
            getTransactionContext(),
            getCommandContext(),
            putDataTag,
            true,
            data));
}

template <typename T>
void
TransactionManagerAdapter<T>::preparePutDataCertificate(
    PutDataTag putDataTag,
    const std::vector<std::uint8_t>& data,
    int certificateSize)
{
    std::shared_ptr<DtoAdapters::TransactionContextDto> transactionContext
        = getTransactionContext();
    std::shared_ptr<DtoAdapters::CommandContextDto> commandContext
        = getCommandContext();

    int payloadCapacity
        = getTransactionContext()->getCard()->getPayloadCapacity();

    if (!mCard->isPkiModeSupported()) {
        throw UnsupportedOperationException(
            MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD);
    }

    Assert::getInstance().isEqual(
        data.size(), certificateSize, MSG_DATA_LENGTH);

    mCommands.push_back(
        std::make_shared<CommandPutData>(
            transactionContext,
            commandContext,
            putDataTag,
            true,
            Arrays::copyOf(
                data,
                payloadCapacity
                    - CalypsoCardConstant::TAG_CERTIFICATE_HEADER_SIZE)));
    mCommands.push_back(
        std::make_shared<CommandPutData>(
            transactionContext,
            commandContext,
            putDataTag,
            false,
            Arrays::copyOfRange(
                data,
                payloadCapacity
                    - CalypsoCardConstant::TAG_CERTIFICATE_HEADER_SIZE,
                data.size())));
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareReadRecord(
    std::uint8_t sfi, int recordNumber)
{
    try {
        if (getCommandContext()->isSecureSessionOpen()) {
            throw IllegalStateException(MSG_SECURE_SESSION_OPEN);
        }

        Assert::getInstance()
            .isInRange(
                static_cast<int>(sfi),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                recordNumber,
                CalypsoCardConstant::NB_REC_MIN,
                CalypsoCardConstant::NB_REC_MAX,
                MSG_RECORD_NUMBER);

        /*
         * A null record size indicates that the card determines the output
         * length. However, "legacy case 1" cards require a non-zero value.
         */
        std::unique_ptr<int> recordSize
            = mCard->isLegacyCase1()
                  ? std::unique_ptr<int>(
                        new int(CalypsoCardConstant::LEGACY_REC_LENGTH))
                  : nullptr;

        mCommands.push_back(
            std::make_shared<CommandReadRecords>(
                getTransactionContext(),
                getCommandContext(),
                sfi,
                recordNumber,
                CommandReadRecords::ReadMode::ONE_RECORD,
                std::move(recordSize),
                recordSize != nullptr ? *recordSize : 0));
    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareReadRecords(
    std::uint8_t sfi, int fromRecordNumber, int toRecordNumber, int recordSize)
{
    try {
        Assert::getInstance()
            .isInRange(
                static_cast<int>(sfi),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                fromRecordNumber,
                CalypsoCardConstant::NB_REC_MIN,
                CalypsoCardConstant::NB_REC_MAX,
                "fromRecordNumber")
            .isInRange(
                toRecordNumber,
                fromRecordNumber,
                CalypsoCardConstant::NB_REC_MAX,
                "toRecordNumber")
            .isInRange(recordSize, 0, getPayloadCapacity(), "recordSize");

        if (toRecordNumber == fromRecordNumber
            || (mCard->getProductType()
                    != CalypsoCard::ProductType::PRIME_REVISION_3
                && mCard->getProductType()
                       != CalypsoCard::ProductType::LIGHT)) {
            /*
             * Creates N unitary "Read Records" commands.
             * Try to group the first read record command with the open secure
             * session command.
             */
            if (canConfigureReadOnOpenSecureSession()) {
                auto session
                    = std::dynamic_pointer_cast<CommandOpenSecureSession>(
                        mCommands[mCommands.size() - 1]);
                session->configureReadMode(sfi, fromRecordNumber, recordSize);
                fromRecordNumber++;
            }

            for (int i = fromRecordNumber; i <= toRecordNumber; i++) {
                mCommands.push_back(
                    std::make_shared<CommandReadRecords>(
                        getTransactionContext(),
                        getCommandContext(),
                        sfi,
                        i,
                        CommandReadRecords::ReadMode::ONE_RECORD,
                        std::unique_ptr<int>(new int(recordSize)),
                        recordSize));
            }
        } else {
            /*
             * Manages the reading of multiple records taking into account the
             * transmission capacity of the card and the response format (2
             * extra bytes).
             * Multiple APDUs can be generated depending on record size and
             * transmission capacity.
             */
            const int nbBytesPerRecord = recordSize + 2;
            const int nbRecordsPerApdu
                = getPayloadCapacity() / nbBytesPerRecord;
            const int dataSizeMaxPerApdu = nbRecordsPerApdu * nbBytesPerRecord;

            int currentRecordNumber = fromRecordNumber;
            int nbRecordsRemainingToRead
                = toRecordNumber - fromRecordNumber + 1;

            while (currentRecordNumber < toRecordNumber) {
                int currentLength
                    = nbRecordsRemainingToRead <= nbRecordsPerApdu
                          ? nbRecordsRemainingToRead * nbBytesPerRecord
                          : dataSizeMaxPerApdu;

                mCommands.push_back(
                    std::make_shared<CommandReadRecords>(
                        getTransactionContext(),
                        getCommandContext(),
                        sfi,
                        currentRecordNumber,
                        CommandReadRecords::ReadMode::MULTIPLE_RECORD,
                        std::unique_ptr<int>(new int(currentLength)),
                        recordSize));
                currentRecordNumber += (currentLength / nbBytesPerRecord);
                nbRecordsRemainingToRead -= (currentLength / nbBytesPerRecord);
            }

            /*
             * Optimization: prepare a read "one record" if possible for last
             * iteration.
             */
            if (currentRecordNumber == toRecordNumber) {
                mCommands.push_back(
                    std::make_shared<CommandReadRecords>(
                        getTransactionContext(),
                        getCommandContext(),
                        sfi,
                        currentRecordNumber,
                        CommandReadRecords::ReadMode::ONE_RECORD,
                        std::unique_ptr<int>(new int(recordSize)),
                        recordSize));
            }
        }

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareReadRecordsPartially(
    std::uint8_t sfi,
    int fromRecordNumber,
    int toRecordNumber,
    int offset,
    int nbBytesToRead)
{
    try {
        if (mCard->getProductType()
                != CalypsoCard::ProductType::PRIME_REVISION_3
            && mCard->getProductType() != CalypsoCard::ProductType::LIGHT) {
            throw UnsupportedOperationException(
                std::string("'Read Record Multiple' command is not available ")
                + "for this card");
        }

        if (getCommandContext()->isSecureSessionOpen()) {
            throw IllegalStateException(MSG_SECURE_SESSION_OPEN);
        }

        Assert::getInstance()
            .isInRange(
                static_cast<int>(sfi),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                fromRecordNumber,
                CalypsoCardConstant::NB_REC_MIN,
                CalypsoCardConstant::NB_REC_MAX,
                "fromRecordNumber")
            .isInRange(
                toRecordNumber,
                fromRecordNumber,
                CalypsoCardConstant::NB_REC_MAX,
                "toRecordNumber")
            .isInRange(
                offset,
                CalypsoCardConstant::OFFSET_MIN,
                CalypsoCardConstant::OFFSET_MAX,
                MSG_OFFSET)
            .isInRange(
                nbBytesToRead,
                CalypsoCardConstant::DATA_LENGTH_MIN,
                getPayloadCapacity(),
                "nbBytesToRead");

        const int nbRecordsPerApdu = getPayloadCapacity() / nbBytesToRead;

        int currentRecordNumber = fromRecordNumber;

        while (currentRecordNumber <= toRecordNumber) {
            mCommands.push_back(
                std::make_shared<CommandReadRecordMultiple>(
                    getTransactionContext(),
                    getCommandContext(),
                    sfi,
                    currentRecordNumber,
                    offset,
                    nbBytesToRead));
            currentRecordNumber += nbRecordsPerApdu;
        }

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareReadBinary(
    std::uint8_t sfi, int offset, int nbBytesToRead)
{
    try {
        if (mCard->getProductType()
            != CalypsoCard::ProductType::PRIME_REVISION_3) {
            if (mCard->getProductType()
                == CalypsoCard::ProductType::PRIME_REVISION_2) {
                mLogger->warn(
                    std::string("Command may not be supported for ")
                    + "PRIME_REVISION_2 card: Read Binary");
            } else {
                throw UnsupportedOperationException(
                    "'Read Binary' command is not available for this card");
            }
        }

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
                MSG_OFFSET)
            .greaterOrEqual(nbBytesToRead, 1, "nbBytesToRead");

        if (sfi > 0 && offset > 255) {
            /*
             * Tips to select the file: add a "Read Binary" command (read one
             * byte at offset 0).
             */
            mCommands.push_back(
                std::make_shared<CommandReadBinary>(
                    getTransactionContext(), getCommandContext(), sfi, 0, 1));
        }

        int currentOffset = offset;
        int nbBytesRemainingToRead = nbBytesToRead;

        do {
            int currentLength
                = std::min(nbBytesRemainingToRead, getPayloadCapacity());

            mCommands.push_back(
                std::make_shared<CommandReadBinary>(
                    getTransactionContext(),
                    getCommandContext(),
                    sfi,
                    currentOffset,
                    currentLength));

            currentOffset += currentLength;
            nbBytesRemainingToRead -= currentLength;

        } while (nbBytesRemainingToRead > 0);

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareReadCounter(
    std::uint8_t sfi, int nbCountersToRead)
{
    return prepareReadRecords(sfi, 1, 1, nbCountersToRead * 3);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareSearchRecords(
    std::shared_ptr<SearchCommandData> data)
{
    try {
        if (mCard->getProductType()
            != CalypsoCard::ProductType::PRIME_REVISION_3) {
            throw UnsupportedOperationException(
                std::string("'Search Record Multiple' command is not available")
                + " for this card");
        }

        Assert::getInstance().notNull(data, "data");

        auto dataAdapter
            = std::dynamic_pointer_cast<DtoAdapters::SearchCommandDataAdapter>(
                data);
        if (!dataAdapter) {
            throw IllegalArgumentException(
                "Cannot cast 'data' to SearchCommandDataAdapter. Actual type: "
                /* FIXME? + data->getClass().getName()*/);
        }

        if (getCommandContext()->isSecureSessionOpen()) {
            throw IllegalStateException(MSG_SECURE_SESSION_OPEN);
        }

        Assert::getInstance()
            .isInRange(
                static_cast<int>(dataAdapter->getSfi()),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                dataAdapter->getRecordNumber(),
                CalypsoCardConstant::NB_REC_MIN,
                CalypsoCardConstant::NB_REC_MAX,
                "startAtRecord")
            .isInRange(
                dataAdapter->getOffset(),
                CalypsoCardConstant::OFFSET_MIN,
                CalypsoCardConstant::OFFSET_MAX,
                MSG_OFFSET)
            .isInRange(
                dataAdapter->getSearchData().size(),
                CalypsoCardConstant::DATA_LENGTH_MIN,
                getPayloadCapacity(),
                "searchData");
        if (dataAdapter->getMask().size() != 0) {
            Assert::getInstance().isInRange(
                dataAdapter->getMask().size(),
                CalypsoCardConstant::DATA_LENGTH_MIN,
                dataAdapter->getSearchData().size(),
                "mask");
        }

        mCommands.push_back(
            std::make_shared<CommandSearchRecordMultiple>(
                getTransactionContext(), getCommandContext(), dataAdapter));
    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareCheckPinStatus()
{
    try {
        if (!mCard->isPinFeatureAvailable()) {
            throw UnsupportedOperationException(MSG_PIN_NOT_AVAILABLE);
        }

        mCommands.push_back(
            std::make_shared<CommandVerifyPin>(
                getTransactionContext(), getCommandContext()));
    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareAppendRecord(
    std::uint8_t sfi, const std::vector<std::uint8_t>& recordData)
{
    try {
        Assert::getInstance()
            .isInRange(
                static_cast<int>(sfi),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                recordData.size(),
                0,
                getPayloadCapacity(),
                MSG_RECORD_DATA_LENGTH);

        auto command = std::make_shared<CommandAppendRecord>(
            getTransactionContext(), getCommandContext(), sfi, recordData);
        prepareNewSecureSessionIfNeeded(command);
        mCommands.push_back(command);

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareUpdateRecord(
    std::uint8_t sfi,
    int recordNumber,
    const std::vector<std::uint8_t>& recordData)
{
    try {
        Assert::getInstance()
            .isInRange(
                static_cast<int>(sfi),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                recordNumber,
                CalypsoCardConstant::NB_REC_MIN,
                CalypsoCardConstant::NB_REC_MAX,
                MSG_RECORD_NUMBER)
            .isInRange(
                recordData.size(),
                0,
                getPayloadCapacity(),
                MSG_RECORD_DATA_LENGTH);

        auto command = std::make_shared<CommandUpdateRecord>(
            getTransactionContext(),
            getCommandContext(),
            sfi,
            recordNumber,
            recordData);
        prepareNewSecureSessionIfNeeded(command);
        mCommands.push_back(command);

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareWriteRecord(
    std::uint8_t sfi,
    int recordNumber,
    const std::vector<std::uint8_t>& recordData)
{
    try {
        Assert::getInstance()
            .isInRange(
                static_cast<int>(sfi),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                recordNumber,
                CalypsoCardConstant::NB_REC_MIN,
                CalypsoCardConstant::NB_REC_MAX,
                MSG_RECORD_NUMBER)
            .isInRange(
                recordData.size(),
                0,
                getPayloadCapacity(),
                MSG_RECORD_DATA_LENGTH);
        auto command = std::make_shared<CommandWriteRecord>(
            getTransactionContext(),
            getCommandContext(),
            sfi,
            recordNumber,
            recordData);
        prepareNewSecureSessionIfNeeded(command);
        mCommands.push_back(command);

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareUpdateBinary(
    std::uint8_t sfi, int offset, const std::vector<std::uint8_t>& data)
{
    return prepareUpdateOrWriteBinary(true, sfi, offset, data);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareWriteBinary(
    std::uint8_t sfi, int offset, const std::vector<std::uint8_t>& data)
{
    return prepareUpdateOrWriteBinary(false, sfi, offset, data);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareUpdateOrWriteBinary(
    bool isUpdateCommand,
    std::uint8_t sfi,
    int offset,
    const std::vector<std::uint8_t>& data)
{
    try {
        if (mCard->getProductType()
            != CalypsoCard::ProductType::PRIME_REVISION_3) {
            if (mCard->getProductType()
                == CalypsoCard::ProductType::PRIME_REVISION_2) {
                mLogger->warn(
                    std::string("Command may not be supported for ")
                    + "PRIME_REVISION_2 card: Update/Write Binary");
            } else {
                throw UnsupportedOperationException(
                    std::string("'Update/Write Binary' command is not ")
                    + "available for this card");
            }
        }

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
                MSG_OFFSET)
            .notEmpty(data, "data");

        if (sfi > 0 && offset > 255) {
            /*
             * Tips to select the file: add a "Read Binary" command (read one
             * byte at offset 0).
             */
            mCommands.push_back(
                std::make_shared<CommandReadBinary>(
                    getTransactionContext(), getCommandContext(), sfi, 0, 1));
        }

        const int dataLength = data.size();
        int currentOffset = offset;
        int currentIndex = 0;

        do {
            int currentLength
                = std::min(dataLength - currentIndex, getPayloadCapacity());

            auto command = std::make_shared<CommandUpdateOrWriteBinary>(
                isUpdateCommand,
                getTransactionContext(),
                getCommandContext(),
                sfi,
                currentOffset,
                Arrays::copyOfRange(
                    data, currentIndex, currentIndex + currentLength));
            prepareNewSecureSessionIfNeeded(command);
            mCommands.push_back(command);

            currentOffset += currentLength;
            currentIndex += currentLength;

        } while (currentIndex < dataLength);

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareIncreaseCounter(
    std::uint8_t sfi, int counterNumber, int incValue)
{
    return prepareIncreaseOrDecreaseCounter(
        false, sfi, counterNumber, incValue);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareIncreaseCounters(
    std::uint8_t sfi, const std::map<int, int>& counterNumberToIncValueMap)
{
    return prepareIncreaseOrDecreaseCounters(
        false, sfi, counterNumberToIncValueMap);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareDecreaseCounter(
    std::uint8_t sfi, int counterNumber, int decValue)
{
    return prepareIncreaseOrDecreaseCounter(true, sfi, counterNumber, decValue);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareDecreaseCounters(
    std::uint8_t sfi, const std::map<int, int>& counterNumberToDecValueMap)
{
    return prepareIncreaseOrDecreaseCounters(
        true, sfi, counterNumberToDecValueMap);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareSetCounter(
    std::uint8_t sfi, int counterNumber, int newValue)
{
    try {
        std::shared_ptr<int> oldValue = nullptr;
        std::shared_ptr<ElementaryFile> ef = mCard->getFileBySfi(sfi);
        if (ef != nullptr) {
            oldValue = ef->getData()->getContentAsCounterValue(
                counterNumber != 0 ? counterNumber : 1);
        }
        if (oldValue == nullptr) {
            throw IllegalStateException(
                std::string("The counter value is not available. SFI: ")
                + std::to_string(sfi)
                + ", Counter: " + std::to_string(counterNumber));
        }

        int delta = newValue - *oldValue.get();
        if (delta > 0) {
            mLogger->trace(
                "Increment counter #% (file %h) from % to %\n",
                counterNumber,
                HexUtil::toHex(sfi),
                newValue - delta,
                newValue);
            prepareIncreaseCounter(sfi, counterNumber, delta);

        } else if (delta < 0) {
            mLogger->trace(
                "Decrement counter #% (file %h) from % to %",
                counterNumber,
                HexUtil::toHex(sfi),
                newValue - delta,
                newValue);
            prepareDecreaseCounter(sfi, counterNumber, -delta);

        } else {
            mLogger->debug(
                "Counter #% (sfi %h) already set to the desired value %\n",
                counterNumber,
                HexUtil::toHex(sfi),
                newValue);
        }

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareIncreaseOrDecreaseCounter(
    bool isDecreaseCommand,
    std::uint8_t sfi,
    int counterNumber,
    int incDecValue)
{
    try {
        Assert::getInstance()
            .isInRange(
                static_cast<int>(sfi),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                counterNumber,
                0,  // Allows simulated counters
                getPayloadCapacity() / 3,
                "counterNumber")
            .isInRange(
                incDecValue,
                CalypsoCardConstant::CNT_VALUE_MIN,
                CalypsoCardConstant::CNT_VALUE_MAX,
                "incDecValue");

        auto command = std::make_shared<CommandIncreaseOrDecrease>(
            isDecreaseCommand,
            getTransactionContext(),
            getCommandContext(),
            sfi,
            counterNumber,
            incDecValue);
        prepareNewSecureSessionIfNeeded(command);
        mCommands.push_back(command);

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareIncreaseOrDecreaseCounters(
    bool isDecreaseCommand,
    std::uint8_t sfi,
    const std::map<int, int>& counterNumberToIncDecValueMap)
{
    try {
        Assert::getInstance()
            .isInRange(
                static_cast<int>(sfi),
                CalypsoCardConstant::SFI_MIN,
                CalypsoCardConstant::SFI_MAX,
                "sfi")
            .isInRange(
                counterNumberToIncDecValueMap.size(),
                1,
                getPayloadCapacity() / 3,
                "counterNumberToIncDecValueMap");

        for (const auto& entry : counterNumberToIncDecValueMap) {
            Assert::getInstance()
                .isInRange(
                    entry.first,
                    CalypsoCardConstant::NUM_CNT_MIN,
                    getPayloadCapacity() / 3,
                    "counterNumberToIncDecValueMapKey")
                .isInRange(
                    entry.second,
                    CalypsoCardConstant::CNT_VALUE_MIN,
                    CalypsoCardConstant::CNT_VALUE_MAX,
                    "counterNumberToIncDecValueMapValue");
        }

        if (mCard->getProductType()
                != CalypsoCard::ProductType::PRIME_REVISION_3
            && mCard->getProductType()
                   != CalypsoCard::ProductType::PRIME_REVISION_2) {
            for (const auto& entry : counterNumberToIncDecValueMap) {
                if (isDecreaseCommand) {
                    prepareDecreaseCounter(sfi, entry.first, entry.second);

                } else {
                    prepareIncreaseCounter(sfi, entry.first, entry.second);
                }
            }

        } else {
            const int nbCountersPerApdu = getPayloadCapacity() / 4;
            if (static_cast<int>(counterNumberToIncDecValueMap.size())
                <= nbCountersPerApdu) {
                auto command
                    = std::make_shared<CommandIncreaseOrDecreaseMultiple>(
                        isDecreaseCommand,
                        getTransactionContext(),
                        getCommandContext(),
                        sfi,
                        counterNumberToIncDecValueMap);

                prepareNewSecureSessionIfNeeded(command);
                mCommands.push_back(command);

            } else {
                /*
                 * The number of counters exceeds the payload capacity, let's
                 * split into several apdu commands
                 */
                int i = 0;
                std::map<int, int> map;
                for (const auto& entry : counterNumberToIncDecValueMap) {
                    i++;
                    map[entry.first] = entry.second;
                    if (i == nbCountersPerApdu) {
                        auto command = std::make_shared<
                            CommandIncreaseOrDecreaseMultiple>(
                            isDecreaseCommand,
                            getTransactionContext(),
                            getCommandContext(),
                            sfi,
                            map);

                        prepareNewSecureSessionIfNeeded(command);
                        mCommands.push_back(command);
                        i = 0;
                        map.clear();
                    }
                }
                if (!map.empty()) {
                    auto command
                        = std::make_shared<CommandIncreaseOrDecreaseMultiple>(
                            isDecreaseCommand,
                            getTransactionContext(),
                            getCommandContext(),
                            sfi,
                            map);

                    prepareNewSecureSessionIfNeeded(command);
                    mCommands.push_back(command);
                }
            }
        }

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareSvReadAllLogs()
{
    try {
        if (!mCard->isSvFeatureAvailable()) {
            throw UnsupportedOperationException(
                "Stored Value is not available for this card");
        }

        if (mCard->getApplicationSubtype()
            != CalypsoCardConstant::STORED_VALUE_FILE_STRUCTURE_ID) {
            throw UnsupportedOperationException(
                "The currently selected application is not an SV application");
        }

        /* Reset SV data in CalypsoCard if any */
        const std::vector<std::uint8_t> empty;
        mCard->setSvData((std::uint8_t)0, empty, empty, 0, 0);
        prepareReadRecords(
            CalypsoCardConstant::SV_RELOAD_LOG_FILE_SFI,
            1,
            CalypsoCardConstant::SV_RELOAD_LOG_FILE_NB_REC,
            CalypsoCardConstant::SV_LOG_FILE_REC_LENGTH);
        prepareReadRecords(
            CalypsoCardConstant::SV_DEBIT_LOG_FILE_SFI,
            1,
            CalypsoCardConstant::SV_DEBIT_LOG_FILE_NB_REC,
            CalypsoCardConstant::SV_LOG_FILE_REC_LENGTH);

    } catch (...) {
        resetTransaction();
        throw;
    }

    return dynamic_cast<T&>(*this);
}

template <typename T>
T&
TransactionManagerAdapter<T>::prepareGenerateAsymmetricKeyPair()
{
    if (!mCard->isPkiModeSupported()) {
        throw UnsupportedOperationException(
            MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD);
    }

    if (getTransactionContext()->isSecureSessionOpen()) {
        throw IllegalStateException(MSG_SECURE_SESSION_OPEN);
    }

    mCommands.push_back(
        std::unique_ptr<CommandGenerateAsymmetricKeyPair>(
            new CommandGenerateAsymmetricKeyPair(
                getTransactionContext(), getCommandContext())));

    return dynamic_cast<T&>(*this);
}

template <typename T>
const std::vector<std::vector<std::uint8_t>>&
TransactionManagerAdapter<T>::getTransactionAuditData() const
{
    /* CL-CSS-INFODATA.1 */
    return mTransactionAuditData;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

/* Explicit template instantiations for concrete transaction manager bases */
#include "keypop/calypso/card/cpp/SecureExtendedModeTransactionManagerBase.hpp"
#include "keypop/calypso/card/cpp/SecureRegularModeTransactionManagerBase.hpp"
#include "keypop/calypso/card/transaction/FreeTransactionManager.hpp"
#include "keypop/calypso/card/transaction/SecurePkiModeTransactionManager.hpp"

template class keyple::card::calypso::TransactionManagerAdapter<
    keypop::calypso::card::transaction::FreeTransactionManager>;

template class keyple::card::calypso::TransactionManagerAdapter<
    keypop::calypso::card::cpp::SecureExtendedModeTransactionManagerBase>;

template class keyple::card::calypso::TransactionManagerAdapter<
    keypop::calypso::card::cpp::SecureRegularModeTransactionManagerBase>;

template class keyple::card::calypso::TransactionManagerAdapter<
    keypop::calypso::card::transaction::SecurePkiModeTransactionManager>;
