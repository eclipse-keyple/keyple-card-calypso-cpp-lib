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

#pragma once

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/calypso/card/GetDataTag.hpp"
#include "keypop/calypso/card/PutDataTag.hpp"
#include "keypop/calypso/card/SelectFileControl.hpp"
#include "keypop/calypso/card/transaction/TransactionManager.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/ProxyReaderApi.hpp"
#include "keypop/card/spi/CardRequestSpi.hpp"
#include "keypop/reader/ChannelControl.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::calypso::card::GetDataTag;
using keypop::calypso::card::PutDataTag;
using keypop::calypso::card::SelectFileControl;
using keypop::calypso::card::transaction::TransactionManager;
using keypop::card::CardResponseApi;
using keypop::card::ProxyReaderApi;
using keypop::card::spi::CardRequestSpi;
using keypop::reader::ChannelControl;

/**
 * Adapter ofTransactionManager.
 *
 * <ul>
 *   <li>CL-APP-ISOL.1
 *   <li>CL-CMD-SEND.1
 *   <li>CL-CMD-RECV.1
 *   <li>CL-CMD-CASE.1
 *   <li>CL-CMD-LCLE.1
 *   <li>CL-CMD-DATAIN.1
 *   <li>CL-C1-5BYTE.1
 *   <li>CL-C1-MAC.1
 *   <li>CL-C4-LE.1
 *   <li>CL-CLA-CMD.1
 *   <li>CL-RFU-FIELDCMD.1
 *   <li>CL-RFU-VALUECMD.1
 *   <li>CL-RFU-FIELDRSP.1
 *   <li>CL-SW-ANALYSIS.1
 *   <li>CL-SW-SUCCESS.1
 *   <li>CL-SF-SFI.1
 *   <li>CL-PERF-HFLOW.1
 *   <li>CL-CSS-INFOEND.1
 *   <li>CL-SW-CHECK.1
 *   <li>CL-CSS-SMEXCEED.1
 *   <li>CL-CSS-6D006E00.1
 *   <li>CL-CSS-UNEXPERR.1
 *   <li>CL-CSS-INFOCSS.1
 *   <li>CL-CSS-OSSMODE.1
 *   <li>CL-SV-CMDMODE.1
 * </ul>
 *
 * @param <T> The type of the lowest level child object.
 * @since 3.0.0
 */
template <typename T>
class TransactionManagerAdapter : public virtual TransactionManager<T> {
public:
    /**
     * Builds a new instance.
     *
     * @param cardReader The card reader to be used.
     * @param card The selected card on which to operate the transaction.
     * @since 3.0.0
     */
    TransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> cardReader,
        std::shared_ptr<CalypsoCardAdapter> card);

    /**
     * Returns the transaction context.
     *
     * @return A non-null reference.
     * @since 3.0.0
     */
    virtual std::shared_ptr<DtoAdapters::TransactionContextDto>
    getTransactionContext() const = 0;

    /**
     * @return The current command context as a new DTO instance containing a
     * reference to the global transaction context.
     * @since 3.0.0
     */
    virtual std::shared_ptr<DtoAdapters::CommandContextDto>
    getCommandContext() const = 0;

    /**
     * Returns the payload capacity.
     *
     * @return A positive value.
     * @since 3.0.0
     */
    virtual int getPayloadCapacity() const = 0;

    /**
     * Resets the transaction fields and try to cancel silently the current
     * secure session if opened, without raising any exception.
     *
     * @since 3.0.0
     */
    virtual void resetTransaction() = 0;

    /**
     * Closes and opens a new secure session if the three following conditions
     * are satisfied:
     *
     * <ul>
     *   <li>a secure session is open
     *   <li>the command will overflow the modifications buffer size
     *   <li>the multiple session mode is allowed
     * </ul>
     *
     * @param command The command.
     * @throw SessionBufferOverflowException If the command will overflow the
     * modifications buffer size and the multiple session is not allowed.
     * @since 3.0.0
     */
    virtual void
    prepareNewSecureSessionIfNeeded(const std::shared_ptr<Command>& command)
        = 0;

    /**
     * @return True if it is possible to configure the auto read record into the
     * open secure session command.
     * @since 3.0.0
     */
    virtual bool canConfigureReadOnOpenSecureSession() const = 0;

    /**
     * Executes the provided commands.
     *
     * @param commands The commands.
     * @param channelControl The channel control directive.
     * @since 3.0.0
     */
    void executeCardCommands(
        const std::vector<std::shared_ptr<Command>>& commands,
        ChannelControl channelControl);

    /**
     * Parses the command's response.
     *
     * @param command The command.
     * @param apduResponse The response from the card.
     * @throw CardCommandException If there is an error in the card command.
     * @since 3.1.0
     */
    virtual void parseCommandResponse(
        const std::shared_ptr<Command>& command,
        const std::shared_ptr<ApduResponseApi>& apduResponse);

    /**
     * Handles the post-processing of a command based on its index and the list
     * of commands.
     *
     * @param commandIndex the index of the command in the list to be processed
     * @param commands the list of commands to be post-processed
     * @since 3.2.1
     */
    virtual void handleCommandPostProcessing(
        int commandIndex,
        const std::vector<std::shared_ptr<Command>>& commands);

    /**
     * Returns a string representation of the transaction audit data.
     *
     * @return A non-empty string.
     * @since 3.0.0
     */
    std::string getTransactionAuditDataAsString() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareSelectFile(std::uint16_t lid) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareSelectFile(SelectFileControl selectFileControl) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareGetData(GetDataTag tag) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    T& preparePutData(
        PutDataTag putDataTag, const std::vector<std::uint8_t>& data) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareReadRecord(std::uint8_t sfi, int recordNumber) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareReadRecords(
        std::uint8_t sfi,
        int fromRecordNumber,
        int toRecordNumber,
        int recordSize) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareReadRecordsPartially(
        std::uint8_t sfi,
        int fromRecordNumber,
        int toRecordNumber,
        int offset,
        int nbBytesToRead) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareReadBinary(std::uint8_t sfi, int offset, int nbBytesToRead) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareReadCounter(std::uint8_t sfi, int nbCountersToRead) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareSearchRecords(std::shared_ptr<SearchCommandData> data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareCheckPinStatus() final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareAppendRecord(
        std::uint8_t sfi, const std::vector<std::uint8_t>& recordData) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareUpdateRecord(
        std::uint8_t sfi,
        int recordNumber,
        const std::vector<std::uint8_t>& recordData) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareWriteRecord(
        std::uint8_t sfi,
        int recordNumber,
        const std::vector<std::uint8_t>& recordData) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareUpdateBinary(
        std::uint8_t sfi,
        int offset,
        const std::vector<std::uint8_t>& data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareWriteBinary(
        std::uint8_t sfi,
        int offset,
        const std::vector<std::uint8_t>& data) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareIncreaseCounter(
        std::uint8_t sfi, int counterNumber, int incValue) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareIncreaseCounters(
        std::uint8_t sfi,
        const std::map<int, int>& counterNumberToIncValueMap) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareDecreaseCounter(
        std::uint8_t sfi, int counterNumber, int decValue) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    T& prepareDecreaseCounters(
        std::uint8_t sfi,
        const std::map<int, int>& counterNumberToDecValueMap) final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T&
    prepareSetCounter(std::uint8_t sfi, int counterNumber, int newValue) final;

    /**
     * Factorisation of prepareDecreaseCounter and prepareIncreaseCounter.
     *
     * @param isDecreaseCommand True if is a decrease command, False if is an
     * increase command.
     * @param sfi SFI of the EF to select.
     * @param counterNumber The number of the counter (must be zero in case of a
     * simulated counter).
     * @param incDecValue Value to increment/decrement to the counter (defined
     * as a positive int <= 16777215 [FFFFFFh])
     * @return The current instance.
     * @since 3.0.0
     */
    T& prepareIncreaseOrDecreaseCounter(
        bool isDecreaseCommand,
        std::uint8_t sfi,
        int counterNumber,
        int incDecValue);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    T& prepareSvReadAllLogs() final;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    T& prepareGenerateAsymmetricKeyPair() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::vector<std::vector<std::uint8_t>>&
    getTransactionAuditData() const final;

protected:
    /* Dynamic fields */
    std::vector<std::shared_ptr<Command>> mCommands;

    std::shared_ptr<CalypsoCardAdapter> mCard;

protected:
    /**
     * Note: private in Java.
     */
    std::shared_ptr<ProxyReaderApi> mCardReader;

private:
    const std::shared_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(TransactionManagerAdapter));

    /* Prefix/suffix used to compose exception messages */
    static const std::string
        MSG_THE_NUMBER_OF_COMMANDS_RESPONSES_DOES_NOT_MATCH_EXPECTED;
    static const std::string MSG_RESPONSES_GOT;
    static const std::string MSG_CARD_READER_COMMUNICATION_ERROR;
    static const std::string MSG_CARD_COMMUNICATION_ERROR;
    static const std::string MSG_WHILE_TRANSMITTING_COMMANDS;
    static const std::string MSG_PIN_NOT_AVAILABLE;
    static const std::string MSG_RECORD_NUMBER;
    static const std::string MSG_OFFSET;
    static const std::string MSG_RECORD_DATA;
    static const std::string MSG_RECORD_DATA_LENGTH;
    static const std::string MSG_SECURE_SESSION_OPEN;
    static const std::string MSG_PKI_MODE_IS_NOT_AVAILABLE_FOR_THIS_CARD;
    static const std::string MSG_DATA_LENGTH;

    /**
     *
     */
    std::vector<std::vector<std::uint8_t>> mTransactionAuditData;

    /**
     * Creates a list of ApduRequestSpi from a list of Command.
     *
     * @param commands The list of commands.
     * @return An empty list if there is no command.
     * @since 2.2.0
     */
    std::vector<std::shared_ptr<ApduRequestSpi>>
    getApduRequests(const std::vector<std::shared_ptr<Command>>& commands);

    /**
     * Transmits a card request, processes and converts any exceptions.
     *
     * @param cardRequest The card request to transmit.
     * @param channelControl The channel control.
     * @return The card response.
     */
    std::shared_ptr<CardResponseApi> transmitCardRequest(
        std::shared_ptr<CardRequestSpi> cardRequest,
        ChannelControl channelControl);

    /**
     * Maps a ChannelControl provided by the Calypso layer to a ChannelControl
     * provided by the Card layer.
     *
     * @param channelControl The ChannelControl provided by the Calypso layer.
     * @return The corresponding ChannelControl provided by the Card layer.
     */
    keypop::card::ChannelControl
    mapToInternalChannelControl(ChannelControl channelControl) const;

    /**
     * Saves the provided exchanged APDU commands in the list of transaction
     * audit data.
     *
     * @param cardRequest The card request.
     * @param cardResponse The associated card response.
     */
    void saveTransactionAuditData(
        const std::shared_ptr<CardRequestSpi>& cardRequest,
        const std::shared_ptr<CardResponseApi>& cardResponse);

    /** */
    void preparePutDataCardKeyPair(
        PutDataTag putDataTag, const std::vector<std::uint8_t>& data);

    /** */
    void preparePutDataCertificate(
        PutDataTag putDataTag,
        const std::vector<std::uint8_t>& data,
        int certificateSize);

    /**
     * Prepare an "Update/Write Binary" command.
     *
     * @param isUpdateCommand True if it is an "Update Binary" command, false i
     *  it is a "Write Binary" command.
     * @param sfi The SFI.
     * @param offset The offset.
     * @param data The data to update/write.
     * @return The current instance.
     */
    T& prepareUpdateOrWriteBinary(
        bool isUpdateCommand,
        std::uint8_t sfi,
        int offset,
        const std::vector<std::uint8_t>& data);

    /**
     * Factorisation of prepareDecreaseMultipleCounters and
     * prepareIncreaseMultipleCounters.
     *
     * @param isDecreaseCommand True if is a decrease command, False if is an
     * increase command.
     * @param sfi SFI of the EF to select.
     * @param counterNumberToIncDecValueMap The map containing the counter
     * numbers to be incremented/decremented and their associated
     * increment/decrement values.
     * @return The current instance.
     */
    T& prepareIncreaseOrDecreaseCounters(
        bool isDecreaseCommand,
        std::uint8_t sfi,
        const std::map<int, int>& counterNumberToIncDecValueMap);
};

template <typename T>
class TransactionManagerAdapter<TransactionManager<T>> {
public:
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
