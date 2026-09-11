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

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CardCommandException.hpp"
#include "keyple/card/calypso/CardCommandRef.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keypop/card/ApduResponseApi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::card::ApduResponseApi;

/**
 * Superclass for all card commands.
 *
 * <p>It provides the generic getters to retrieve:
 *
 * <ul>
 *   <li>the card command reference,
 *   <li>the name of the command,
 *   <li>the built keypop::card::spi::ApduRequestSpi,
 *   <li>the parsed keypop::card::ApduResponseApi.
 * </ul>
 *
 * @since 2.0.1
 */
class Command {
public:
    /**
     * This internal class provides status word properties
     *
     * @since 2.0.1
     */
    class StatusProperties {
    public:
        /**
         * Creates a successful status.
         *
         * @param information the status information.
         * @since 2.0.1
         */
        explicit StatusProperties(const std::string& information);

        /**
         * Creates an error status.<br>
         * If {@code exceptionClass} is null, then a successful status is
         * created.
         *
         * @param information the status information.
         * @param exceptionClass the associated exception class.
         * @since 2.0.1
         */
        StatusProperties(
            const std::string& information,
            const std::type_info& exceptionClass);

        /**
         * Gets information
         *
         * @return A nullable reference
         * @since 2.0.1
         */
        const std::string& getInformation() const;

        /**
         * Gets successful indicator
         *
         * @return The successful indicator
         * @since 2.0.1
         */
        bool isSuccessful() const;

        /**
         * Gets Exception Class
         *
         * @return A nullable reference
         * @since 2.0.1
         */
        const std::type_info& getExceptionClass() const;

    private:
        /** */
        const std::string mInformation;

        /** */
        const bool mSuccessful;

        /** */
        const std::type_info& mExceptionClass;
    };

    /**
     * Constructor dedicated for the building of referenced Calypso commands
     *
     * @param commandRef A command reference from the Calypso command table.
     * @param expectedResponseLength The expected command response length or
     * null if not specified.
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command
     * @since 2.0.1
     */
    Command(
        const CardCommandRef& commandRef,
        std::unique_ptr<int> expectedResponseLength,
        std::shared_ptr<DtoAdapters::TransactionContextDto> transactionContext,
        std::shared_ptr<DtoAdapters::CommandContextDto> commandContext);

    /**
     * Appends a string to the current name.
     *
     * <p>The sub name completes the name of the current command. This method
     * must therefore only be invoked conditionally (log level &gt;= debug).
     *
     * @param subName The string to append.
     * @throw NullPointerException If the request is not set.
     * @since 2.0.1
     */
    void addSubName(const std::string& subName);

    /**
     * Returns the current command identification
     *
     * @return A not null reference.
     * @since 2.0.1
     */
    const CardCommandRef& getCommandRef() const;

    /**
     * Gets the name of this APDU command.
     *
     * @return A not empty string.
     * @since 2.0.1
     */
    const std::string& getName() const;

    /**
     * Sets the command ApduRequestAdapter.
     *
     * @param apduRequest The APDU request.
     * @since 2.0.1
     */
    void setApduRequest(
        std::shared_ptr<DtoAdapters::ApduRequestAdapter> apduRequest);

    /**
     * Sets the command ApduRequestAdapter in "best effort" mode.
     *
     * @param apduRequest The APDU request.
     * @since 3.0.0
     */
    void setApduRequestInBestEffortMode(
        std::shared_ptr<DtoAdapters::ApduRequestAdapter> apduRequest);

    /**
     * Gets the ApduRequestAdapter.
     *
     * @return Null if the request is not set.
     * @since 2.0.1
     */
    std::shared_ptr<DtoAdapters::ApduRequestAdapter> getApduRequest() const;

    /**
     * Gets ApduResponseApi
     *
     * @return Null if the response is not set.
     * @since 2.0.1
     */
    std::shared_ptr<ApduResponseApi> getApduResponse() const;

    /**
     * Returns the transaction context.
     *
     * @return Null if not defined (selection process) or for legacy use
     * (deprecated methods).
     * @since 2.3.2
     */
    std::shared_ptr<DtoAdapters::TransactionContextDto>
    getTransactionContext() const;

    /**
     * Returns the command context.
     *
     * @return Null if not defined (selection process) or for legacy use
     * (deprecated methods).
     * @since 2.3.2
     */
    std::shared_ptr<DtoAdapters::CommandContextDto> getCommandContext() const;

    /**
     * @param expectedResponseLength The expected command response length or
     * null if the expected length is not specified.
     * @since 2.3.2
     */
    void setExpectedResponseLength(std::unique_ptr<int> expectedResponseLength);

    /**
     * Returns the value of the expected length.
     *
     * @return null if expected length is not set.
     * @since 2.3.2
     */
    int* getExpectedResponseLength() const;

    /**
     * Notifies that the crypto service has been synchronized.
     *
     * @since 2.3.2
     */
    void confirmCryptoServiceSuccessfullySynchronized();

    /**
     * @return "true" if the post-processing is already done.
     * @since 2.3.2
     */
    bool isCryptoServiceSynchronized() const;

    /**
     * Finalize the construction of the APDU request if needed (used only with
     * symmetric crypto transactions).
     *
     * @since 2.3.2
     */
    virtual void finalizeRequest() = 0;

    /**
     * @return "true" if the crypto service is required to finalize the
     * construction of the request (used only with symmetric crypto
     * transactions).
     * @since 2.3.2
     */
    virtual bool isCryptoServiceRequiredToFinalizeRequest() const = 0;

    /**
     * Attempts to synchronize the crypto service before executing the finalized
     * command on the card and returns "true" in any of the following cases
     * (used only with symmetric crypto transactions):
     *
     * <ul>
     *   <li>the crypto service is not involved in the process
     *   <li>the crypto service has been correctly synchronized
     *   <li>the crypto service has already been synchronized
     * </ul>
     *
     * @return "false" if the crypto service could not be synchronized before
     * transmitting the commands to the card.
     * @since 2.3.2
     */
    virtual bool synchronizeCryptoServiceBeforeCardProcessing() = 0;

    /**
     * Parses the APDU response, updates the card image and synchronize the
     * crypto service if it is involved in the process.
     *
     * @param apduResponse The APDU response.
     * @throws CardCommandException if status is not successful or if the length
     * of the response is not equal to the LE field in the request.
     * @since 2.3.2
     */
    virtual void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
        = 0;

    /**
     * Sets the Calypso card and invoke the
     * setApduResponseAndCheckStatus(ApduResponseApi) method.
     *
     * @since 2.2.3
     */
    void parseResponseForSelection(
        const std::shared_ptr<ApduResponseApi>& apduResponse,
        std::shared_ptr<CalypsoCardAdapter> calypsoCard);

    /**
     * Updates the terminal session using the parsed APDU response if the
     * encryption is not active. If encryption is enabled in symmetric mode,
     * then the session MAC has already been updated during decryption.
     *
     * @since 2.3.2
     */
    void updateTerminalSessionIfNeeded();

    /**
     * Updates the terminal session MAC using the provided APDU response when
     * needed.
     *
     * @param apduResponse The APDU response to use.
     * @since 2.3.2
     */
    void updateTerminalSessionIfNeeded(
        const std::vector<std::uint8_t>& apduResponse);

    /**
     * Encrypts the APDU request using the crypto service and updates the
     * terminal session MAC if the encryption is active.
     *
     * @since 2.3.2
     */
    void encryptRequestAndUpdateTerminalSessionMacIfNeeded();

    /**
     * Decrypts the provided APDU response using the crypto service and updates
     * the terminal session MAC if the encryption is active.
     *
     * @param apduResponse The APDU response to update.
     * @since 2.3.2
     */
    void decryptResponseAndUpdateTerminalSessionMacIfNeeded(
        std::shared_ptr<ApduResponseApi> apduResponse);

    /**
     * Parses the response and checks the status word.
     *
     * @param apduResponse The APDU response.
     * @throw CardCommandException If status is not successful or if the length
     * of the response is not equal to the expected one.
     * @since 2.0.1
     */
    void setApduResponseAndCheckStatus(
        std::shared_ptr<ApduResponseApi> apduResponse);

    /**
     * Parses the response and checks the status word in "best effort" mode.
     *
     * <p>Do not throwxception for "file not found" and "record not found"
     * errors outside a secure session.
     *
     * @param apduResponse The APDU response.
     * @return "false" in case of "best effort" mode and a "file not found" or a
     * "record not found" error occurs. In this case, the process must be
     * stopped.
     * @throw CardCommandException If status is not successful and a secure
     * session is open or the SW is different of 6A82h and 6A83h, or if the
     * length of the response is not equal to the expected one.
     * @since 2.3.2
     */
    bool setApduResponseAndCheckStatusInBestEffortMode(
        std::shared_ptr<ApduResponseApi> apduResponse);

    /**
     * Returns the internal status table
     *
     * @return A not null reference
     * @since 2.0.1
     */
    virtual const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const;

protected:
    /**
     * This Map stores expected status that could be by default initialized with
     * sw1=90 and sw2=00 (Success)
     *
     * @since 2.0.1
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

protected:
    static const std::vector<std::uint8_t> APDU_RESPONSE_9000;

private:
    /**
     *
     */
    const CardCommandRef mCommandRef;

    /**
     *
     */
    std::shared_ptr<DtoAdapters::CommandContextDto> mCommandContext;

    /**
     *
     */
    std::shared_ptr<DtoAdapters::TransactionContextDto> mTransactionContext;

    /**
     *
     */
    std::unique_ptr<int> mExpectedResponseLength;

    /**
     *
     */
    std::string mName;

    /**
     *
     */
    std::shared_ptr<DtoAdapters::ApduRequestAdapter> mApduRequest;

    /**
     *
     */
    std::shared_ptr<ApduResponseApi> mApduResponse;

    /**
     *
     */
    bool mIsCryptoServiceSynchronized = false;

    /**
     * @return The properties of the result.
     * @throw NullPointerException If the response is not set.
     */
    std::shared_ptr<StatusProperties> getStatusWordProperties() const;

    /**
     * This method check the status word and if the length of the response is
     * equal to the expected one.<br>
     * If status word is not referenced, then status is considered unsuccessful.
     *
     * @throw CardCommandException if status is not successful or if the length
     * of the response is not equal to the LE field in the request.
     */
    void checkStatus();

    /**
     * Throws the specific APDU command exception matching the given class.
     *
     * Throws instead of returning: returning by value would slice the
     * exception down to CardCommandException.
     *
     * @param exceptionClass the exception class.
     * @param message The message.
     * @since 2.0.1
     */
    [[noreturn]] void throwCommandException(
        const std::type_info& exceptionClass, const std::string& message);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
