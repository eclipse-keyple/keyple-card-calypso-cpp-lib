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

#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;

/**
 * Builds the Close Secure Session APDU command.
 *
 * @since 2.0.1
 */
class CommandCloseSecureSession final : public Command {
public:
    /**
     * Constructor.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param isAutoRatificationAsked "true" if the auto ratification is asked.
     * @param svPostponedDataIndex The index of the SV postponed data or -1 if
     * there is no SV postponed data.
     * @since 2.3.2
     */
    CommandCloseSecureSession(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        bool isAutoRatificationAsked,
        int svPostponedDataIndex);

    /**
     * Instantiates a new command based on the product type of the card to
     * generate either an "Abort Secure Session" command or a "Close Secure
     * Session" in PKI mode.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param context The command context.
     * @param isAbort true for creating an abort session command.
     * @since 2.3.2
     */
    CommandCloseSecureSession(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        bool isAbort);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool isCryptoServiceRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool synchronizeCryptoServiceBeforeCardProcessing() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * Increments the index of the SV postponed data by one.
     *
     * <p>This method updates the value of the mSvPostponedDataIndex field,
     * which represents the current position or index within the collection of
     * postponed data related to SV. This operation is typically used to
     * progress through postponed data elements in sequence.
     *
     * @since 3.2.1
     */
    void incrementSvPostponedDataIndex();

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandCloseSecureSession));

    /**
     *
     */
    static const std::string MSG_CARD_SESSION_MAC_NOT_VERIFIABLE;
    static const std::string MSG_CARD_SV_MAC_NOT_VERIFIABLE;
    static const std::string MSG_INVALID_CARD_SESSION_MAC;
    static const std::string MSG_INVALID_CARD_SESSION_SIGNATURE;

    /**
     *
     */
    static const CardCommandRef mCommandRef;

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    bool mIsAutoRatificationAsked;

    /**
     *
     */
    bool mIsAbortSecureSession;

    /**
     *
     */
    int mSvPostponedDataIndex;

    /**
     * The postponed data.
     */
    std::vector<std::vector<std::uint8_t>> mPostponedData;

    /**
     * Aborts the secure session.
     *
     * @param apduResponse The response from the APDU command.
     */
    void processAbort(std::shared_ptr<ApduResponseApi> apduResponse);

    /**
     * Parses the response in symmetric crypto mode to verify the card MAC.
     *
     * @param responseData The byte array containing the response data.
     */
    void
    parseResponseInSymmetricMode(const std::vector<std::uint8_t>& responseData);

    /**
     * Parses the response in PKI mode to verify the card signature.
     *
     * @param responseData The byte array containing the response data.
     */
    void parseResponseInAsymmetricMode(
        const std::vector<std::uint8_t>& responseData);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
