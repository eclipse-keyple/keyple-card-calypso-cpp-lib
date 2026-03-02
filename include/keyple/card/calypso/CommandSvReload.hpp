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

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"

namespace keyple {
namespace card {
namespace calypso {

/**
 * Builds the SV Reload command.
 *
 * <p>See specs: Calypso Stored Value balance (signed binaries' coding based on
 * the two's complement method)
 *
 * <p>balance - 3 bytes signed binary - Integer from -8,388,608 to 8,388,607
 *
 * <p>amount for reload, 3 bytes signed binary - Integer from -8,388,608 to
 * 8,388,607
 *
 * <pre>
 * -8,388,608           %10000000.00000000.00000000
 * -8,388,607           %10000000.00000000.00000001
 * -8,388,606           %10000000.00000000.00000010
 *
 * -3           %11111111.11111111.11111101
 * -2           %11111111.11111111.11111110
 * -1           %11111111.11111111.11111111
 * 0           %00000000.00000000.00000000
 * 1           %00000000.00000000.00000001
 * 2           %00000000.00000000.00000010
 * 3           %00000000.00000000.00000011
 *
 * 8,388,605           %01111111.11111111.11111101
 * 8,388,606           %01111111.11111111.11111110
 * 8,388,607           %01111111.11111111.11111111
 * </pre>
 *
 * @since 2.0.1
 */
class CommandSvReload final : public Command {
public:
    /**
     *
     */
    static const std::string MSG_CARD_SV_MAC_NOT_VERIFIABLE;

    /**
     * Instantiates a new CommandSvReload.
     *
     * <p>The process is carried out in two steps: first to check and store the
     * card and application data, then to create the final APDU with the data
     * from the SAM (see finalizeCommand).
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param amount amount to debit (signed integer from -8388608 to 8388607).
     * @param date debit date (not checked by the card).
     * @param time debit time (not checked by the card).
     * @param free 2 free bytes stored in the log but not processed by the card.
     * @param isExtendedModeAllowed True if the extended mode is allowed.
     * @throw IllegalArgumentException If the command is inconsistent
     * @since 2.3.2
     */
    CommandSvReload(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        int amount,
        const std::vector<std::uint8_t>& date,
        const std::vector<std::uint8_t>& time,
        const std::vector<std::uint8_t>& free,
        bool isExtendedModeAllowed);

    /**
     * Complete the construction of the APDU to be sent to the card with the
     * elements received from the SAM:
     * <p>4-byte SAM id
     * <p>3-byte challenge
     * <p>3-byte transaction number
     * <p>5 or 10 byte signature (hi part)
     *
     * @param svCommandSecurityData the sam id and the data out from the
     * SvPrepareReload SAM command.
     * @since 2.0.1
     */
    void finalizeCommand(
        std::shared_ptr<DtoAdapters::SvCommandSecurityDataApiAdapter>
            svCommandSecurityData);

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
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<int, const std::shared_ptr<StatusProperties>>&
    getStatusTable() const override;

    /**
     * Gets the SV Reload part of the data to include in the SAM SV Prepare Load
     * command
     *
     * @return a byte array containing the SV reload data
     * @since 2.0.1
     */
    std::vector<std::uint8_t> getSvReloadData();

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandSvReload));

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    static const std::string MSG_INVALID_CARD_SESSION_MAC;

    /**
     *
     */
    static const int SW_POSTPONED_DATA;

    /**
     *
     */
    const int mAmount;

    /**
     *
     */
    const bool mIsExtendedModeAllowed;

    /**
     * Apdu data array.
     */
    std::vector<std::uint8_t> mDataIn;

    /**
     *
     */
    static int computeExpectedResponseLength(
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        bool isExtendedModeAllowed);

    /**
     *
     */
    static std::unique_ptr<std::uint8_t> computeLe(
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        bool isExtendedModeAllowed);

    /**
     * Updates the Calypso card with the SV Reload data to update the SV
     * balance and the SV reload log.
     *
     *  @param calypsoCard The Calypso card.
     */
    void
    updateCalypsoCardSvHistory(std::shared_ptr<CalypsoCardAdapter> calypsoCard);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
