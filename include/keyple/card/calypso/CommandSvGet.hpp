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
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/calypso/card/transaction/SvOperation.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::calypso::card::transaction::SvOperation;

/**
 * Builds the SV Get command.
 *
 * @since 2.0.1
 */
class CommandSvGet final : public Command {
public:
    /**
     * Instantiates a new CommandSvGet.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param svOperation the desired SV operation.
     * @param useExtendedMode True if the extended mode must be used.
     * @throw IllegalArgumentException If the command is inconsistent
     * @since 2.3.2
     */
    CommandSvGet(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        SvOperation svOperation,
        bool useExtendedMode);

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
     * Parses the proprietary information and updates the corresponding Calypso
     * card.
     *
     * @param dataOut The dataOut block to parse.
     * @param calypsoCard The Calypso card to update.
     * @since 2.2.3
     */
    static void parseProprietaryInformation(
        const std::vector<std::uint8_t>& dataOut,
        std::shared_ptr<CalypsoCardAdapter> calypsoCard);

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandSvGet));

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    std::vector<std::uint8_t> mHeader;

    /**
     *
     */
    static int computeExpectedResponseLength(
        SvOperation svOperation, bool useExtendedMode);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
