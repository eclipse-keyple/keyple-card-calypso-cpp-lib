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
 * Builds the "Increase/Decrease Multiple" APDU command.
 *
 * @since 2.1.0
 */
class CommandIncreaseOrDecreaseMultiple final : public Command {
public:
    /**
     * Constructor.
     *
     * @param isDecreaseCommand True if it is a "Decrease Multiple" command,
     * false if it is an "Increase Multiple" command.
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param sfi The SFI.
     * @param counterNumberToIncDecValueMap The map containing the counter
     * numbers to be incremented and their associated increment values.
     * @since 2.1.0
     */
    CommandIncreaseOrDecreaseMultiple(
        bool isDecreaseCommand,
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        std::uint8_t sfi,
        const std::map<int, int>& counterNumberToIncDecValueMap);

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
    const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandIncreaseOrDecreaseMultiple));

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    const std::uint8_t mSfi;

    /**
     *
     */
    const std::map<int, int> mCounterNumberToIncDecValueMap;

    /**
     * Builds the anticipated APDU response with the SW.
     *
     * @return A not empty byte array.
     * @throw IllegalStateException If some expected counters have not been read
     * beforehand.
     * @since 2.3.2
     */
    std::vector<std::uint8_t> buildAnticipatedResponse();

    /**
     * Gets the value of all counters currently presents in the card image.
     *
     * @return A not empty map.
     * @throws IllegalStateException If some expected counters have not been
     * read beforehand.
     */
    std::map<const int, const int> getOldCounterValues();
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
