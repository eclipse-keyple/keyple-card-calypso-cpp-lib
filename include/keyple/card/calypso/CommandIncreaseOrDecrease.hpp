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
 * Builds the Update Record APDU command.
 *
 * @since 2.0.1
 */
class CommandIncreaseOrDecrease final : public Command {
public:
    /**
     * Constructor.
     *
     * @param isDecreaseCommand True if it is a "Decrease" command, false if it
     * is an "Increase" command.
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param sfi SFI of the file to select or 00h for current EF.
     * @param counterNumber &gt;= 01h: Counters file, number of the counter.
     * 00h: Simulated Counter. file.
     * @param incDecValue Value to subtract or add to the counter (defined as a
     * positive int &lt;=16777215 [FFFFFFh])
     * @since 2.3.2
     */
    CommandIncreaseOrDecrease(
        bool isDecreaseCommand,
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        std::uint8_t sfi,
        int counterNumber,
        int incDecValue);

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
        = LoggerFactory::getLogger(typeid(CommandIncreaseOrDecrease));

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     * Construction arguments
     */
    const std::uint8_t mSfi;

    /**
     *
     */
    const int mCounterNumber;

    /**
     *
     */
    const int mIncDecValue;

    /**
     *
     */
    static const int SW_POSTPONED_DATA;

    /**
     * Builds the anticipated APDU response with the SW.
     *
     * @return A not empty byte array.
     * @throws IllegalStateException If the counter has not been read
     * beforehand.
     * @since 2.3.2
     */
    std::vector<std::uint8_t> buildAnticipatedResponse();

    /**
     * Builds the anticipated value of the APDU DataOut field.
     *
     * @return A 3-byte byte array.
     * @throw IllegalStateException If the counter has not been read beforehand.
     */
    std::vector<std::uint8_t> buildAnticipatedDataOut();
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
