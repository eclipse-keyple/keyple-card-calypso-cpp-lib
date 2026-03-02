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
 * Builds the "Update/Write Binary" APDU command.
 *
 * @since 2.1.0
 */
class CommandUpdateOrWriteBinary final : public Command {
public:
    /**
     * Constructor.
     *
     * @param isUpdateCommand True if it is an "Update Binary" command, false if
     * it is a "Write Binary" command.
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param sfi the sfi to select.
     * @param offset the offset.
     * @param data the data to write.
     * @since 2.3.2
     */
    CommandUpdateOrWriteBinary(
        bool isUpdateCommand,
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        std::uint8_t sfi,
        int offset,
        const std::vector<uint8_t>& data);

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
        = LoggerFactory::getLogger(typeid(CommandUpdateOrWriteBinary));

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     * Construction arguments
     */
    const uint8_t mSfi;

    /**
     *
     */
    const int mOffset;

    /**
     *
     */
    const std::vector<uint8_t> mData;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
