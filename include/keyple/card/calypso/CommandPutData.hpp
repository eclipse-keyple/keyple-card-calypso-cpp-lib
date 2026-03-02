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
#include <typeinfo>
#include <vector>

#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keypop/calypso/card/PutDataTag.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::PutDataTag;

/**
 * Builds the Put Data command.
 *
 * @since 3.1.0
 */
class CommandPutData final : public Command {
public:
    /**
     * Constructor.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @since 3.1.0
     */
    CommandPutData(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        PutDataTag tag,
        bool isFirstPart,
        const std::vector<std::uint8_t>& data);

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    bool isCryptoServiceRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    bool synchronizeCryptoServiceBeforeCardProcessing() override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    const PutDataTag mTag;

    /**
     *
     */
    const std::vector<std::uint8_t> mData;

    /**
     *
     */
    const bool mIsFirstPart;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
