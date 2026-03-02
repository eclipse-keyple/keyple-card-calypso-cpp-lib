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

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"

namespace keyple {
namespace card {
namespace calypso {

/**
 * Builds the Change PIN APDU command.
 *
 * @since 2.0.1
 */
class CommandChangeKey final : public Command {
public:
    /**
     * Constructor.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param keyIndex The key index.
     * @param newKif The new KIF.
     * @param newKvc The new KVC.
     * @param issuerKif The issuer KIF.
     * @param issuerKvc The issuer KVC.
     * @since 2.3.2
     */
    CommandChangeKey(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        std::uint8_t keyIndex,
        std::uint8_t newKif,
        std::uint8_t newKvc,
        std::uint8_t issuerKif,
        std::uint8_t issuerKvc);

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

private:
    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    const std::uint8_t mKeyIndex;

    /**
     *
     */
    const std::uint8_t mNewKif;

    /**
     *
     */
    const std::uint8_t mNewKvc;

    /**
     *
     */
    const std::uint8_t mIssuerKif;

    /**
     *
     */
    const std::uint8_t mIssuerKvc;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
