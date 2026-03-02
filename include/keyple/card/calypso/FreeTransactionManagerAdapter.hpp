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

#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/card/calypso/TransactionManagerAdapter.hpp"
#include "keypop/calypso/card/transaction/FreeTransactionManager.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::transaction::FreeTransactionManager;

/**
 * Adapter of FreeTransactionManager.
 *
 * @since 3.0.0
 */
class FreeTransactionManagerAdapter final
: public TransactionManagerAdapter<FreeTransactionManager>,
  public FreeTransactionManager {
public:
    /**
     * Builds a new instance.
     *
     * @param cardReader The card reader to be used.
     * @param card The selected card on which to operate the transaction.
     * @since 3.0.0
     */
    FreeTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> cardReader,
        std::shared_ptr<CalypsoCardAdapter> card);

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::shared_ptr<DtoAdapters::TransactionContextDto>
    getTransactionContext() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::shared_ptr<DtoAdapters::CommandContextDto>
    getCommandContext() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    int getPayloadCapacity() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    void resetTransaction() override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    void prepareNewSecureSessionIfNeeded(
        const std::shared_ptr<Command>& command) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    bool canConfigureReadOnOpenSecureSession() const override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     * @deprecated Use processCommands(keypop::reader::ChannelControl) instead.
     */
    // FreeTransactionManager& processCommands(
    //     keypop::calypso::card::transaction::ChannelControl channelControl)
    //     override;

    /**
     * {@inheritDoc}
     *
     * <p>For each prepared command, if a pre-processing is required, then we
     * try to execute the post-processing of each of the previous commands in
     * anticipation. If at least one post-processing cannot be anticipated, then
     * we execute the block of previous commands first.
     *
     * @since 3.2.0
     */
    FreeTransactionManager&
    processCommands(ChannelControl channelControl) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    FreeTransactionManager&
    prepareVerifyPin(const std::vector<std::uint8_t>& pin) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    FreeTransactionManager&
    prepareChangePin(const std::vector<std::uint8_t>& newPin) override;

private:
    /**  */
    static const std::string MSG_PIN_NOT_AVAILABLE;

    /** */
    std::shared_ptr<DtoAdapters::TransactionContextDto> mTransactionContext;

    /** */
    std::shared_ptr<DtoAdapters::CommandContextDto> mCommandContext;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
