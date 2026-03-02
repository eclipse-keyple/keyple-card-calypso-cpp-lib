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
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
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
 * Builds the "Verify PIN" command.
 *
 * @since 2.0.1
 */
class CommandVerifyPin final : public Command {
public:
    /**
     * Verify the PIN in encrypted mode.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param pin the PIN data. The PIN is always 4-byte long here, even in the
     * case of an encrypted transmission (@see setCipheredPinData).
     * @param cipheringKif The ciphering KIF.
     * @param cipheringKvc The ciphering KVC.
     * @since 2.3.2
     */
    CommandVerifyPin(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        const std::vector<std::uint8_t>& pin,
        std::uint8_t cipheringKif,
        std::uint8_t cipheringKvc);

    /**
     * Verify the PIN in plain mode.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param pin the PIN data. The PIN is always 4-byte long here, even in the
     * case of an encrypted transmission (@see setCipheredPinData).
     * @since 2.3.2
     */
    CommandVerifyPin(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        const std::vector<std::uint8_t>& pin);

    /**
     * Alternate command dedicated to the reading of the wrong presentation
     * counter
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @since 2.3.2
     */
    CommandVerifyPin(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext);

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
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandVerifyPin));

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
    std::vector<std::uint8_t> mPin;

    /**
     *
     */
    bool mIsReadCounterMode;

    /**
     *
     */
    bool mIsPinEncryptedMode;

    /**
     *
     */
    std::uint8_t mCipheringKif;

    /**
     *
     */
    std::uint8_t mCipheringKvc;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
