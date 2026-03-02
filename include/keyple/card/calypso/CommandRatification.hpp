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

namespace keyple {
namespace card {
namespace calypso {

/**
 * Builds a "Ratification" command.
 *
 * <p>i.e. the command sent after closing the secure session to handle the
 * ratification mechanism.
 *
 * <p>This particular command is not associated with any parsing since the
 * response to this command is always an error and is never checked.
 *
 * @since 2.3.2
 */
class CommandRatification final : public Command {
public:
    /**
     * Constructor.
     *
     * @since 2.3.2
     */
    CommandRatification(
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
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
