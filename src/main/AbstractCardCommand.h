/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#pragma once

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "CalypsoCardCommand.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Superclass for all card commands.
 *
 * @since 2.0.1
 */
class AbstractCardCommand : public AbstractApduCommand {
public:
    /**
     * (package-private)<br>
     * Constructor dedicated for the building of referenced Calypso commands
     *
     * @param commandRef a command reference from the Calypso command table.
     * @since 2.0.1
     */
    AbstractCardCommand(const CalypsoCardCommand& commandRef);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const CalypsoCardCommand& getCommandRef() const override;

    /**
     * (package-private)<br>
     * Indicates if the session buffer is used when executing this command.
     *
     * <p>Allows the management of the overflow of this buffer.
     *
     * @return True if this command uses the session buffer
     * @since 2.0.1
     */
    virtual bool isSessionBufferUsed() const = 0;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const CalypsoApduCommandException buildCommandException(
        const std::type_info& exceptionClass,
        const std::string& message,
        const CardCommand& commandRef,
        const int statusWord) const final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    AbstractCardCommand& setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    void checkStatus() override;
};

}
}
}
