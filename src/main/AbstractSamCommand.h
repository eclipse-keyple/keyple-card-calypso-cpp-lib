/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
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

#include <map>

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "CalypsoSamCommand.h"

namespace keyple {
namespace card {
namespace calypso {


using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Superclass for all SAM command.
 *
 * @since 2.0.1
 */
class AbstractSamCommand : public AbstractApduCommand {
public:
    /**
     * (package-private)<br>
     * Default SAM product type.
     *
     * @since 2.0.1
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

    /**
     * (package-private)<br>
     * Constructor dedicated for the building of referenced Calypso commands
     *
     * @param commandRef a command reference from the Calypso command table.
     * @param le The value of the LE field.
     * @since 2.0.1
     */
    AbstractSamCommand(const CalypsoSamCommand& commandRef, const int le);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const CalypsoSamCommand& getCommandRef() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const CalypsoApduCommandException buildCommandException(const std::type_info& exceptionClass,
                                                            const std::string& message) const final;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.1
     */
    const CalypsoApduCommandException buildUnexpectedResponseLengthException(
        const std::string& message) const final;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

private:
    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
