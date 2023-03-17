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
#include "CalypsoSamAdapter.h"
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
     * @param commandRef A command reference from the Calypso command table.
     * @param le The value of the LE field.
     * @param calypsoSam The Calypso SAM (it may be null if the SAM selection has not yet been
     *                   made).
     * @since 2.0.1
     */
    AbstractSamCommand(const CalypsoSamCommand& commandRef,
                       const int le,
                       const std::shared_ptr<CalypsoSamAdapter> calypsoSam);

    /**
     * (package-private)<br>
     * Returns the Calypso SAM.
     *
     * @return Null if the SAM selection has not yet been made.
     * @since 2.2.3
     */
    const std::shared_ptr<CalypsoSamAdapter> getCalypsoSam() const;

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

    /**
     * (package-private)<br>
     * Sets the Calypso SAM and invoke the {@link #parseApduResponse(ApduResponseApi)} method.
     *
     * @since 2.2.3
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse,
                           const std::shared_ptr<CalypsoSamAdapter> calypsoSam);

private:
    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();

    /**
     *
     */
    std::shared_ptr<CalypsoSamAdapter> mCalypsoSam;
};

}
}
}
