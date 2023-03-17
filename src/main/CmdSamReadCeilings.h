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

#include <cstdint>
#include <map>
#include <vector>

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "CalypsoSamAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Builds the Read Ceilings APDU command.
 *
 * @since 2.0.1
 */
class CmdSamReadCeilings final : public AbstractSamCommand {
public:
    /**
     * Ceiling operation type
     */
    enum class CeilingsOperationType {
        /**
         * Single ceiling
         */
        READ_SINGLE_CEILING,

        /**
         * Ceiling record
         */
        READ_CEILING_RECORD,
    };

    /**
     * (package-private)<br>
     * Instantiates a new CmdSamReadCeilings.
     *
     * @param calypsoSam The Calypso SAM.
     * @param ceilingsOperationType the ceiling operation type.
     * @param target the ceiling index (0-26) if READ_SINGLE_CEILING, the record index (1-3) if
     *        READ_CEILING_RECORD.
     * @since 2.0.1
     */
    CmdSamReadCeilings(std::shared_ptr<CalypsoSamAdapter> calypsoSam,
                       const CeilingsOperationType ceilingsOperationType,
                       const int target);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     * @since 2.2.3
     */
    void parseApduResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

private:
    /**
     * The command
     */
    static const CalypsoSamCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    const CeilingsOperationType mCeilingsOperationType;

    /**
     *
     */
    const int mFirstEventCeilingNumber;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
