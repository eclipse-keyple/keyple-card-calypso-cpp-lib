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

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "CalypsoSamAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;

/**
 * (package-private)<br>
 * Builds the Read Event Counter APDU command.
 *
 * @since 2.0.1
 */
class CmdSamReadEventCounter final : public AbstractSamCommand {
public:
    /**
     * Event counter operation type
     */
    enum CounterOperationType {
        /**
         * Single counter
         */
        READ_SINGLE_COUNTER,

        /**
         * Counter record
         */
        READ_COUNTER_RECORD
    };

    /**
     * (package-private)<br>
     * Instantiate a new CmdSamReadEventCounter
     *
     * @param sam the SAM.
     * @param counterOperationType the counter operation type.
     * @param target the counter index (0-26) if READ_SINGLE_COUNTER, the record index (1-3) if
     *        READ_COUNTER_RECORD.
     * @since 2.0.1
     */
    CmdSamReadEventCounter(std::shared_ptr<CalypsoSamAdapter> sam,
                           const CounterOperationType counterOperationType,
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
     * @since 2.2.3
     */
    AbstractSamCommand& setApduResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

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
    std::shared_ptr<CalypsoSamAdapter> mSam;

    /**
     *
     */
    const CounterOperationType mCounterOperationType;

    /**
     *
     */
    const int mFirstEventCounterNumber;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
