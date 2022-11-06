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

#include <cstdint>
#include <map>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"

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
    enum SamEventCounterOperationType {
        /**
         * Counter record
         */
        COUNTER_RECORD,
        
        /**
         * Single counter
         */
        SINGLE_COUNTER
    };

    /**
     * (package-private)<br>
     * Instantiate a new CmdSamReadEventCounter
     *
     * @param productType the SAM product type.
     * @param operationType the counter operation type.
     * @param index the counter index.
     * @since 2.0.1
     */
    CmdSamReadEventCounter(const CalypsoSam::ProductType productType, 
                           const SamEventCounterOperationType operationType,
                           const int index);

    /**
   * (package-private)<br>
   * Gets the key parameters.
   *
   * @return the counter data (Value or Record)
   * @since 2.0.1
   */
    const std::vector<uint8_t> getCounterData() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
    /**
     * The command
     */
    static const CalypsoSamCommand mCommand;

    /**
     * 
     */
    static const int MAX_COUNTER_NUMB;

    /**
     * 
     */

    static const int MAX_COUNTER_REC_NUMB;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
