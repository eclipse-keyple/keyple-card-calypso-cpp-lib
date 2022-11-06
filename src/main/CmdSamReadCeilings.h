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
         * Ceiling record
         */
        CEILING_RECORD,
      
        /**
         * Single ceiling
         */
        SINGLE_CEILING
    };

    /**
     * (package-private)<br>
     * Instantiates a new CmdSamReadCeilings.
     *
     * @param productType the SAM product type.
     * @param operationType the counter operation type.
     * @param index the counter index.
     * @since 2.0.1
     */
    CmdSamReadCeilings(const CalypsoSam::ProductType productType, 
                       const CeilingsOperationType operationType,
                       const int index);

    /**
     * (package-private)<br>
     * Gets the key parameters.
     *
     * @return The ceiling data (Value or Record)
     * @since 2.0.1
     */
    const std::vector<uint8_t> getCeilingsData() const;

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
    static const int MAX_CEILING_NUMB;

    /**
     * 
     */

    static const int MAX_CEILING_REC_NUMB;

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
