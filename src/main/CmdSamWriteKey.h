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
 * Builds the Write Key APDU command.
 *
 * @since 2.0.1
 */
class CmdSamWriteKey final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * CalypsoSamCardSelectorBuilder constructor
     *
     * @param productType the SAM product type.
     * @param writingMode the writing mode (P1).
     * @param keyReference the key reference (P2).
     * @param keyData the key data.
     * @since 2.0.1
     */
    CmdSamWriteKey(const CalypsoSam::ProductType productType, 
                   const uint8_t writingMode,
                   const uint8_t keyReference,
                   const std::vector<uint8_t>& keyData);

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
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
