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
#include "AbstractApduCommand.h"
#include "AbstractSamCommand.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;
using namespace keyple::card::calypso;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the SV Prepare Load APDU command.
 *
 * @since 2.0.1
 */
class CmdSamSvPrepareLoad final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdSamSvPrepareLoad to prepare a load transaction.
     *
     * <p>Build the SvPrepareLoad APDU from the SvGet command and response, the SvReload partial
     * command
     *
     * @param productType the SAM product type.
     * @param svGetHeader the SV Get command header.
     * @param svGetData a byte array containing the data from the SV get command and response.
     * @param svReloadCmdBuildData the SV reload command data.
     * @since 2.0.1
     */
    CmdSamSvPrepareLoad(const CalypsoSam::ProductType productType,
                        const std::vector<uint8_t>& svGetHeader,
                        const std::vector<uint8_t>& svGetData,
                        const std::vector<uint8_t>& svReloadCmdBuildData);

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
