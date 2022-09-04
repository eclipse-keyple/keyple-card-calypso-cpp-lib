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

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the SV Debit or Undebit APDU command.
 *
 * @since 2.0.1
 */
class CmdSamSvPrepareDebitOrUndebit final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdSamSvPrepareDebit to prepare a debit or cancel transaction.
     *
     * @param isDebitCommand True if the current card command is an "SV Debit" command, false if it
     *        is an "SV Undebit" command.
     * @param productType the SAM product type.
     * @param svGetHeader the SV Get command header.
     * @param svGetData a byte array containing the data from the SV get command and response.
     * @param svDebitOrUndebitCmdBuildData the SV debit/undebit command data.
     * @since 2.0.1
     */
    CmdSamSvPrepareDebitOrUndebit(const bool isDebitCommand,
                                  const CalypsoSam::ProductType productType,
                                  const std::vector<uint8_t>& svGetHeader,
                                  const std::vector<uint8_t>& svGetData,
                                  const std::vector<uint8_t>& svDebitOrUndebitCmdBuildData);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
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
