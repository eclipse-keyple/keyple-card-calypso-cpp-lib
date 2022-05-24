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
 * Builds the SV Check APDU command.
 *
 * @since 2.0.1
 */
class CmdSamSvCheck final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdSamSvCheck to authenticate a card SV transaction.
     *
     * @param productType the SAM product type.
     * @param svCardSignature null if the operation is to abort the SV transaction, a 3 or 6-byte
     *     array. containing the card signature from SV Debit, SV Load or SV Undebit.
     * @since 2.0.1
     */
    CmdSamSvCheck(const CalypsoSam::ProductType productType,
                  const std::vector<uint8_t>& svCardSignature);

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
