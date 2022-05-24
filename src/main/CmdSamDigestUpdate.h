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
#include "CalypsoSamCommand.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;

/**
 * (package-private)<br>
 * Builds the Digest Update APDU command.
 *
 * <p>This command have to be sent twice for each command executed during a session. First time for
 * the command sent and second time for the answer received.
 *
 * @since 2.0.1
 */
class CmdSamDigestUpdate final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdSamDigestUpdate.
     *
     * @param productType of the SAM.
     * @param encryptedSession the encrypted session flag, true if encrypted.
     * @param digestData all bytes from command sent by the card or response from the command.
     * @throws IllegalArgumentException If the digest data is null or has a length &gt; 255
     * @since 2.0.1
     */
    CmdSamDigestUpdate(const CalypsoSam::ProductType productType,
                       const bool encryptedSession,
                       const std::vector<uint8_t>& digestData);

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
