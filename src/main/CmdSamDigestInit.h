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
 * Builds the Digest Init APDU command.
 *
 * @since 2.0.1
 */
class CmdSamDigestInit final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdSamDigestInit.
     *
     * @param productType the SAM product type.
     * @param verificationMode the verification mode.
     * @param confidentialSessionMode the confidential session mode (rev 3.2).
     * @param workKif from the card response.
     * @param workKvc from the card response.
     * @param digestData all data out from the card response.
     * @throw IllegalArgumentException If the KIF or KVC is 0
     * @throw IllegalArgumentException If the digest data is null
     * @throw IllegalArgumentException If the request is inconsistent
     * @since 2.0.1
     */
    CmdSamDigestInit(
        const CalypsoSam::ProductType productType,
        const bool verificationMode,
        const bool confidentialSessionMode,
        const uint8_t workKif,
        const uint8_t workKvc,
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
