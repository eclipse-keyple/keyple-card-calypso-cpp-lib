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

#include <map>
#include <memory>

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "CalypsoSamAdapter.h"
#include "CalypsoSamCommand.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Builds the Digest Close APDU command.
 *
 * @since 2.0.1
 */
class CmdSamDigestClose final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdSamDigestClose .
     *
     * @param calypsoSam The Calypso SAM.
     * @param expectedResponseLength the expected response length.
     * @since 2.0.1
     */
    CmdSamDigestClose(const std::shared_ptr<CalypsoSamAdapter> calypsoSam,
                      const int expectedResponseLength);

    /**
     * (package-private)<br>
     * Gets the sam signature.
     *
     * @return The sam half session signature
     * @since 2.0.1
     */
    const std::vector<uint8_t> getSignature() const;

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
