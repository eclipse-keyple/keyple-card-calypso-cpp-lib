/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
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
#include <memory>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoCard.h"

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardClass.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;
using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the Get Challenge APDU command.
 *
 * @since 2.0.1
 */
class CmdCardGetChallenge final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardGetChallenge.
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @since 2.0.1
     */
    CmdCardGetChallenge(const CalypsoCardClass calypsoCardClass);

    /**
     * {@inheritDoc}
     *
     * @return false
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * (package-private)<br>
     * Gets the card challenge
     *
     * @return An array of bytes
     * @since 2.0.1
     */
    const std::vector<uint8_t> getCardChallenge() const;

private:
    /**
     *
     */
    static const CalypsoCardCommand mCommand;
};

}
}
}
