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
 * Builds the "Verify PIN" command.
 *
 * @since 2.0.1
 */
class CmdCardVerifyPin final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Verify the PIN
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @param encryptPinTransmission true if the PIN transmission has to be encrypted.
     * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of an encrypted
     *     transmission (@see setCipheredPinData).
     * @since 2.0.1
     */
    CmdCardVerifyPin(
        const CalypsoCardClass calypsoCardClass,
        const bool encryptPinTransmission,
        const std::vector<uint8_t>& pin);

    /**
     * (package-private)<br>
     * Alternate command dedicated to the reading of the wrong presentation counter
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @since 2.0.1
     */
    CmdCardVerifyPin(const CalypsoCardClass calypsoCardClass);

    /**
     * {@inheritDoc}
     *
     * @return false
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * (package-private)<br>
     * Indicates if the command is used to read the attempt counter only
     *
     * @return True if the command is used to read the attempt counter
     * @since 2.0.1
     */
    bool isReadCounterOnly() const;

    /**
     * (package-private)<br>
     * Determine the value of the attempt counter from the status word
     *
     * @return The remaining attempt counter value (0, 1, 2 or 3)
     * @since 2.0.1
     */
    int getRemainingAttemptCounter() const;

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
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CmdCardVerifyPin));

    /**
     *
     */
    static const CalypsoCardCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    const uint8_t mCla;

    /**
     *
     */
    bool mReadCounterOnly;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
