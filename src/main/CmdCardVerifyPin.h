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

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"

/* Calypsonet Terminal Calypso */
#include "CalypsoCard.h"

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardAdapter.h"
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
     * @param calypsoCard The Calypso card.
     * @param encryptPinTransmission true if the PIN transmission has to be encrypted.
     * @param pin the PIN data. The PIN is always 4-byte long here, even in the case of an encrypted
     *     transmission (@see setCipheredPinData).
     * @since 2.0.1
     */
    CmdCardVerifyPin(
        const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
        const bool encryptPinTransmission,
        const std::vector<uint8_t>& pin);

    /**
     * (package-private)<br>
     * Alternate command dedicated to the reading of the wrong presentation counter
     *
     * @param calypsoCard The Calypso card.
     * @since 2.0.1
     */
    CmdCardVerifyPin(const std::shared_ptr<CalypsoCardAdapter> calypsoCard);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @return false
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

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
