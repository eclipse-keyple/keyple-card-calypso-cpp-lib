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
 * Builds the Close Secure Session APDU command.
 *
 * @since 2.0.1
 */
class CmdCardCloseSession final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardCloseSession depending on the product type of the card.
     *
     * @param calypsoCard The {@link CalypsoCard}.
     * @param ratificationAsked the ratification asked.
     * @param terminalSessionSignature the sam half session signature.
     * @throw IllegalArgumentException If the signature is null or has a wrong length
     * @throw IllegalArgumentException If the command is inconsistent
     * @since 2.0.1
     */
    CmdCardCloseSession(const std::shared_ptr<CalypsoCard> calypsoCard,
                        const bool ratificationAsked,
                        const std::vector<uint8_t> terminalSessionSignature);

    /**
     * (package-private)<br>
     * Instantiates a new CmdCardCloseSession based on the product type of the card to generate an
     * abort session command (Close Secure Session with p1 = p2 = lc = 0).
     *
     * @param calypsoCard The {@link CalypsoCard}.
     * @since 2.0.1
     */
    CmdCardCloseSession(const std::shared_ptr<CalypsoCard> calypsoCard);

    /**
     * {@inheritDoc}
     *
     * @return False
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * {@inheritDoc}
     *
     * <p>Checks the card response length; the admissible lengths are 0, 4 or 8 bytes.
     *
     * @since 2.0.1
     */
    CmdCardCloseSession& setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
        override;

    /**
     * (package-private)<br>
     * Gets the low part of the session signature.
     *
     * @return A 4 or 8-byte array of bytes according to the extended mode availability.
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getSignatureLo() const;

    /**
     * (package-private)<br>
     * Gets the secure session postponed data (e.g. Sv Signature).
     *
     * @return A 0, 3 or 6-byte array of bytes according to presence of postponed data and the
     *         extended mode usage.
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getPostponedData() const;

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
    static const CalypsoCardCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    const std::shared_ptr<CalypsoCard> mCalypsoCard;

    /**
     * The signatureLo
     */
    std::vector<uint8_t> mSignatureLo;

    /**
     * The postponed data
     */
    std::vector<uint8_t> mPostponedData;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
