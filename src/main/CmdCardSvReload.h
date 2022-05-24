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
#include "CalypsoCard.h"

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;
using namespace keyple::card::calypso;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the SV Reload command.
 *
 * <p>See specs: Calypso Stored Value balance (signed binaries' coding based on the two's complement
 * method)
 *
 * <p>balance - 3 bytes signed binary - Integer from -8,388,608 to 8,388,607
 *
 * <p>amount for reload, 3 bytes signed binary - Integer from -8,388,608 to 8,388,607
 *
 * <pre>
 * -8,388,608           %10000000.00000000.00000000
 * -8,388,607           %10000000.00000000.00000001
 * -8,388,606           %10000000.00000000.00000010
 *
 * -3           %11111111.11111111.11111101
 * -2           %11111111.11111111.11111110
 * -1           %11111111.11111111.11111111
 * 0           %00000000.00000000.00000000
 * 1           %00000000.00000000.00000001
 * 2           %00000000.00000000.00000010
 * 3           %00000000.00000000.00000011
 *
 * 8,388,605           %01111111.11111111.11111101
 * 8,388,606           %01111111.11111111.11111110
 * 8,388,607           %01111111.11111111.11111111
 * </pre>
 *
 * @since 2.0.1
 */
class CmdCardSvReload final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardSvReload.
     *
     * <p>The process is carried out in two steps: first to check and store the card and application
     * data, then to create the final APDU with the data from the SAM (see finalizeCommand).
     *
     * @param calypsoCard the Calypso card.
     * @param amount amount to debit (signed integer from -8388608 to 8388607).
     * @param kvc debit key KVC (not checked by the card).
     * @param date debit date (not checked by the card).
     * @param time debit time (not checked by the card).
     * @param free 2 free bytes stored in the log but not processed by the card.
     * @throw IllegalArgumentException If the command is inconsistent
     * @since 2.0.1
     */
    CmdCardSvReload(const std::shared_ptr<CalypsoCard> calypsoCard,
                    const int amount,
                    const uint8_t kvc,
                    const std::vector<uint8_t>& date,
                    const std::vector<uint8_t>& time,
                    const std::vector<uint8_t>& free);

    /**
     * (package-private)<br>
     * Complete the construction of the APDU to be sent to the card with the elements received from
     * the SAM:
     *
     * <p>4-byte SAM id
     *
     * <p>3-byte challenge
     *
     * <p>3-byte transaction number
     *
     * <p>5 or 10 byte signature (hi part)
     *
     * @param reloadComplementaryData the sam id and the data out from the SvPrepareReload SAM
     *     command.
     * @since 2.0.1
     */
    void finalizeCommand(const std::vector<uint8_t>& reloadComplementaryData);

    /**
     * (package-private)<br>
     * Gets the SV Reload part of the data to include in the SAM SV Prepare Load command
     *
     * @return a byte array containing the SV reload data
     * @since 2.0.1
     */
    const std::vector<uint8_t> getSvReloadData() const;

    /**
     * {@inheritDoc}
     *
     * @return True
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * {@inheritDoc}
     *
     * <p>The permitted lengths are 0 (in session), 3 (not 3.2) or 6 (3.2)
     *
     * @throws IllegalStateException If the length is incorrect.
     * @since 2.0.1
     */
    CmdCardSvReload& setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * (package-private)<br>
     * Gets the SV signature. <br>
     * The signature can be empty here in the case of a secure session where the transmission of the
     * signature is postponed until the end of the session.
     *
     * @return A byte array containing the signature
     * @since 2.0.1
     */
    const std::vector<uint8_t> getSignatureLo() const;

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
    std::shared_ptr<CalypsoCard> mCalypsoCard;

    /**
     * Apdu data array
     */
    std::vector<uint8_t> mDataIn;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
