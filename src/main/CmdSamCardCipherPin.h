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

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;

/**
 * (package-private)<br>
 * Builds the Card Cipher PIN APDU command.
 *
 * @since 2.0.1
 */
class CmdSamCardCipherPin final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdSamCardCipherPin and generate the ciphered data for a "Verify PIN" or
     * Change PIN card command.
     *
     * <p>In the case of a PIN verification, only the current PIN must be provided (newPin must be set
     * to null).
     *
     * <p>In the case of a PIN update, the current and new PINs must be provided.
     *
     * @param productType the SAM product type.
     * @param cipheringKif the KIF of the key used to encipher the PIN data.
     * @param cipheringKvc the KVC of the key used to encipher the PIN data.
     * @param currentPin the current PIN (a 4-byte byte array).
     * @param newPin the new PIN (a 4-byte byte array if the operation in progress is a PIN update,
     *     null if the operation in progress is a PIN verification)
     * @since 2.0.1
     */
    CmdSamCardCipherPin(const CalypsoSam::ProductType productType,
                        const uint8_t cipheringKif,
                        const uint8_t cipheringKvc,
                        const std::vector<uint8_t>& currentPin,
                        const std::vector<uint8_t>& newPin);

    /**
     * (package-private)<br>
     * Gets the 8 bytes of ciphered data.
     *
     * @return The ciphered data byte array
     * @since 2.0.1
     */
    const std::vector<uint8_t> getCipheredData() const;

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
