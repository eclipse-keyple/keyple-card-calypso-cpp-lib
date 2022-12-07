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
#include <string>

/* Keyple Card Calypso */
#include "CardCommand.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Defines all supported Calypso SAM APDU commands.
 *
 * @since 2.0.0
 */
class CalypsoSamCommand : public CardCommand {
public:
    static const CalypsoSamCommand SELECT_DIVERSIFIER;
    static const CalypsoSamCommand GET_CHALLENGE;
    static const CalypsoSamCommand DIGEST_INIT;
    static const CalypsoSamCommand DIGEST_UPDATE;
    static const CalypsoSamCommand DIGEST_UPDATE_MULTIPLE;
    static const CalypsoSamCommand DIGEST_CLOSE;
    static const CalypsoSamCommand DIGEST_AUTHENTICATE;
    static const CalypsoSamCommand GIVE_RANDOM;
    static const CalypsoSamCommand CARD_GENERATE_KEY;
    static const CalypsoSamCommand CARD_CIPHER_PIN;
    static const CalypsoSamCommand UNLOCK;
    static const CalypsoSamCommand WRITE_KEY;
    static const CalypsoSamCommand READ_KEY_PARAMETERS;
    static const CalypsoSamCommand READ_EVENT_COUNTER;
    static const CalypsoSamCommand READ_CEILINGS;
    static const CalypsoSamCommand SV_CHECK;
    static const CalypsoSamCommand SV_PREPARE_DEBIT;
    static const CalypsoSamCommand SV_PREPARE_LOAD;
    static const CalypsoSamCommand SV_PREPARE_UNDEBIT;
    static const CalypsoSamCommand PSO_COMPUTE_SIGNATURE;
    static const CalypsoSamCommand PSO_VERIFY_SIGNATURE;

    /**
     * Gets the name.
     *
     * @return A String
     * @since 2.0.0
     */
    const std::string& getName() const override;

    /**
     * Gets the instruction byte (INS).
     *
     * @return A byte
     * @since 2.0.0
     */
    uint8_t getInstructionByte() const override;

private:
    /**
     * The name
     */
    const std::string mName;

    /**
     * The instruction byte
     */
    const uint8_t mInstructionByte;

    /**
     * The generic constructor of CalypsoCommands.
     *
     * @param name the name.
     * @param instructionByte the instruction byte.
     * @since 2.0.0
     */
    CalypsoSamCommand(const std::string& name, const uint8_t instructionByte);
};

}
}
}
