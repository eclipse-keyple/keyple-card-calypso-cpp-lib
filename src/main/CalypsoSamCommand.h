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
    /** select diversifier. */
    static const CalypsoSamCommand SELECT_DIVERSIFIER;

    /** get challenge. */
    static const CalypsoSamCommand GET_CHALLENGE;

    /** digest init. */
    static const CalypsoSamCommand DIGEST_INIT;

    /** digest update. */
    static const CalypsoSamCommand DIGEST_UPDATE;

    /** digest update multiple. */
    static const CalypsoSamCommand DIGEST_UPDATE_MULTIPLE;

    /** digest close. */
    static const CalypsoSamCommand DIGEST_CLOSE;

    /** digest authenticate. */
    static const CalypsoSamCommand DIGEST_AUTHENTICATE;

    /** digest authenticate. */
    static const CalypsoSamCommand GIVE_RANDOM;

    /** digest authenticate. */
    static const CalypsoSamCommand CARD_GENERATE_KEY;

    /** card cipher PIN. */
    static const CalypsoSamCommand CARD_CIPHER_PIN;

    /** unlock. */
    static const CalypsoSamCommand UNLOCK;

    /** write key. */
    static const CalypsoSamCommand WRITE_KEY;

    /** read key parameters. */
    static const CalypsoSamCommand READ_KEY_PARAMETERS;

    /** read event counter. */
    static const CalypsoSamCommand READ_EVENT_COUNTER;

    /** read ceilings. */
    static const CalypsoSamCommand READ_CEILINGS;

    /** SV check. */
    static const CalypsoSamCommand SV_CHECK;

    /** SV prepare debit. */
    static const CalypsoSamCommand SV_PREPARE_DEBIT;

    /** SV prepare load. */
    static const CalypsoSamCommand SV_PREPARE_LOAD;

    /** SV prepare undebit. */
    static const CalypsoSamCommand SV_PREPARE_UNDEBIT;

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
