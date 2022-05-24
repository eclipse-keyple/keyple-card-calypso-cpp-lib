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
 * Defines all supported Calypso card APDU commands.
 *
 * @since 2.0.0
 */
class CalypsoCardCommand : public CardCommand {
public:
    /** no command yet */
    static const CalypsoCardCommand NONE;

    /** get data. */
    static const CalypsoCardCommand GET_DATA;

    /** open session. */
    static const CalypsoCardCommand OPEN_SESSION;

    /** close session. */
    static const CalypsoCardCommand CLOSE_SESSION;

    /** read records. */
    static const CalypsoCardCommand READ_RECORDS;

    /** update record. */
    static const CalypsoCardCommand UPDATE_RECORD;

    /** write record. */
    static const CalypsoCardCommand WRITE_RECORD;

    /** append record. */
    static const CalypsoCardCommand APPEND_RECORD;

    /** read binary. */
    static const CalypsoCardCommand READ_BINARY;

    /** update binary. */
    static const CalypsoCardCommand UPDATE_BINARY;

    /** write binary. */
    static const CalypsoCardCommand WRITE_BINARY;

    /** search record multiple. */
    static const CalypsoCardCommand SEARCH_RECORD_MULTIPLE;

    /** read record multiple. */
    static const CalypsoCardCommand READ_RECORD_MULTIPLE;

    /** get challenge. */
    static const CalypsoCardCommand GET_CHALLENGE;

    /** increase counter. */
    static const CalypsoCardCommand INCREASE;

    /** decrease counter. */
    static const CalypsoCardCommand DECREASE;

    /** increase multiple counters. */
    static const CalypsoCardCommand INCREASE_MULTIPLE;

    /** decrease multiple counters. */
    static const CalypsoCardCommand DECREASE_MULTIPLE;

    /** decrease counter. */
    static const CalypsoCardCommand SELECT_FILE;

    /** change key */
    static const CalypsoCardCommand CHANGE_KEY;

    /** change PIN */
    static const CalypsoCardCommand CHANGE_PIN;

    /** verify PIN */
    static const CalypsoCardCommand VERIFY_PIN;

    /** SV Get */
    static const CalypsoCardCommand SV_GET;

    /** SV Debit */
    static const CalypsoCardCommand SV_DEBIT;

    /** SV Reload */
    static const CalypsoCardCommand SV_RELOAD;

    /** SV Undebit */
    static const CalypsoCardCommand SV_UNDEBIT;

    /** invalidate */
    static const CalypsoCardCommand INVALIDATE;

    /** rehabilitate */
    static const CalypsoCardCommand REHABILITATE;

    /**
     *
     */
    bool operator==(const CalypsoCardCommand& o) const;

    /**
     *
     */
    bool operator!=(const CalypsoCardCommand& o) const;

    /**
     *
     */
    CalypsoCardCommand& operator=(const CalypsoCardCommand& o);

    /**
     *
     */
    CalypsoCardCommand(const CalypsoCardCommand& o);

    /**default
     * @since 2.0.0
     */
    uint8_t getInstructionByte() const;

private:
    /**
     * The command name
     */
    std::string mName;

    /**
     * The instruction byte
     */
    uint8_t mInstructionByte;

    /**
     * The generic constructor of CalypsoCommands.
     *
     * @param name the name.
     * @param instructionByte the instruction byte.
     * @since 2.0.0
     */
    CalypsoCardCommand(const std::string& name, const uint8_t instructionByte);

    /**
     * Gets the name.
     *
     * @return A String
     * @since 2.0.0
     */
    const std::string& getName() const;
};

}
}
}
