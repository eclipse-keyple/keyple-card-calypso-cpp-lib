/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#pragma once

#include <cstdint>
#include <string>

namespace keyple {
namespace card {
namespace calypso {

/**
 * Defines all supported Calypso card APDU commands.
 *
 * @since 2.0.0
 */
class CardCommandRef {
public:
    /** no command yet */
    static const CardCommandRef NONE;

    static const CardCommandRef GET_DATA;
    static const CardCommandRef PUT_DATA;
    static const CardCommandRef OPEN_SECURE_SESSION;
    static const CardCommandRef CLOSE_SECURE_SESSION;
    static const CardCommandRef MANAGE_SECURE_SESSION;
    static const CardCommandRef RATIFICATION;
    static const CardCommandRef READ_RECORDS;
    static const CardCommandRef UPDATE_RECORD;
    static const CardCommandRef WRITE_RECORD;
    static const CardCommandRef APPEND_RECORD;
    static const CardCommandRef READ_BINARY;
    static const CardCommandRef UPDATE_BINARY;
    static const CardCommandRef WRITE_BINARY;
    static const CardCommandRef SEARCH_RECORD_MULTIPLE;
    static const CardCommandRef READ_RECORD_MULTIPLE;
    static const CardCommandRef GET_CHALLENGE;
    static const CardCommandRef INCREASE;
    static const CardCommandRef DECREASE;
    static const CardCommandRef INCREASE_MULTIPLE;
    static const CardCommandRef DECREASE_MULTIPLE;
    static const CardCommandRef SELECT_FILE;
    static const CardCommandRef CHANGE_KEY;
    static const CardCommandRef CHANGE_PIN;
    static const CardCommandRef VERIFY_PIN;
    static const CardCommandRef SV_GET;
    static const CardCommandRef SV_DEBIT;
    static const CardCommandRef SV_RELOAD;
    static const CardCommandRef SV_UNDEBIT;
    static const CardCommandRef INVALIDATE;
    static const CardCommandRef REHABILITATE;
    static const CardCommandRef GENERATE_ASYMMETRIC_KEY_PAIR;
    /**
     *
     */
    bool operator==(const CardCommandRef& o) const;

    /**
     *
     */
    bool operator!=(const CardCommandRef& o) const;

    /**
     *
     */
    CardCommandRef& operator=(const CardCommandRef& o);

    /**
     *
     */
    CardCommandRef(const CardCommandRef& o);

    /**default
     * @since 2.0.0
     */
    uint8_t getInstructionByte() const;

    /**
     * Gets the name.
     *
     * @return A String
     * @since 2.0.0
     */
    const std::string& getName() const;

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
    CardCommandRef(const std::string& name, const uint8_t instructionByte);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
