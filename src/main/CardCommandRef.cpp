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

#include "keyple/card/calypso/CardCommandRef.hpp"

namespace keyple {
namespace card {
namespace calypso {

const CardCommandRef CardCommandRef::NONE("None", 0x00);

const CardCommandRef CardCommandRef::GET_DATA("Get Data", 0xCA);
const CardCommandRef CardCommandRef::PUT_DATA("Put Data", 0xDA);
const CardCommandRef CardCommandRef::OPEN_SECURE_SESSION("Open Secure Session", 0x8A);
const CardCommandRef CardCommandRef::CLOSE_SECURE_SESSION("Close Secure Session", 0x8E);
const CardCommandRef CardCommandRef::MANAGE_SECURE_SESSION("Manage Secure Session", 0x82);
const CardCommandRef CardCommandRef::RATIFICATION("Ratification", 0xB2);
const CardCommandRef CardCommandRef::READ_RECORDS("Read Records", 0xB2);
const CardCommandRef CardCommandRef::UPDATE_RECORD("Update Record", 0xDC);
const CardCommandRef CardCommandRef::WRITE_RECORD("Write Record", 0xD2);
const CardCommandRef CardCommandRef::APPEND_RECORD("Append Record", 0xE2);
const CardCommandRef CardCommandRef::READ_BINARY("Read Binary", 0xB0);
const CardCommandRef CardCommandRef::UPDATE_BINARY("Update Binary", 0xD6);
const CardCommandRef CardCommandRef::WRITE_BINARY("Write Binary", 0xD0);
const CardCommandRef CardCommandRef::SEARCH_RECORD_MULTIPLE("Search Record Multiple", 0xA2);
const CardCommandRef CardCommandRef::READ_RECORD_MULTIPLE("Read Record Multiple", 0xB3);
const CardCommandRef CardCommandRef::GET_CHALLENGE("Get Challenge", 0x84);
const CardCommandRef CardCommandRef::INCREASE("Increase", 0x32);
const CardCommandRef CardCommandRef::DECREASE("Decrease", 0x30);
const CardCommandRef CardCommandRef::INCREASE_MULTIPLE("Increase Multiple", 0x3A);
const CardCommandRef CardCommandRef::DECREASE_MULTIPLE("Decrease Multiple", 0x38);
const CardCommandRef CardCommandRef::SELECT_FILE("Select File", 0xA4);
const CardCommandRef CardCommandRef::CHANGE_KEY("Change Key", 0xD8);
const CardCommandRef CardCommandRef::CHANGE_PIN("Change PIN", 0xD8);
const CardCommandRef CardCommandRef::VERIFY_PIN("Verify PIN", 0x20);
const CardCommandRef CardCommandRef::SV_GET("SV Get", 0x7C);
const CardCommandRef CardCommandRef::SV_DEBIT("SV Debit", 0xBA);
const CardCommandRef CardCommandRef::SV_RELOAD("SV Reload", 0xB8);
const CardCommandRef CardCommandRef::SV_UNDEBIT("SV Undebit", 0xBC);
const CardCommandRef CardCommandRef::INVALIDATE("Invalidate", 0x04);
const CardCommandRef CardCommandRef::REHABILITATE("Rehabilitate", 0x44);
const CardCommandRef CardCommandRef::GENERATE_ASYMMETRIC_KEY_PAIR("Generate Asymetric Key Pair", 0x46);

CardCommandRef::CardCommandRef(
    const std::string& name, const uint8_t instructionByte)
: mName(name)
, mInstructionByte(instructionByte)
{
}

CardCommandRef::CardCommandRef(const CardCommandRef& o)
: mName(o.mName)
, mInstructionByte(o.mInstructionByte)
{
}

const std::string&
CardCommandRef::getName() const
{
    return mName;
}

std::uint8_t
CardCommandRef::getInstructionByte() const
{
    return mInstructionByte;
}

bool
CardCommandRef::operator==(const CardCommandRef& o) const
{
    return mName == o.mName &&
           mInstructionByte == o.mInstructionByte;
}

bool
CardCommandRef::operator!=(const CardCommandRef& o) const
{
    return !(*this == o);
}

CardCommandRef&
CardCommandRef::operator=(const CardCommandRef& o)
{
    mName = o.mName;
    mInstructionByte = o.mInstructionByte;

    return *this;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
