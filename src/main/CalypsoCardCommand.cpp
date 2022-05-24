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

#include "CalypsoCardCommand.h"

namespace keyple {
namespace card {
namespace calypso {

const CalypsoCardCommand CalypsoCardCommand::NONE("None", 0x00);
const CalypsoCardCommand CalypsoCardCommand::GET_DATA("Get Data", 0xCA);
const CalypsoCardCommand CalypsoCardCommand::OPEN_SESSION("Open Secure Session", 0x8A);
const CalypsoCardCommand CalypsoCardCommand::CLOSE_SESSION("Close Secure Session", 0x8E);
const CalypsoCardCommand CalypsoCardCommand::READ_RECORDS("Read Records", 0xB2);
const CalypsoCardCommand CalypsoCardCommand::UPDATE_RECORD("Update Record", 0xDC);
const CalypsoCardCommand CalypsoCardCommand::WRITE_RECORD("Write Record", 0xD2);
const CalypsoCardCommand CalypsoCardCommand::APPEND_RECORD("Append Record", 0xE2);
const CalypsoCardCommand CalypsoCardCommand::READ_BINARY("Read Binary", 0xB0);
const CalypsoCardCommand CalypsoCardCommand::UPDATE_BINARY("Update Binary", 0xD6);
const CalypsoCardCommand CalypsoCardCommand::WRITE_BINARY("Write Binary", 0xD0);
const CalypsoCardCommand CalypsoCardCommand::SEARCH_RECORD_MULTIPLE("Search Record Multiple", 0xA2);
const CalypsoCardCommand CalypsoCardCommand::READ_RECORD_MULTIPLE("Read Record Multiple", 0xB3);
const CalypsoCardCommand CalypsoCardCommand::GET_CHALLENGE("Get Challenge", 0x84);
const CalypsoCardCommand CalypsoCardCommand::INCREASE("Increase", 0x32);
const CalypsoCardCommand CalypsoCardCommand::DECREASE("Decrease", 0x30);
const CalypsoCardCommand CalypsoCardCommand::INCREASE_MULTIPLE("Increase Multiple", 0x3A);
const CalypsoCardCommand CalypsoCardCommand::DECREASE_MULTIPLE("Decrease Multiple", 0x38);
const CalypsoCardCommand CalypsoCardCommand::SELECT_FILE("Select File", 0xA4);
const CalypsoCardCommand CalypsoCardCommand::CHANGE_KEY("Change Key", 0xD8);
const CalypsoCardCommand CalypsoCardCommand::CHANGE_PIN("Change PIN", 0xD8);
const CalypsoCardCommand CalypsoCardCommand::VERIFY_PIN("Verify PIN", 0x20);
const CalypsoCardCommand CalypsoCardCommand::SV_GET("SV Get", 0x7C);
const CalypsoCardCommand CalypsoCardCommand::SV_DEBIT("SV Debit", 0xBA);
const CalypsoCardCommand CalypsoCardCommand::SV_RELOAD("SV Reload", 0xB8);
const CalypsoCardCommand CalypsoCardCommand::SV_UNDEBIT("SV Undebit", 0xBC);
const CalypsoCardCommand CalypsoCardCommand::INVALIDATE("Invalidate", 0x04);
const CalypsoCardCommand CalypsoCardCommand::REHABILITATE("Invalidate", 0x44);

CalypsoCardCommand::CalypsoCardCommand(const std::string& name, const uint8_t instructionByte)
: mName(name), mInstructionByte(instructionByte) {}

CalypsoCardCommand::CalypsoCardCommand(const CalypsoCardCommand& o)
: mName(o.mName), mInstructionByte(o.mInstructionByte) {}

const std::string& CalypsoCardCommand::getName() const
{
    return mName;
}

uint8_t CalypsoCardCommand::getInstructionByte() const
{
    return mInstructionByte;
}

bool CalypsoCardCommand::operator==(const CalypsoCardCommand& o) const
{
    return mName == o.mName &&
           mInstructionByte == o.mInstructionByte;
}

bool CalypsoCardCommand::operator!=(const CalypsoCardCommand& o) const
{
    return !(*this == o);
}

CalypsoCardCommand& CalypsoCardCommand::operator=(const CalypsoCardCommand& o)
{
    mName = o.mName;
    mInstructionByte = o.mInstructionByte;

    return *this;
}

}
}
}
