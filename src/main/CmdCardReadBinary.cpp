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

#include "CmdCardReadBinary.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "System.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"
#include "CardTerminatedException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardReadBinary::STATUS_TABLE = initStatusTable();

CmdCardReadBinary::CmdCardReadBinary(const CalypsoCardClass calypsoCardClass,
                                     const uint8_t sfi,
                                     const int offset,
                                     const uint8_t length)
: AbstractCardCommand(CalypsoCardCommand::READ_BINARY), mSfi(sfi), mOffset(offset)
{
    const uint8_t msb = ((offset & 0xFF00) >> 8);
    const uint8_t lsb = (offset & 0xFF);

    /*
     * 100xxxxx : 'xxxxx' = SFI of the EF to select.
     * 0xxxxxxx : 'xxxxxxx' = MSB of the offset of the first byte.
     */
    const uint8_t p1 = msb > 0 ? msb : 0x80 + mSfi;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(
                calypsoCardClass.getValue(),
                getCommandRef().getInstructionByte(),
                p1,
                lsb,
                length)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "OFFSET:" << offset << ", "
              << "LENGTH:" << length;

    addSubName(extraInfo.str());
}

bool CmdCardReadBinary::isSessionBufferUsed() const
{
    return false;
}

uint8_t CmdCardReadBinary::getSfi() const
{
    return mSfi;
}

int CmdCardReadBinary::getOffset() const
{
    return mOffset;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardReadBinary::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6981,
              std::make_shared<StatusProperties>("Incorrect EF type: not a Binary EF.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (PIN code " \
                                                 "not presented, encryption required).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Incorrect file type: the Current File is not " \
                                                 "an EF. Supersedes 6981h.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Offset not in the file (offset overflow).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 value not supported.",
                                                 typeid(CardIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardReadBinary::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
