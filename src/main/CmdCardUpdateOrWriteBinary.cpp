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

#include "CmdCardUpdateOrWriteBinary.h"

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
    CmdCardUpdateOrWriteBinary::STATUS_TABLE = initStatusTable();

CmdCardUpdateOrWriteBinary::CmdCardUpdateOrWriteBinary(
  const bool isUpdateCommand,
  const CalypsoCardClass calypsoCardClass,
  const uint8_t sfi,
  const int offset,
  const std::vector<uint8_t>& data)
: AbstractCardCommand(isUpdateCommand ? CalypsoCardCommand::UPDATE_BINARY :
                                        CalypsoCardCommand::WRITE_BINARY),
  mSfi(sfi),
  mOffset(offset),
  mData(data)
{
    const uint8_t msb = (offset & 0xFF00) >> 8;
    const uint8_t lsb = (offset & 0xFF);

    /*
     * 100xxxxx : 'xxxxx' = SFI of the EF to select.
     * 0xxxxxxx : 'xxxxxxx' = MSB of the offset of the first byte.
     */
    const uint8_t p1 = msb > 0 ? msb : 0x80 + sfi;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            getCommandRef().getInstructionByte(),
                            p1,
                            lsb,
                            data)));



    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "OFFSET:" << offset;

    addSubName(extraInfo.str());
}

bool CmdCardUpdateOrWriteBinary::isSessionBufferUsed() const
{
    return true;
}

uint8_t CmdCardUpdateOrWriteBinary::getSfi() const
{
    return mSfi;
}

int CmdCardUpdateOrWriteBinary::getOffset() const
{
    return mOffset;
}

const std::vector<uint8_t>& CmdCardUpdateOrWriteBinary::getData() const
{
    return mData;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardUpdateOrWriteBinary::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6400,
              std::make_shared<StatusProperties>("Too many modifications in session",
                                                 typeid(CardSessionBufferOverflowException))});
    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported, or Offset+Lc > file size",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6981,
              std::make_shared<StatusProperties>("Incorrect EF type: not a Binary EF",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (no secure " \
                                                 "session, incorrect key, encryption required, " \
                                                 "PKI mode and not Always access mode)",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode, DF is " \
                                                 "invalidated, etc..)",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Incorrect file type: the Current File is not " \
                                                 "an EF. Supersedes 6981h",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Offset not in the file (offset overflow)",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 value not supported",
                                                 typeid(CardIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardUpdateOrWriteBinary::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
