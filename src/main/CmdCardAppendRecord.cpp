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

#include "CmdCardAppendRecord.h"

#include <sstream>

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const CalypsoCardCommand CmdCardAppendRecord::mCommand = CalypsoCardCommand::APPEND_RECORD;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardAppendRecord::STATUS_TABLE = initStatusTable();

CmdCardAppendRecord::CmdCardAppendRecord(const CalypsoCardClass calypsoCardClass,
                                         const uint8_t sfi,
                                         const std::vector<uint8_t>& newRecordData)
: AbstractCardCommand(mCommand), mSfi(sfi), mData(newRecordData)

{

    const uint8_t cla = calypsoCardClass.getValue();
    const uint8_t p1 = 0x00;
    const uint8_t p2 = (sfi == 0) ? 0x00 : sfi * 8;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, newRecordData)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h";

    addSubName(extraInfo.str());
}

bool CmdCardAppendRecord::isSessionBufferUsed() const
{
    return true;
}

int CmdCardAppendRecord::getSfi() const
{
    return mSfi;
}

const std::vector<uint8_t>& CmdCardAppendRecord::getData() const
{
    return mData;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardAppendRecord::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 value not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6400,
              std::make_shared<StatusProperties>("Too many modifications in session.",
                                                 typeid(CardSessionBufferOverflowException))});
    m.insert({0x6981,
              std::make_shared<StatusProperties>("The current EF is not a Cyclic EF.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (no session, " \
                                                 "wrong key).",
                                                  typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode, DF is " \
                                                 "invalidated, etc..).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Command not allowed (no current EF).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found.",
                                                 typeid(CardDataAccessException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardAppendRecord::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
