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

#include "CmdCardUpdateRecord.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

const CalypsoCardCommand CmdCardUpdateRecord::mCommand = CalypsoCardCommand::UPDATE_RECORD;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardUpdateRecord::STATUS_TABLE = initStatusTable();

CmdCardUpdateRecord::CmdCardUpdateRecord(const CalypsoCardClass calypsoCardClass,
                                         const uint8_t sfi,
                                         const int recordNumber,
                                         const std::vector<uint8_t>& newRecordData)
: AbstractCardCommand(mCommand),
  mSfi(sfi),
  mRecordNumber(recordNumber),
  mData(newRecordData)
{
    const uint8_t cla = calypsoCardClass.getValue();
    const uint8_t p2 = (sfi == 0) ? 0x04 : sfi * 8 + 4;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla,
                            mCommand.getInstructionByte(),
                            recordNumber,
                            p2,
                            newRecordData)));


    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "REC:" << recordNumber;

    addSubName(extraInfo.str());
}

bool CmdCardUpdateRecord::isSessionBufferUsed() const
{
    return true;
}

int CmdCardUpdateRecord::getSfi() const
{
    return mSfi;
}

int CmdCardUpdateRecord::getRecordNumber() const
{
    return mRecordNumber;
}

const std::vector<uint8_t>& CmdCardUpdateRecord::getData() const
{
    return mData;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardUpdateRecord::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6400,
              std::make_shared<StatusProperties>("Too many modifications in session.",
                                                 typeid(CardSessionBufferOverflowException))});
    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6981,
              std::make_shared<StatusProperties>("Command forbidden on cyclic files when the " \
                                                 "record exists and is not record 01h and on " \
                                                 "binary files.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (no session, " \
                                                 "wrong key, encryption required).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode, DF is " \
                                                 "invalidated, etc..).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Command not allowed (no current EF).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record is not found (record index is 0 or " \
                                                 "above NumRec).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P2 value not supported.",
                                                 typeid(CardIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardUpdateRecord::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
