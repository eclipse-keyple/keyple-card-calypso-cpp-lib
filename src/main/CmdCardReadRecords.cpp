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

#include "CmdCardReadRecords.h"

#include <sstream>

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityContextException.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const CalypsoCardCommand CmdCardReadRecords::mCommand = CalypsoCardCommand::READ_RECORDS;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardReadRecords::STATUS_TABLE = initStatusTable();

CmdCardReadRecords::CmdCardReadRecords(const CalypsoCardClass calypsoCardClass,
                                       const int sfi,
                                       const int firstRecordNumber,
                                       const ReadMode readMode,
                                       const int expectedLength)
: AbstractCardCommand(mCommand),
  mSfi(sfi),
  mFirstRecordNumber(firstRecordNumber),
  mReadMode(readMode)
{
    const uint8_t p1 = firstRecordNumber;
    uint8_t p2 = sfi == 0x00 ? 0x05 : (sfi * 8) + 5;
    if (readMode == ReadMode::ONE_RECORD) {
        p2 -= 0x01;
    }
    const uint8_t le = expectedLength;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(
                calypsoCardClass.getValue(), mCommand.getInstructionByte(), p1, p2, le)));


    std::stringstream extraInfo;
    extraInfo << "SFI: " << sfi << "h, "
              << "REC: " << firstRecordNumber << ", "
              << "READMODE: " << readMode << ", "
              << "EXPECTEDLENGTH: " << expectedLength;
    addSubName(extraInfo.str());
}

bool CmdCardReadRecords::isSessionBufferUsed() const
{
    return false;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardReadRecords::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6981,
              std::make_shared<StatusProperties>("Command forbidden on binary files",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (PIN code " \
                                                 "not presented, encryption required).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode, stored " \
                                                 "value log file and a stored value operation was" \
                                                 " done during the current session).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Command not allowed (no current EF)",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found (record index is 0, or above " \
                                                 "NumRec",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P2 value not supported",
                                                 typeid(CardIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardReadRecords::getStatusTable() const
{
    return STATUS_TABLE;
}

CmdCardReadRecords& CmdCardReadRecords::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::setApduResponse(apduResponse);

    if (apduResponse->getDataOut().size() > 0) {
        if (mReadMode == CmdCardReadRecords::ReadMode::ONE_RECORD) {
            mRecords.insert({mFirstRecordNumber, apduResponse->getDataOut()});
        } else {
            const std::vector<uint8_t> mApdu = apduResponse->getDataOut();
            int apduLen = mApdu.size();
            int index = 0;
            while (apduLen > 0) {
                const uint8_t recordNb = mApdu[index++];
                const uint8_t len = mApdu[index++];
                mRecords.insert({recordNb, Arrays::copyOfRange(mApdu, index, index + len)});
                index = index + len;
                apduLen -= (2 + len);
            }
        }
    }

    return *this;
}

int CmdCardReadRecords::getSfi() const
{
    return mSfi;
}

int CmdCardReadRecords::getFirstRecordNumber() const
{
    return mFirstRecordNumber;
}

CmdCardReadRecords::ReadMode CmdCardReadRecords::getReadMode() const
{
    return mReadMode;
}

const std::map<const int, const std::vector<uint8_t>>& CmdCardReadRecords::getRecords() const
{
    return mRecords;
}

std::ostream& operator<<(std::ostream& os, const CmdCardReadRecords::ReadMode rm)
{
    os << "READ_MODE: ";

    switch (rm) {
    case CmdCardReadRecords::ReadMode::MULTIPLE_RECORD:
        os << "MULTIPLE_RECORD";
        break;
    case CmdCardReadRecords::ReadMode::ONE_RECORD:
        os << "ONE_RECORD";
        break;
    default:
        os << "UNKNOWN";
        break;
    }

    return os;
}

}
}
}
