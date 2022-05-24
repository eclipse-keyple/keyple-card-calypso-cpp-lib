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

#include "CmdCardReadRecordMultiple.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"

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
using namespace keyple::core::util::cpp;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardReadRecordMultiple::STATUS_TABLE = initStatusTable();

CmdCardReadRecordMultiple::CmdCardReadRecordMultiple(
    const CalypsoCardClass calypsoCardClass,
    const uint8_t sfi,
    const uint8_t recordNumber,
    const uint8_t offset,
    const uint8_t length)
: AbstractCardCommand(CalypsoCardCommand::READ_RECORD_MULTIPLE),
  mSfi(sfi),
  mRecordNumber(recordNumber),
  mOffset(offset),
  mLength(length)
{
    const uint8_t p2 = (sfi * 8 + 5);
    const std::vector<uint8_t> dataIn = {0x54, 0x02, offset, length};

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            getCommandRef().getInstructionByte(),
                            recordNumber,
                            p2,
                            dataIn,
                            0)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "RECORD_NUMBER:" << recordNumber << ", "
              << "OFFSET:" << offset << ", "
              << "LENGTH:" << length;

    addSubName(extraInfo.str());
}

bool CmdCardReadRecordMultiple::isSessionBufferUsed() const
{
    return false;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardReadRecordMultiple::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported (<4).",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6981,
              std::make_shared<StatusProperties>("Incorrect EF type: Binary EF.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (PIN code " \
                                                 "not presented, encryption required).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode, Stored " \
                                                 "Value log file and a Stored Value operation was" \
                                                 " done during the current secure session).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Incorrect file type: the Current File is not " \
                                                 "an EF. Supersedes 6981h.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect command data (incorrect Tag, " \
                                                 "incorrect Length, R. Length > RecSize, R. " \
                                                 "Offset + R. Length > RecSize, R. Length = 0).",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found (record index is 0, or above " \
                                                 "NumRec).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 value not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6200,
              std::make_shared<StatusProperties>("Successful execution, partial read only: issue " \
                                                 "another Read Record Multiple from record (P1 + " \
                                                 "(Size of returned data) / (R. Length)) to " \
                                                 "continue reading.")});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardReadRecordMultiple::getStatusTable() const
{
    return STATUS_TABLE;
}

CmdCardReadRecordMultiple& CmdCardReadRecordMultiple::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::setApduResponse(apduResponse);

    if (apduResponse->getDataOut().size() > 0) {
        const std::vector<uint8_t> dataOut = apduResponse->getDataOut();
        const int nbRecords = dataOut.size() / mLength;
        for (int i = 0; i < nbRecords; i++) {
            mResults.insert({mRecordNumber + i,
                             Arrays::copyOfRange(dataOut, i * mLength, (i + 1) * mLength)});
        }
    }

    return *this;
}

int CmdCardReadRecordMultiple::getSfi() const
{
    return mSfi;
}

uint8_t CmdCardReadRecordMultiple::getOffset() const
{
    return mOffset;
}

const std::map<const int, const std::vector<uint8_t>>& CmdCardReadRecordMultiple::getResults() const
{
    return mResults;
}

}
}
}
