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

#include "CmdCardSearchRecordMultiple.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "System.h"

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
    CmdCardSearchRecordMultiple::STATUS_TABLE = initStatusTable();

CmdCardSearchRecordMultiple::CmdCardSearchRecordMultiple(
  const CalypsoCardClass calypsoCardClass,
  const std::shared_ptr<SearchCommandDataAdapter> data)
: AbstractCardCommand(CalypsoCardCommand::SEARCH_RECORD_MULTIPLE),
  mData(data)
{
    const int searchDataLength = data->getSearchData().size();
    const uint8_t p2 = data->getSfi() * 8 + 7;

    std::vector<uint8_t> dataIn(3 + (2 * searchDataLength));
    if (data->isEnableRepeatedOffset()) {
        dataIn[0] = 0x80;
    }

    if (data->isFetchFirstMatchingResult()) {
        dataIn[0] |= 1;
    }

    dataIn[1] = data->getOffset();
    dataIn[2] = searchDataLength;

    System::arraycopy(data->getSearchData(), 0, dataIn, 3, searchDataLength);

    if (data->getMask().empty()) {
        /* CL-CMD-SEARCH.1 */
        Arrays::fill(dataIn,
                     dataIn.size() - searchDataLength,
                     dataIn.size(),
                     static_cast<uint8_t>(0xFF));
    } else {
        System::arraycopy(data->getMask(),
                          0,
                          dataIn,
                          dataIn.size() - searchDataLength,
                          data->getMask().size());
    if (static_cast<int>(data->getMask().size()) != searchDataLength) {
        /* CL-CMD-SEARCH.1 */
        Arrays::fill(dataIn,
                     dataIn.size() - searchDataLength + data->getMask().size(),
                     dataIn.size(),
                     static_cast<uint8_t>(0xFF));
    }
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            getCommandRef().getInstructionByte(),
                            data->getRecordNumber(),
                            p2,
                            dataIn,
                            0)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << data->getSfi() << "h, "
              << "RECORD_NUMBER:" << data->getRecordNumber() << ", "
              << "OFFSET:" << data->getOffset() << ", "
              << "REPEATED_OFFSET:" << data->isEnableRepeatedOffset() << ", "
              << "FETCH_FIRST_RESULT:" << data->isFetchFirstMatchingResult() << ", "
              << "SEARCH_DATA:" << ByteArrayUtil::toHex(data->getSearchData()) << "h, "
              << "MASK:" << ByteArrayUtil::toHex(data->getMask()) << "h";

    addSubName(extraInfo.str());
}

bool CmdCardSearchRecordMultiple::isSessionBufferUsed() const
{
    return false;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSearchRecordMultiple::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6400,
              std::make_shared<StatusProperties>("Data Out overflow (outgoing data would be too" \
                                                 " long).",
                                                 typeid(CardSessionBufferOverflowException))});
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
                                                 "done during the current secure session).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Incorrect file type: the Current File is not " \
                                                 "an EF. Supersedes 6981h.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect command data (S. Length incompatible " \
                                                 "with Lc, S. Length > RecSize, S. Offset + S. " \
                                                 "Length > RecSize, S. Mask bigger than S. Data).",
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

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardSearchRecordMultiple::getStatusTable() const
{
    return STATUS_TABLE;
}

CmdCardSearchRecordMultiple& CmdCardSearchRecordMultiple::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::setApduResponse(apduResponse);

    if (apduResponse->getDataOut().size() > 0) {
        const std::vector<uint8_t> dataOut = apduResponse->getDataOut();

        const int nbRecords = dataOut[0];
        for (int i = 1; i <= nbRecords; i++) {
            mData->getMatchingRecordNumbers().push_back(dataOut[i]);
        }

        if (mData->isFetchFirstMatchingResult() && nbRecords > 0) {
            mFirstMatchingRecordContent =
                Arrays::copyOfRange(dataOut, nbRecords + 1, dataOut.size());
        }
    }

    return *this;
}

const std::shared_ptr<SearchCommandDataAdapter> CmdCardSearchRecordMultiple::getSearchCommandData()
    const
{
    return mData;
}

const std::vector<uint8_t> CmdCardSearchRecordMultiple::getFirstMatchingRecordContent() const
{
    return !mFirstMatchingRecordContent.empty() ?
               mFirstMatchingRecordContent : std::vector<uint8_t>();
}

}
}
}
