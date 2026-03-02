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

#include "keyple/card/calypso/CommandReadRecordMultiple.hpp"

#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandReadRecordMultiple::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<Command::StatusProperties>(
                  "Lc value not supported",
                  typeid(CardIllegalParameterException))},
             {0x6981,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect EF type: Binary EF",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<Command::StatusProperties>(
                  "Security conditions not fulfilled (PIN code not presented,"
                  " encryption required)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<Command::StatusProperties>(
                  "Access forbidden (Never access mode, Stored value log file"
                  " and a Stored value operation was done during the current "
                  "session)",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect file type: the Current File is not an EF. "
                  "Supersedes 6981h",
                  typeid(CardDataAccessException))},
             {0x6A80,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect command data (incorrect Tag, incorrect Length, "
                  "R. Length > RecSize, R. Offset + R. Length > RecSize, R. "
                  "Length = 0)",
                  typeid(CardIllegalParameterException))},
             {0x6A82,
              std::make_shared<Command::StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6A83,
              std::make_shared<Command::StatusProperties>(
                  "Record not found (record index is 0, or above NumRec)",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<Command::StatusProperties>(
                  "P1 or P2 value not supported",
                  typeid(CardIllegalParameterException))},
             {0x6200,
              std::make_shared<Command::StatusProperties>(
                  "Successful execution, partial read only: issue another "
                  "Read Record Multiple from record (P1 + (Size of returned "
                  "data) / (R. Length)) to continue reading")}});
        return m;
    }();

CommandReadRecordMultiple::CommandReadRecordMultiple(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::uint8_t sfi,
    std::uint8_t recordNumber,
    std::uint8_t offset,
    std::uint8_t length)
: Command(
      CardCommandRef::READ_RECORD_MULTIPLE,
      nullptr,
      transactionContext,
      commandContext)
, mSfi(sfi)
, mRecordNumber(recordNumber)
, mOffset(offset)
, mLength(length)
{
    const uint8_t p2 = (sfi * 8 + 5);
    const std::vector<uint8_t> dataIn = {0x54, 0x02, offset, length};

    /* APDU Case 4 - always outside secure session */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            transactionContext->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            recordNumber,
            p2,
            dataIn)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "RECORD_NUMBER:" << recordNumber << ", "
              << "OFFSET:" << offset << ", "
              << "LENGTH:" << length;

    addSubName(extraInfo.str());
}

void
CommandReadRecordMultiple::finalizeRequest()
{
    /* NOP */
}

bool
CommandReadRecordMultiple::isCryptoServiceRequiredToFinalizeRequest() const
{
    return false;
}

bool
CommandReadRecordMultiple::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandReadRecordMultiple::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    if (!setApduResponseAndCheckStatusInBestEffortMode(apduResponse)) {
        return;
    }

    const std::vector<std::uint8_t> dataOut = apduResponse->getDataOut();
    const int nbRecords = dataOut.size() / mLength;

    for (int i = 0; i < nbRecords; i++) {
        getTransactionContext()->getCard()->setContent(
            mSfi,
            mRecordNumber + i,
            Arrays::copyOfRange(dataOut, i * mLength, (i + 1) * mLength),
            mOffset);
    }
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandReadRecordMultiple::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
