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

#include "keyple/card/calypso/CommandSearchRecordMultiple.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSessionBufferOverflowException.hpp"
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
    CommandSearchRecordMultiple::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6400,
              std::make_shared<Command::StatusProperties>(
                  "Data Out overflow (outgoing data would be too long)",
                  typeid(CardSessionBufferOverflowException))},
             {0x6700,
              std::make_shared<Command::StatusProperties>(
                  "Lc value not supported (<4)",
                  typeid(CardIllegalParameterException))},
             {0x6981,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect EF type: Binary EF",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<Command::StatusProperties>(
                  "Security conditions not fulfilled (PIN code not presented, "
                  "encryption required)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<Command::StatusProperties>(
                  "Access forbidden (Never access mode, Stored Value log file "
                  "and a Stored Value operation was done during the current "
                  "secure session)",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect file type: the Current File is not an EF. "
                  "Supersedes 6981h",
                  typeid(CardDataAccessException))},
             {0x6A80,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect command data (S. Length incompatible with Lc, S. "
                  "Length > RecSize, S. Offset + S. Length > RecSize, S. Mask "
                  "bigger than S. Data)",
                  typeid(CardIllegalParameterException))},
             {0x6A82,
              std::make_shared<Command::StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6A83,
              std::make_shared<Command::StatusProperties>(
                  "Record not found (record index is 0, or above NumRec",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<Command::StatusProperties>(
                  "P2 value not supported",
                  typeid(CardIllegalParameterException))}});

        return m;
    }();

CommandSearchRecordMultiple::CommandSearchRecordMultiple(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    const std::shared_ptr<DtoAdapters::SearchCommandDataAdapter> data)
: Command(
      CardCommandRef::SEARCH_RECORD_MULTIPLE,
      nullptr,
      transactionContext,
      commandContext)
, mData(data)
{
    const int searchDataLength = static_cast<int>(data->getSearchData().size());
    const uint8_t p2 = data->getSfi() * 8 + 7;

    std::vector<uint8_t> dataIn(3 + (2 * searchDataLength));
    if (data->isEnableRepeatedOffset()) {
        dataIn[0] = 0x80;
    }

    if (data->isFetchFirstMatchingResult()) {
        dataIn[0] |= 1;
    }

    dataIn[1] = static_cast<uint8_t>(data->getOffset());
    dataIn[2] = static_cast<uint8_t>(searchDataLength);

    System::arraycopy(data->getSearchData(), 0, dataIn, 3, searchDataLength);

    if (data->getMask().empty()) {
        /* CL-CMD-SEARCH.1 */
        Arrays::fill(
            dataIn,
            dataIn.size() - searchDataLength,
            dataIn.size(),
            static_cast<uint8_t>(0xFF));

    } else {
        System::arraycopy(
            data->getMask(),
            0,
            dataIn,
            dataIn.size() - searchDataLength,
            data->getMask().size());

        if (static_cast<int>(data->getMask().size()) != searchDataLength) {
            /* CL-CMD-SEARCH.1 */
            Arrays::fill(
                dataIn,
                dataIn.size() - searchDataLength + data->getMask().size(),
                dataIn.size(),
                static_cast<uint8_t>(0xFF));
        }
    }

    /* APDU Case 4 - always outside secure session */
    setApduRequestInBestEffortMode(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            transactionContext->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            data->getRecordNumber(),
            p2,
            dataIn,
            0x00)));

    const std::string extraInfo
        = "SFI: " + HexUtil::toHex(data->getSfi())
          + "h, Rec: " + std::to_string(data->getRecordNumber()) + ", Offset: "
          + std::to_string(data->getOffset()) + ", Repeated offset: "
          + std::to_string(data->isEnableRepeatedOffset())
          + ", Fetch first result: "
          + std::to_string(data->isFetchFirstMatchingResult())
          + ", Search data: " + HexUtil::toHex(data->getSearchData()) + "h,"
          + " Mask: " + HexUtil::toHex(data->getMask()) + "h";

    addSubName(extraInfo);
}

void
CommandSearchRecordMultiple::finalizeRequest()
{
    /* NOP */
}

bool
CommandSearchRecordMultiple::isCryptoServiceRequiredToFinalizeRequest() const
{
    return false;
}

bool
CommandSearchRecordMultiple::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandSearchRecordMultiple::getStatusTable() const
{
    return STATUS_TABLE;
}

void
CommandSearchRecordMultiple::parseResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    if (!setApduResponseAndCheckStatusInBestEffortMode(apduResponse)) {
        return;
    }

    const std::vector<uint8_t> dataOut = apduResponse->getDataOut();
    const int nbRecords = dataOut[0];

    for (int i = 1; i <= nbRecords; i++) {
        mData->getMatchingRecordNumbers().push_back(dataOut[i]);
    }

    if (mData->isFetchFirstMatchingResult() && nbRecords > 0) {
        getTransactionContext()->getCard()->setContent(
            mData->getSfi(),
            mData->getMatchingRecordNumbers()[0],
            Arrays::copyOfRange(dataOut, nbRecords + 1, dataOut.size()));
    }
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
