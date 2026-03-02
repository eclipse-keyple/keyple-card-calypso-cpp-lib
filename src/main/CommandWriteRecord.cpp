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

#include "keyple/card/calypso/CommandWriteRecord.hpp"

#include <map>
#include <memory>
#include <sstream>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardClass.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardCommandRef.hpp"
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
    CommandWriteRecord::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6400,
              std::make_shared<Command::StatusProperties>(
                  "Too many modifications in session",
                  typeid(CardSessionBufferOverflowException))},
             {0x6700,
              std::make_shared<Command::StatusProperties>(
                  "Lc value not supported", typeid(CardDataAccessException))},
             {0x6981,
              std::make_shared<Command::StatusProperties>(
                  "Wrong EF type (not a Linear EF, or Cyclic EF with Record "
                  "Number 01h)",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<Command::StatusProperties>(
                  "Security conditions not fulfilled (no session, wrong key, "
                  "encryption required)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<Command::StatusProperties>(
                  "Access forbidden (Never access mode, DF is invalidated, "
                  "etc..)",
                  typeid(CardSecurityContextException))},
             {0x6986,
              std::make_shared<Command::StatusProperties>(
                  "Command not allowed (no current EF)",
                  typeid(CardDataAccessException))},
             {0x6A82,
              std::make_shared<Command::StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6A83,
              std::make_shared<Command::StatusProperties>(
                  "Record is not found (record index is 0 or above NumRec)",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<Command::StatusProperties>(
                  "P2 value not supported",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandWriteRecord::CommandWriteRecord(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::uint8_t sfi,
    std::uint8_t recordNumber,
    const std::vector<std::uint8_t>& newRecordData)
: Command(
      CardCommandRef::WRITE_RECORD,
      std::unique_ptr<int>(new int(0)),
      transactionContext,
      commandContext)
, mSfi(sfi)
, mRecordNumber(recordNumber)
, mData(newRecordData)
{
    const std::uint8_t p2 = (sfi == 0) ? 0x04 : sfi * 8 + 4;

    // APDU Case 3
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            transactionContext->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            mRecordNumber,
            p2,
            newRecordData)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "REC:" << recordNumber;

    addSubName(extraInfo.str());
}

void
CommandWriteRecord::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandWriteRecord::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandWriteRecord::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (getCommandContext()->isEncryptionActive()) {
        return false;
    }

    updateTerminalSessionIfNeeded(APDU_RESPONSE_9000);

    return true;
}

void
CommandWriteRecord::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);
    getTransactionContext()->getCard()->fillContent(
        mSfi, mRecordNumber, mData, 0);
    updateTerminalSessionIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandWriteRecord::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
