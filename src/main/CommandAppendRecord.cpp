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

#include "keyple/card/calypso/CommandAppendRecord.hpp"

#include <map>
#include <memory>
#include <string>
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
    CommandAppendRecord::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6B00,
              std::make_shared<Command::StatusProperties>(
                  "P1 or P2 value not supported",
                  typeid(CardIllegalParameterException))},
             {0x6700,
              std::make_shared<Command::StatusProperties>(
                  "Lc value not supported", typeid(CardDataAccessException))},
             {0x6400,
              std::make_shared<Command::StatusProperties>(
                  "Too many modifications in session",
                  typeid(CardSessionBufferOverflowException))},
             {0x6981,
              std::make_shared<Command::StatusProperties>(
                  "The current EF is not a Cyclic EF",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<Command::StatusProperties>(
                  "Security conditions not fulfilled (no session, wrong key)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<Command::StatusProperties>(
                  "Access forbidden (Never access mode, DF is invalidated, "
                  "etc..)",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<Command::StatusProperties>(
                  "Command not allowed (no current EF)",
                  typeid(CardDataAccessException))},
             {0x6A82,
              std::make_shared<Command::StatusProperties>(
                  "File not found", typeid(CardDataAccessException))}});
        return m;
    }();

CommandAppendRecord::CommandAppendRecord(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    int sfi,
    const std::vector<std::uint8_t>& data)
: Command(
      CardCommandRef::APPEND_RECORD,
      std::unique_ptr<int>(new int(0)),
      transactionContext,
      commandContext)
, mSfi(sfi)
, mData(data)
{
    const std::uint8_t p1 = 0x00;
    const std::uint8_t p2 = (sfi == 0) ? 0x00 : (sfi * 8);

    /* APDU Case 3 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            transactionContext->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            p1,
            p2,
            data)));

    addSubName(
        std::string("SFI: ") + HexUtil::toHex(static_cast<std::uint8_t>(sfi))
        + "h");
}

void
CommandAppendRecord::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandAppendRecord::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandAppendRecord::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (getCommandContext()->isEncryptionActive()) {
        return false;
    }

    updateTerminalSessionIfNeeded(APDU_RESPONSE_9000);

    return true;
}

void
CommandAppendRecord::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);
    getTransactionContext()->getCard()->addCyclicContent(mSfi, mData);
    updateTerminalSessionIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandAppendRecord::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
