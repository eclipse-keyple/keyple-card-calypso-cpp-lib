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

#include "keyple/card/calypso/CommandUpdateOrWriteBinary.hpp"

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
    CommandUpdateOrWriteBinary::STATUS_TABLE = [] {
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
                  "Incorrect EF type: not a Binary EF",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<Command::StatusProperties>(
                  "Security conditions not fulfilled (no secure session, "
                  "incorrect key, encryption required, PKI mode and not Always "
                  "access mode)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<Command::StatusProperties>(
                  "Access forbidden (Never access mode, DF is invalidated, "
                  "etc..)",
                  typeid(CardSecurityContextException))},
             {0x6986,
              std::make_shared<Command::StatusProperties>(
                  "Incorrect file type: the Current File is not an EF. "
                  "Supersedes 6981h",
                  typeid(CardDataAccessException))},
             {0x6A82,
              std::make_shared<Command::StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6A83,
              std::make_shared<Command::StatusProperties>(
                  "Offset not in the file (offset overflow)",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<Command::StatusProperties>(
                  "P1 value not supported",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandUpdateOrWriteBinary::CommandUpdateOrWriteBinary(
    bool isUpdateCommand,
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::uint8_t sfi,
    int offset,
    const std::vector<uint8_t>& data)
: Command(
      isUpdateCommand ? CardCommandRef::UPDATE_BINARY
                      : CardCommandRef::WRITE_BINARY,
      std::unique_ptr<int>(new int(0)),
      transactionContext,
      commandContext)
, mSfi(sfi)
, mOffset(offset)
, mData(data)
{
    const std::uint8_t msb
        = static_cast<std::uint8_t>((offset & 0x0000FF00) >> 8);
    const std::uint8_t lsb = static_cast<std::uint8_t>((offset & 0x000000FF));

    /*
     * 100xxxxx : 'xxxxx' = SFI of the EF to select.
     * 0xxxxxxx : 'xxxxxxx' = MSB of the offset of the first byte.
     */
    const std::uint8_t p1 = msb > 0 ? msb : (0x80 + sfi);

    // APDU Case 3
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            transactionContext->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            p1,
            lsb,
            data)));

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "Offset:" << offset;

    addSubName(extraInfo.str());
}

void
CommandUpdateOrWriteBinary::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandUpdateOrWriteBinary::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandUpdateOrWriteBinary::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (getCommandContext()->isEncryptionActive()) {
        return false;
    }

    updateTerminalSessionIfNeeded(APDU_RESPONSE_9000);

    return true;
}

void
CommandUpdateOrWriteBinary::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);

    if (getCommandRef() == CardCommandRef::UPDATE_BINARY) {
        getTransactionContext()->getCard()->setContent(mSfi, 1, mData, mOffset);

    } else {
        getTransactionContext()->getCard()->fillContent(
            mSfi, 1, mData, mOffset);
    }

    updateTerminalSessionIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandUpdateOrWriteBinary::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
