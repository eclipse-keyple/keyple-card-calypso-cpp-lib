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

#include "keyple/card/calypso/CommandGetChallenge.hpp"

#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/core/util/ApduUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;

CommandGetChallenge::CommandGetChallenge(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
: Command(
      CardCommandRef::GET_CHALLENGE,
      std::unique_ptr<int>(new int(8)),
      transactionContext,
      commandContext)
{
    /* APDU Case 2 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            0x00,
            0x00,
            static_cast<std::uint8_t>(8))));
}

void
CommandGetChallenge::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandGetChallenge::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandGetChallenge::synchronizeCryptoServiceBeforeCardProcessing()
{
    /* Need to synchronize the card image with the challenge. */
    return false;
}

void
CommandGetChallenge::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);
    getTransactionContext()->getCard()->setChallenge(
        getApduResponse()->getDataOut());
    updateTerminalSessionIfNeeded();
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
