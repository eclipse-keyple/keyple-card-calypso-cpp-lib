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

#include "keyple/card/calypso/CommandRatification.hpp"

#include <memory>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/core/util/ApduUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;

CommandRatification::CommandRatification(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
: Command(
      CardCommandRef::RATIFICATION,
      std::unique_ptr<int>(new int(0)),
      transactionContext,
      commandContext)
{
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            0x00,
            0x00)));
}

void
CommandRatification::finalizeRequest()
{
    /* NOP */
}

bool
CommandRatification::isCryptoServiceRequiredToFinalizeRequest() const
{
    return false;
}

bool
CommandRatification::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandRatification::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    try {
        Command::setApduResponseAndCheckStatus(apduResponse);

    } catch (const CardCommandException& e) {
        /* NOP: ratification nominal case */
    }
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
