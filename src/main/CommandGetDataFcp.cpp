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

#include "keyple/card/calypso/CommandGetDataFcp.hpp"

#include <map>
#include <memory>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardClass.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardCommandRef.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CommandSelectFile.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/BerTlvUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::BerTlvUtil;
using keyple::core::util::HexUtil;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandGetDataFcp::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6A88,
              std::make_shared<StatusProperties>(
                  "Data object not found (optional mode not "
                  "available)",
                  typeid(CardDataAccessException))},
             {0x6A82,
              std::make_shared<StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "P1 or P2 value not supported",
                  typeid(CardDataAccessException))}});
        return m;
    }();

CommandGetDataFcp::CommandGetDataFcp(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
: Command(CardCommandRef::GET_DATA, nullptr, transactionContext, commandContext)
{
    const std::uint8_t cardClass
        = transactionContext->getCard() != nullptr
              ? transactionContext->getCard()->getCardClass().getValue()
              : CalypsoCardClass::ISO.getValue();

    /* APDU Case 2 - always outside secure session */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            cardClass,
            getCommandRef().getInstructionByte(),
            CalypsoCardConstant::TAG_FCP_FOR_CURRENT_FILE_MSB,
            CalypsoCardConstant::TAG_FCP_FOR_CURRENT_FILE_LSB,
            0x00)));

    addSubName("FCP_FOR_CURRENT_FILE");
}

void
CommandGetDataFcp::finalizeRequest()
{
    /* NOP */
}

bool
CommandGetDataFcp::isCryptoServiceRequiredToFinalizeRequest() const
{
    return false;
}

bool
CommandGetDataFcp::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandGetDataFcp::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);

    CommandSelectFile::parseProprietaryInformation(
        apduResponse->getDataOut(), getTransactionContext()->getCard());
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandGetDataFcp::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
