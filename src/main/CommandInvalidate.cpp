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

#include "keyple/card/calypso/CommandInvalidate.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
#include "keyple/card/calypso/CardSessionBufferOverflowException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/card/transaction/InvalidCardSignatureException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalStateException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::card::transaction::InvalidCardSignatureException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandInvalidate::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6400,
              std::make_shared<StatusProperties>(
                  "Too many modifications in session",
                  typeid(CardSessionBufferOverflowException))},
             {0x6700,
              std::make_shared<StatusProperties>(
                  "Lc value not supported",
                  typeid(CardIllegalParameterException))},
             {0x6982,
              std::make_shared<StatusProperties>(
                  "Security conditions not fulfilled (no session, wrong key)",
                  typeid(CardSecurityContextException))},
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Access forbidden (DF context is invalid)",
                  typeid(CardAccessForbiddenException))}});
        return m;
    }();

CommandInvalidate::CommandInvalidate(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
/* CL-CSS-RESPLE.1: expected length may be overridden later */
: Command(CardCommandRef::INVALIDATE, 0, transactionContext, commandContext)
{
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            0x00,
            0x00,
            0x00))); /* CL-C1-5BYTE.1 */
}

void
CommandInvalidate::finalizeRequest()
{
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandInvalidate::getStatusTable() const
{
    return STATUS_TABLE;
}

bool
CommandInvalidate::isCryptoServiceRequiredToFinalizeRequest() const
{
    return getCommandContext()->isEncryptionActive();
}

bool
CommandInvalidate::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (getCommandContext()->isEncryptionActive()) {
        return false;
    }

    updateTerminalSessionIfNeeded(APDU_RESPONSE_9000);

    return true;
}

void
CommandInvalidate::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);
    updateTerminalSessionIfNeeded();

    /*
     * The DF has been successfully invalidated, update the DF status in the
     * card object.
     */
    getTransactionContext()->getCard()->setDfInvalidated(true);
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
