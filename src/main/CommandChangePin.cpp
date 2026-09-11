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

#include "keyple/card/calypso/CommandChangePin.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
#include "keyple/card/calypso/CardTerminatedException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/card/transaction/InvalidPinException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::card::transaction::InvalidPinException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandChangePin::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Lc value not supported (not 04h, 10h, 18h, 20h)",
                  typeid(CardIllegalParameterException))},
             {0x6900,
              std::make_shared<StatusProperties>(
                  "Transaction Counter is 0", typeid(CardTerminatedException))},
             {0x6982,
              std::make_shared<StatusProperties>(
                  std::string("Security conditions not satisfied (Get ")
                      + "Challenge not done: challenge unavailable)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Access forbidden (a session is open or DF is invalidated)",
                  typeid(CardAccessForbiddenException))},
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Incorrect Cryptogram", typeid(CardSecurityDataException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Decrypted message incorrect (key algorithm not supported, "
                  "incorrect padding, etc.",
                  typeid(CardSecurityDataException))},
             {0x6A87,
              std::make_shared<StatusProperties>(
                  "Lc not compatible with P2",
                  typeid(CardIllegalParameterException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "Incorrect P1, P2", typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandChangePin::CommandChangePin(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    const std::vector<std::uint8_t>& pin)
: Command(CardCommandRef::CHANGE_PIN, 0, transactionContext, commandContext)
, mPin(pin)
, mIsPinEncryptedMode(false)
, mCipheringKif(0)
, mCipheringKvc(0)
{
}

CommandChangePin::CommandChangePin(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    const std::vector<std::uint8_t>& pin,
    std::uint8_t cipheringKif,
    std::uint8_t cipheringKvc)
: Command(CardCommandRef::CHANGE_PIN, 0, transactionContext, commandContext)
, mPin(pin)
, mIsPinEncryptedMode(true)
, mCipheringKif(cipheringKif)
, mCipheringKvc(cipheringKvc)
{
}

void
CommandChangePin::finalizeRequest()
{
    if (mIsPinEncryptedMode) {
        try {
            mPin = getTransactionContext()
                       ->getSymmetricCryptoCardTransactionManagerSpi()
                       ->cipherPinForModification(
                           getTransactionContext()->getCard()->getChallenge(),
                           std::vector<std::uint8_t>(4),
                           mPin,
                           std::make_shared<std::uint8_t>(mCipheringKif),
                           std::make_shared<std::uint8_t>(mCipheringKvc));

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw CryptoIOException(e.what(), e);
        }
    }

    /* APDU Case 3 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            0x00, /* CL-PIN-MP1P2.1 */
            0xFF,
            mPin)));
}

bool
CommandChangePin::isCryptoServiceRequiredToFinalizeRequest() const
{
    return mIsPinEncryptedMode;
}

bool
CommandChangePin::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandChangePin::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);
    /*
     * The PIN has been successfully updated, and the presentation counter is
     * reset to zero.
     */
    getTransactionContext()->getCard()->setPinAttemptRemaining(3);
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandChangePin::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
