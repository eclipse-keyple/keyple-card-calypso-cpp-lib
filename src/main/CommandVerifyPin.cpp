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

#include "keyple/card/calypso/CommandVerifyPin.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardPinException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
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

const CardCommandRef CommandVerifyPin::mCommandRef = CardCommandRef::VERIFY_PIN;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandVerifyPin::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Lc value not supported (only 00h, 04h or 08h are supported)",
                  typeid(CardIllegalParameterException))},
             {0x6900,
              std::make_shared<StatusProperties>(
                  "Transaction Counter is 0", typeid(CardTerminatedException))},
             {0x6982,
              std::make_shared<StatusProperties>(
                  std::string("Security conditions not fulfilled (Get ")
                      + "Challenge not done: challenge unavailable)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Access forbidden (a session is open or DF is invalidated)",
                  typeid(CardAccessForbiddenException))},
             {0x63C1,
              std::make_shared<StatusProperties>(
                  "Incorrect PIN (1 attempt remaining)",
                  typeid(CardPinException))},
             {0x63C2,
              std::make_shared<StatusProperties>(
                  "Incorrect PIN (2 attempt remaining)",
                  typeid(CardPinException))},
             {0x6983,
              std::make_shared<StatusProperties>(
                  "Presentation rejected (PIN is blocked)",
                  typeid(CardPinException))},
             {0x6D00,
              std::make_shared<StatusProperties>(
                  "PIN function not present",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandVerifyPin::CommandVerifyPin(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    const std::vector<std::uint8_t>& pin,
    std::uint8_t cipheringKif,
    std::uint8_t cipheringKvc)
/* CL-CSS-RESPLE.1 */
: Command(mCommandRef, 0, transactionContext, commandContext)
, mPin(pin)
, mIsReadCounterMode(false)
, mIsPinEncryptedMode(true)
, mCipheringKif(cipheringKif)
, mCipheringKvc(cipheringKvc)
{
}

CommandVerifyPin::CommandVerifyPin(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    const std::vector<std::uint8_t>& pin)
: Command(mCommandRef, 0, transactionContext, commandContext)
, mPin(pin)
, mIsReadCounterMode(false)
, mIsPinEncryptedMode(false)
, mCipheringKif(0)
, mCipheringKvc(0)
{
}

CommandVerifyPin::CommandVerifyPin(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
: Command(mCommandRef, 0, transactionContext, commandContext)
, mPin({})
, mIsReadCounterMode(true)
, mIsPinEncryptedMode(false)
, mCipheringKif(0)
, mCipheringKvc(0)
{
}

void
CommandVerifyPin::finalizeRequest()
{
    if (mIsPinEncryptedMode) {
        try {
            mPin = getTransactionContext()
                       ->getSymmetricCryptoCardTransactionManagerSpi()
                       ->cipherPinForPresentation(
                           getTransactionContext()->getCard()->getChallenge(),
                           mPin,
                           std::make_shared<std::uint8_t>(mCipheringKif),
                           std::make_shared<std::uint8_t>(mCipheringKvc));

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw CryptoIOException(e.what(), e);
        }
    }

    /* APDU Case 1 (check status) or 3 (verify) */
    std::vector<std::uint8_t> apdu;

    if (!mPin.empty()) {
        apdu = ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            mCommandRef.getInstructionByte(),
            0x00, /* CL-PIN-PP1P2.1 */
            0x00,
            mPin); /* CL-C1-5BYTE.1 */
    } else {
        apdu = ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            mCommandRef.getInstructionByte(),
            0x00, /* CL-PIN-PP1P2.1 */
            0x00,
            0x00); /* CL-C1-5BYTE.1 */
    }
    setApduRequest(std::make_shared<DtoAdapters::ApduRequestAdapter>(apdu));

    addSubName(
        mIsReadCounterMode    ? "Read presentation counter"
        : mIsPinEncryptedMode ? "Encrypted"
                              : "Plain");

    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandVerifyPin::isCryptoServiceRequiredToFinalizeRequest() const
{
    return mIsPinEncryptedMode || getCommandContext()->isEncryptionActive();
}

bool
CommandVerifyPin::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (getCommandContext()->isEncryptionActive()) {
        return false;
    }

    updateTerminalSessionIfNeeded(APDU_RESPONSE_9000);

    return true;
}

void
CommandVerifyPin::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);

    try {
        Command::setApduResponseAndCheckStatus(apduResponse);
        getTransactionContext()->getCard()->setPinAttemptRemaining(3);

    } catch (const CardPinException& e) {
        switch (apduResponse->getStatusWord()) {
        case 0x63C2:
            getTransactionContext()->getCard()->setPinAttemptRemaining(2);
            break;
        case 0x63C1:
            getTransactionContext()->getCard()->setPinAttemptRemaining(1);
            break;
        case 0x6983:
            getTransactionContext()->getCard()->setPinAttemptRemaining(0);
            break;
        default: {
            /* NOP */
        }
        }

        /*
         * Throw a functional exception if the operation do not target the
         * reading of the attempt counter. Catch it silently otherwise.
         */
        if (!mIsReadCounterMode) {
            throw InvalidPinException(
                std::string("Invalid PIN. Remaining ")
                + std::to_string(
                    getTransactionContext()
                        ->getCard()
                        ->getPinAttemptRemaining())
                + " attempt(s)");
        }
    }

    updateTerminalSessionIfNeeded();
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandVerifyPin::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
