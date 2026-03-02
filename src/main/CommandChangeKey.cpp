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

#include "keyple/card/calypso/CommandChangeKey.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
#include "keyple/card/calypso/CardTerminatedException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandChangeKey::STATUS_TABLE = [] {
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

CommandChangeKey::CommandChangeKey(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::uint8_t keyIndex,
    std::uint8_t newKif,
    std::uint8_t newKvc,
    std::uint8_t issuerKif,
    std::uint8_t issuerKvc)
: Command(CardCommandRef::CHANGE_KEY, 0, transactionContext, commandContext)
, mKeyIndex(keyIndex)
, mNewKif(newKif)
, mNewKvc(newKvc)
, mIssuerKif(issuerKif)
, mIssuerKvc(issuerKvc)
{
}

void
CommandChangeKey::finalizeRequest()
{
    std::vector<std::uint8_t> cipheredKey;

    try {
        cipheredKey
            = getTransactionContext()
                  ->getSymmetricCryptoCardTransactionManagerSpi()
                  ->generateCipheredCardKey(
                      getTransactionContext()->getCard()->getChallenge(),
                      mIssuerKif,
                      mIssuerKvc,
                      mNewKif,
                      mNewKvc);

    } catch (const SymmetricCryptoException& e) {
        throw CryptoException(e.what(), e);

    } catch (const SymmetricCryptoIOException& e) {
        throw CryptoIOException(e.what(), e);
    }

    /* APDU Case 3 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            0x00,
            mKeyIndex,
            cipheredKey)));
}

bool
CommandChangeKey::isCryptoServiceRequiredToFinalizeRequest() const
{
    return true;
}

bool
CommandChangeKey::synchronizeCryptoServiceBeforeCardProcessing()
{
    return true;
}

void
CommandChangeKey::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandChangeKey::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
