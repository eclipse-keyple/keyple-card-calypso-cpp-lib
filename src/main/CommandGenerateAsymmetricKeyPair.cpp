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

#include "keyple/card/calypso/CommandGenerateAsymmetricKeyPair.hpp"

#include <map>
#include <memory>
#include <string>

#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
#include "keyple/card/calypso/CardTerminatedException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/card/transaction/InvalidPinException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::HexUtil;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::card::transaction::InvalidPinException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

const std::string CommandGenerateAsymmetricKeyPair::SECP256R1_OID
    = "06082A8648CE3D030107";

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandGenerateAsymmetricKeyPair::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Lc value not supported", typeid(CardDataAccessException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Conditions of use not satisfied: a secure session is "
                  "running or a card key pair already available",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<StatusProperties>(
                  "Incorrect file type: the current DF is not an autonomous "
                  "PKI application",
                  typeid(CardDataAccessException))},
             {0x6A80,
              std::make_shared<StatusProperties>(
                  "Incorrect incoming data",
                  typeid(CardIllegalParameterException))},
             {0x6D00,
              std::make_shared<StatusProperties>(
                  "PKI mode not available",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandGenerateAsymmetricKeyPair::CommandGenerateAsymmetricKeyPair(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
: Command(
      CardCommandRef::GENERATE_ASYMMETRIC_KEY_PAIR,
      std::unique_ptr<int>(new int(0)),
      transactionContext,
      commandContext)
{
    /* APDU Case 3 */
    setApduRequest(
        std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass().getValue(),
            getCommandRef().getInstructionByte(),
            0x00,
            0x00,
            HexUtil::toByteArray(SECP256R1_OID))));
}

void
CommandGenerateAsymmetricKeyPair::finalizeRequest()
{
    /* nothing to do */
}

bool
CommandGenerateAsymmetricKeyPair::isCryptoServiceRequiredToFinalizeRequest()
    const
{
    return false;
}

bool
CommandGenerateAsymmetricKeyPair::synchronizeCryptoServiceBeforeCardProcessing()
{
    /* Need to synchronize the card image */
    return false;
}

void
CommandGenerateAsymmetricKeyPair::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandGenerateAsymmetricKeyPair::getStatusTable() const
{
    return STATUS_TABLE;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
