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

#include "keyple/card/calypso/CommandManageSession.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
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
    CommandManageSession::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Lc value not supported",
                  typeid(CardIllegalParameterException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  std::string("Preconditions not satisfied:\n")
                      + "- No secure session running in Extended mode.\n"
                      + "- Manage Secure Session not authorized during the "
                        "running\n"
                      + "session (as indicated by the Flags byte of Open "
                        "Secure "
                      + "Session)",
                  typeid(CardSecurityDataException))},
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Incorrect terminal Session MAC (the secure session is "
                  "aborted)",
                  typeid(CardSecurityDataException))},
             {0x6D00,
              std::make_shared<StatusProperties>(
                  "Extended mode not supported, or AES keys not supported",
                  typeid(CardSecurityContextException))}});
        return m;
    }();

CommandManageSession::CommandManageSession(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext)
/* CL-CSS-RESPLE.1: expected length may be overridden later */
: Command(
      CardCommandRef::MANAGE_SECURE_SESSION,
      nullptr,
      transactionContext,
      commandContext)
{
}

CommandManageSession&
CommandManageSession::setEncryptionRequested(bool isEncryptionRequested)
{
    mIsEncryptionRequested = isEncryptionRequested;

    return *this;
}

CommandManageSession&
CommandManageSession::setMutualAuthenticationRequested(
    bool isMutualAuthenticationRequested)
{
    mIsMutualAuthenticationRequested = isMutualAuthenticationRequested;

    return *this;
}

void
CommandManageSession::finalizeRequest()
{
    std::uint8_t p2;
    std::vector<std::uint8_t> terminalSessionMac;

    if (mIsMutualAuthenticationRequested) {
        /*
         * Case 4: this command contains incoming and outgoing data. We define
         * le = 0, the actual length will be processed by the lower layers.
         */
        p2 = mIsEncryptionRequested ? 0x03 : 0x01;
        try {
            terminalSessionMac
                = getTransactionContext()
                      ->getSymmetricCryptoCardTransactionManagerSpi()
                      ->generateTerminalSessionMac();

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw CryptoIOException(e.what(), e);
        }

        setExpectedResponseLength((std::unique_ptr<int>(new int(8))));

    } else {
        /* Case 1: this command contains no data. We define le = null. */
        p2 = mIsEncryptionRequested ? 0x02 : 0x00;
        terminalSessionMac.clear();
        setExpectedResponseLength(0);
    }

    /* APDU Case 1 (no authentication) or case 4 (authentication) */
    setApduRequest(
        std::unique_ptr<DtoAdapters::ApduRequestAdapter>(
            new DtoAdapters::ApduRequestAdapter(
                ApduUtil::build(
                    getTransactionContext()
                        ->getCard()
                        ->getCardClass()
                        .getValue(),
                    getCommandRef().getInstructionByte(),
                    0x00,
                    p2,
                    terminalSessionMac,
                    /* When case 1: CL-C1-5BYTE.1 */
                    0x00))));
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandManageSession::getStatusTable() const
{
    return STATUS_TABLE;
}

bool
CommandManageSession::isCryptoServiceRequiredToFinalizeRequest() const
{
    return mIsMutualAuthenticationRequested;
}

bool
CommandManageSession::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (mIsMutualAuthenticationRequested) {
        return false;
    }

    if (!isCryptoServiceSynchronized()) {
        updateCryptoServiceEncryptionStateIfNeeded();
        confirmCryptoServiceSuccessfullySynchronized();
    }

    return true;
}

void
CommandManageSession::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    try {
        Command::setApduResponseAndCheckStatus(apduResponse);

    } catch (const CardSecurityDataException& e) {
        if (apduResponse->getStatusWord() == 0x6985
            && !getTransactionContext()->getCard()->isExtendedModeSupported()) {
            throw UnsupportedOperationException(
                std::string("'Manage Secure Session' command is not ")
                + "available for this context (Card and/or SAM does not "
                + "support extended mode)");
        }

        throw;
    }

    const std::vector<std::uint8_t> cardSessionMac
        = getApduResponse()->getDataOut();

    if (mIsMutualAuthenticationRequested) {
        try {
            if (!getTransactionContext()
                     ->getSymmetricCryptoCardTransactionManagerSpi()
                     ->isCardSessionMacValid(cardSessionMac)) {
                throw InvalidCardSignatureException(
                    "Invalid card (authentication failed)");
            }
        } catch (const SymmetricCryptoException& e) {
            throw new CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw new CryptoIOException(e.what(), e);
        }
    }

    if (!isCryptoServiceSynchronized()) {
        updateCryptoServiceEncryptionStateIfNeeded();
    }
}

void
CommandManageSession::updateCryptoServiceEncryptionStateIfNeeded()
{
    try {
        if (!getCommandContext()->isEncryptionActive()
            && mIsEncryptionRequested) {
            getTransactionContext()
                ->getSymmetricCryptoCardTransactionManagerSpi()
                ->activateEncryption();

        } else if (
            getCommandContext()->isEncryptionActive()
            && !mIsEncryptionRequested) {
            getTransactionContext()
                ->getSymmetricCryptoCardTransactionManagerSpi()
                ->deactivateEncryption();
        }

    } catch (const SymmetricCryptoException& e) {
        throw CryptoException(e.what(), e);

    } catch (const SymmetricCryptoIOException& e) {
        throw CryptoIOException(e.what(), e);
    }
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
