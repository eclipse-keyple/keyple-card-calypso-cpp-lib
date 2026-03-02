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

#include "keyple/card/calypso/CommandCloseSecureSession.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keypop/calypso/card/transaction/CardSignatureNotVerifiableException.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/card/transaction/InvalidCardSignatureException.hpp"
#include "keypop/calypso/crypto/asymmetric/AsymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::cpp::Arrays;
using keypop::calypso::card::transaction::CardSignatureNotVerifiableException;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::card::transaction::InvalidCardSignatureException;
using keypop::calypso::crypto::asymmetric::AsymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

const std::string CommandCloseSecureSession::MSG_CARD_SESSION_MAC_NOT_VERIFIABLE
    = "Unable to verify the card session MAC associated to the successfully "
      "closed secure session";
const std::string CommandCloseSecureSession::MSG_CARD_SV_MAC_NOT_VERIFIABLE
    = "Unable to verify the card SV MAC associated to the SV operation";
const std::string CommandCloseSecureSession::MSG_INVALID_CARD_SESSION_MAC
    = "Invalid card session MAC";
const std::string CommandCloseSecureSession::MSG_INVALID_CARD_SESSION_SIGNATURE
    = "Invalid card session signature";

const CardCommandRef CommandCloseSecureSession::mCommandRef
    = CardCommandRef::CLOSE_SECURE_SESSION;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandCloseSecureSession::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Lc signatureLo not supported (e.g. Lc=4 with a Revision 3.2 "
                  "mode for Open Secure Session)",
                  typeid(CardIllegalParameterException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "P1 or P2 signatureLo not supported",
                  typeid(CardIllegalParameterException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "No session was opened",
                  typeid(CardAccessForbiddenException))},
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Incorrect signatureLo",
                  typeid(CardSecurityDataException))}});
        return m;
    }();

CommandCloseSecureSession::CommandCloseSecureSession(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    bool isAutoRatificationAsked,
    int svPostponedDataIndex)
/* CL-CSS-RESPLE.1: the command is either case 1 (abort) or case 4 */
: Command(mCommandRef, nullptr, transactionContext, commandContext)
, mIsAutoRatificationAsked(isAutoRatificationAsked)
, mIsAbortSecureSession(false)
, mSvPostponedDataIndex(svPostponedDataIndex)
{
}

CommandCloseSecureSession::CommandCloseSecureSession(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    bool isAbort)
/* CL-CSS-RESPLE.1: the command is either case 1 (abort) or case 4 */
: Command(
      mCommandRef,
      isAbort ? std::unique_ptr<int>(new int(0)) : nullptr,
      transactionContext,
      commandContext)
, mIsAutoRatificationAsked(true)
, mSvPostponedDataIndex(-1)
{
    if (transactionContext->isPkiMode()) {
        /*
         * This a close in PKI mode.
         * In this case, set the APDU earlier since there is no call to
         * finalizeRequest
         * APDU Case 4
         */
        setApduRequest(
            std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
                getTransactionContext()->getCard()->getCardClass().getValue(),
                mCommandRef.getInstructionByte(),
                0x00,
                0x00)));
        mIsAbortSecureSession = isAbort;

    } else {
        /* This is a non PKI session abort */
        mIsAbortSecureSession = true;
    }
}

void
CommandCloseSecureSession::finalizeRequest()
{
    if (mIsAbortSecureSession) {
        /*
         * Abort secure session
         * CL-CSS-ABORTCMD.1
         * APDU Case 1
         */
        setApduRequest(
            std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
                getTransactionContext()->getCard()->getCardClass().getValue(),
                mCommandRef.getInstructionByte(),
                0x00,
                0x00,
                0x00))); /* CL-C1-5BYTE.1 */
    } else {
        /* Close secure session */
        std::vector<std::uint8_t> terminalSessionMac;
        try {
            terminalSessionMac
                = getTransactionContext()
                      ->getSymmetricCryptoCardTransactionManagerSpi()
                      ->finalizeTerminalSessionMac();

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw CryptoIOException(e.what(), e);
        }

        /* APDU Case 4 */
        setApduRequest(
            std::make_shared<DtoAdapters::ApduRequestAdapter>(ApduUtil::build(
                getTransactionContext()->getCard()->getCardClass().getValue(),
                mCommandRef.getInstructionByte(),
                mIsAutoRatificationAsked ? 0x80 : 0x00,
                0x00,
                terminalSessionMac,
                0x00)));
    }
}

bool
CommandCloseSecureSession::isCryptoServiceRequiredToFinalizeRequest() const
{
    return !mIsAbortSecureSession;
}

bool
CommandCloseSecureSession::synchronizeCryptoServiceBeforeCardProcessing()
{
    return mIsAbortSecureSession;
}

void
CommandCloseSecureSession::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    if (mIsAbortSecureSession) {
        processAbort(apduResponse);
        return;
    }

    Command::setApduResponseAndCheckStatus(apduResponse);
    getTransactionContext()->setSecureSessionOpen(false);

    const std::vector<std::uint8_t> responseData
        = getApduResponse()->getDataOut();

    if (getTransactionContext()->isPkiMode()) {
        parseResponseInAsymmetricMode(responseData);
    } else {
        parseResponseInSymmetricMode(responseData);
    }
}

void
CommandCloseSecureSession::processAbort(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    getTransactionContext()->setSecureSessionOpen(false);

    try {
        Command::setApduResponseAndCheckStatus(apduResponse);
        mLogger->info("Secure session aborted\n");
        getTransactionContext()->getCard()->restoreFiles();

    } catch (const CardCommandException& e) {
        mLogger->warn(
            "Failed to abort secure session [reason=%]\n", e.getMessage());
    }
}

void
CommandCloseSecureSession::parseResponseInSymmetricMode(
    const std::vector<std::uint8_t>& responseData)
{
    /* Retrieve the postponed data */
    const int cardSessionMacLength
        = getTransactionContext()->getCard()->isExtendedModeSupported() ? 8 : 4;
    int i = 0;

    while (i < static_cast<int>(responseData.size() - cardSessionMacLength)) {
        const auto data
            = Arrays::copyOfRange(responseData, i + 1, i + responseData[i]);
        mPostponedData.push_back(data);
        i += responseData[i];
    }

    /* Check the card session MAC (CL-CSS-MACVERIF.1) */
    const auto cardSessionMac
        = Arrays::copyOfRange(responseData, i, responseData.size());

    try {
        if (!getTransactionContext()
                 ->getSymmetricCryptoCardTransactionManagerSpi()
                 ->isCardSessionMacValid(cardSessionMac)) {
            throw InvalidCardSignatureException(MSG_INVALID_CARD_SESSION_MAC);
        }

    } catch (const SymmetricCryptoIOException& e) {
        throw CardSignatureNotVerifiableException(
            MSG_CARD_SESSION_MAC_NOT_VERIFIABLE, e);

    } catch (const SymmetricCryptoException& e) {
        throw CryptoException(e.what(), e);
    }

    if (mSvPostponedDataIndex != -1) {
        /* CL-SV-POSTPON.1 */
        try {
            if (!getTransactionContext()
                     ->getSymmetricCryptoCardTransactionManagerSpi()
                     ->isCardSvMacValid(
                         mPostponedData[mSvPostponedDataIndex])) {
                throw InvalidCardSignatureException(
                    MSG_INVALID_CARD_SESSION_MAC);
            }

        } catch (const SymmetricCryptoIOException& e) {
            throw CardSignatureNotVerifiableException(
                MSG_CARD_SV_MAC_NOT_VERIFIABLE, e);

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);
        }
    }
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandCloseSecureSession::getStatusTable() const
{
    return STATUS_TABLE;
}

void
CommandCloseSecureSession::parseResponseInAsymmetricMode(
    const std::vector<std::uint8_t>& responseData)
{
    try {
        if (!getTransactionContext()
                 ->getAsymmetricCryptoCardTransactionManagerSpi()
                 ->isCardPkiSessionValid(responseData)) {
            throw InvalidCardSignatureException(
                MSG_INVALID_CARD_SESSION_SIGNATURE);
        }

    } catch (const AsymmetricCryptoException& e) {
        throw CryptoException(e.what(), e);
    }
}

void
CommandCloseSecureSession::incrementSvPostponedDataIndex()
{
    mSvPostponedDataIndex++;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
