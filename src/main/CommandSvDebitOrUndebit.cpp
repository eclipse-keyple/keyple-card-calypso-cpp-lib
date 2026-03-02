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

#include "keyple/card/calypso/CommandSvDebitOrUndebit.hpp"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
#include "keyple/card/calypso/CardSessionBufferOverflowException.hpp"
#include "keyple/card/calypso/CardTerminatedException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/transaction/CardSignatureNotVerifiableException.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/card/transaction/InvalidCardSignatureException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::transaction::CardSignatureNotVerifiableException;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::card::transaction::InvalidCardSignatureException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

const std::string CommandSvDebitOrUndebit::MSG_CARD_SV_MAC_NOT_VERIFIABLE
    = "Unable to verify the card SV MAC associated to the SV operation";
const std::string CommandSvDebitOrUndebit::MSG_INVALID_CARD_SESSION_MAC
    = "Invalid card session MAC";
const int CommandSvDebitOrUndebit::SW_POSTPONED_DATA = 0x6200;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandSvDebitOrUndebit::STATUS_TABLE = [] {
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
             {0x6900,
              std::make_shared<StatusProperties>(
                  "Transaction counter is 0 or SV TNum is FFFEh or FFFFh",
                  typeid(CardTerminatedException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Preconditions not satisfied",
                  typeid(CardAccessForbiddenException))},
             {0x6988,
              std::make_shared<StatusProperties>(
                  "Incorrect signatureHi", typeid(CardSecurityDataException))},
             {SW_POSTPONED_DATA,
              std::make_shared<StatusProperties>(
                  "Successful execution, response data postponed until session "
                  "closing")}});
        return m;
    }();

CommandSvDebitOrUndebit::CommandSvDebitOrUndebit(
    bool isDebitCommand,
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    int amount,
    const std::vector<std::uint8_t>& date,
    const std::vector<std::uint8_t>& time,
    bool isExtendedModeAllowed,
    bool isSvNegativeBalanceAuthorized)
: Command(
      isDebitCommand ? CardCommandRef::SV_DEBIT : CardCommandRef::SV_UNDEBIT,
      std::unique_ptr<int>(new int(computeExpectedResponseLength(
          commandContext, isExtendedModeAllowed))),
      transactionContext,
      commandContext)
,
/* Keeps a copy of these fields until the builder is finalized */
mAmount(amount)
, mIsDebitCommand(isDebitCommand)
, mIsExtendedModeAllowed(isExtendedModeAllowed)
, mIsSvNegativeBalanceAuthorized(isSvNegativeBalanceAuthorized)
{
    /*
     * Handle the dataIn size with signatureHi length according to card product
     * type (3.2 rev have a 10-byte signature)
     */
    mDataIn = std::vector<std::uint8_t>(15 + (isExtendedModeAllowed ? 10 : 5));

    /* dataIn[0] will be filled in at the finalization phase. */
    const std::uint16_t amountShort = isDebitCommand
                                          ? static_cast<std::uint16_t>(-amount)
                                          : static_cast<std::uint16_t>(amount);
    ByteArrayUtil::copyBytes(amountShort, mDataIn, 1, 2);
    mDataIn[3] = date[0];
    mDataIn[4] = date[1];
    mDataIn[5] = time[0];
    mDataIn[6] = time[1];
    mDataIn[7] = transactionContext->getCard()->getSvKvc();

    /*
     * dataIn[8]..dataIn[8+7+sigLen] will be filled in at the finalization
     * phase. Add dummy apdu request to ensure it exists when checking the
     * session buffer usage APDU Case 3 (in session) or 4 (outside session).
     */
    std::unique_ptr<std::uint8_t> le(
        computeLe(commandContext, isExtendedModeAllowed));

    std::vector<std::uint8_t> apdu;
    if (le == nullptr) {
        apdu = ApduUtil::build(0, 0, 0, 0, mDataIn);

    } else {
        apdu = ApduUtil::build(0, 0, 0, 0, mDataIn, *le.get());
    }

    setApduRequest(std::make_shared<DtoAdapters::ApduRequestAdapter>(apdu));
}

void
CommandSvDebitOrUndebit::finalizeRequest()
{
    if (mIsDebitCommand && !mIsSvNegativeBalanceAuthorized
        && (getTransactionContext()->getCard()->getSvBalance() - mAmount) < 0) {
        throw IllegalStateException("Negative balances are not allowed");
    }

    auto svCommandSecurityData(
        std::make_shared<DtoAdapters::SvCommandSecurityDataApiAdapter>());
    svCommandSecurityData->setSvGetRequest(
        getTransactionContext()->getCard()->getSvGetHeader());
    svCommandSecurityData->setSvGetResponse(
        getTransactionContext()->getCard()->getSvGetData());
    svCommandSecurityData->setSvCommandPartialRequest(
        getSvDebitOrUndebitData());

    try {
        getTransactionContext()
            ->getSymmetricCryptoCardTransactionManagerSpi()
            ->computeSvCommandSecurityData(svCommandSecurityData);

    } catch (const SymmetricCryptoException& e) {
        throw CryptoException(e.what(), e);

    } catch (const SymmetricCryptoIOException& e) {
        throw CryptoIOException(e.what(), e);
    }

    finalizeCommand(svCommandSecurityData);
    encryptRequestAndUpdateTerminalSessionMacIfNeeded();
}

bool
CommandSvDebitOrUndebit::isCryptoServiceRequiredToFinalizeRequest() const
{
    return true;
}

bool
CommandSvDebitOrUndebit::synchronizeCryptoServiceBeforeCardProcessing()
{
    return false;
}

void
CommandSvDebitOrUndebit::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);

    if (apduResponse->getDataOut().size() != 0
        && apduResponse->getDataOut().size() != 3
        && apduResponse->getDataOut().size() != 6) {
        throw IllegalStateException(
            "SV Debit/Undebit response is not the correct length. Expected: "
            "0/3/6, Actual: "
            + std::to_string(apduResponse->getDataOut().size()));
    }

    std::shared_ptr<CalypsoCardAdapter> calypsoCard
        = getTransactionContext()->getCard();
    calypsoCard->setSvOperationSignature(apduResponse->getDataOut());
    updateCalypsoCardSvHistory(calypsoCard);
    updateTerminalSessionIfNeeded();

    if (!getCommandContext()->isSecureSessionOpen()) {
        try {
            if (!getTransactionContext()
                     ->getSymmetricCryptoCardTransactionManagerSpi()
                     ->isCardSvMacValid(
                         getTransactionContext()
                             ->getCard()
                             ->getSvOperationSignature())) {
                throw InvalidCardSignatureException(
                    MSG_INVALID_CARD_SESSION_MAC);
            }

        } catch (const SymmetricCryptoIOException& e) {
            throw CardSignatureNotVerifiableException(
                MSG_CARD_SV_MAC_NOT_VERIFIABLE, e);

        } catch (const SymmetricCryptoException& e) {
            throw CryptoIOException(e.what(), e);
        }
    }
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandSvDebitOrUndebit::getStatusTable() const
{
    return STATUS_TABLE;
}

int
CommandSvDebitOrUndebit::computeExpectedResponseLength(
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    bool isExtendedModeAllowed)
{
    if (commandContext->isSecureSessionOpen()) {
        return 0;
    } else {
        return isExtendedModeAllowed ? 6 : 3;
    }
}

std::unique_ptr<std::uint8_t>
CommandSvDebitOrUndebit::computeLe(
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    bool isExtendedModeAllowed)
{
    if (commandContext->isSecureSessionOpen()) {
        return nullptr;
    } else {
        return std::unique_ptr<std::uint8_t>(
            new std::uint8_t(isExtendedModeAllowed ? 6 : 3));
    }
}

void
CommandSvDebitOrUndebit::finalizeCommand(
    std::shared_ptr<DtoAdapters::SvCommandSecurityDataApiAdapter>
        svCommandSecurityData)
{
    const std::uint8_t p1 = svCommandSecurityData->getTerminalChallenge()[0];
    std::uint8_t p2 = svCommandSecurityData->getTerminalChallenge()[1];
    mDataIn[0] = svCommandSecurityData->getTerminalChallenge()[2];
    System::arraycopy(
        svCommandSecurityData->getSerialNumber(), 0, mDataIn, 8, 4);
    System::arraycopy(
        svCommandSecurityData->getTransactionNumber(), 0, mDataIn, 12, 3);
    System::arraycopy(
        svCommandSecurityData->getTerminalSvMac(),
        0,
        mDataIn,
        15,
        svCommandSecurityData->getTerminalSvMac().size());

    /* APDU Case 3 (in session) or 4 (outside session) */
    const std::unique_ptr<std::uint8_t> le(
        computeLe(getCommandContext(), mIsExtendedModeAllowed));

    std::vector<std::uint8_t> _apdu;
    if (le == nullptr)
    {
        _apdu = ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass()
                == CalypsoCardClass::LEGACY
                ? CalypsoCardClass::LEGACY_STORED_VALUE.getValue()
                : CalypsoCardClass::ISO.getValue(),
            getCommandRef().getInstructionByte(),
            p1,
            p2,
            mDataIn);
    }
    else
    {
        _apdu = ApduUtil::build(
            getTransactionContext()->getCard()->getCardClass()
                == CalypsoCardClass::LEGACY
                ? CalypsoCardClass::LEGACY_STORED_VALUE.getValue()
                : CalypsoCardClass::ISO.getValue(),
            getCommandRef().getInstructionByte(),
            p1,
            p2,
            mDataIn,
            *le);
    }

    auto apdu(std::make_shared<DtoAdapters::ApduRequestAdapter>(_apdu));
    apdu->addSuccessfulStatusWord(SW_POSTPONED_DATA);
    setApduRequest(apdu);
}

std::vector<std::uint8_t>
CommandSvDebitOrUndebit::getSvDebitOrUndebitData()
{
    std::vector<std::uint8_t> svDebitOrUndebitData(12);
    svDebitOrUndebitData[0] = getCommandRef().getInstructionByte();

    /*
     * svDebitOrUndebitData[1,2] / P1P2 not set because ignored.
     * Lc is 5 bytes longer in product type 3.2.
     */
    svDebitOrUndebitData[3] = mIsExtendedModeAllowed ? 0x19 : 0x14;

    /* Appends the fixed part of dataIn. */
    System::arraycopy(mDataIn, 0, svDebitOrUndebitData, 4, 8);

    return svDebitOrUndebitData;
}

void
CommandSvDebitOrUndebit::updateCalypsoCardSvHistory(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard)
{
    const int balance = calypsoCard->getSvBalance() - mAmount;
    calypsoCard->updateSvData(balance, calypsoCard->getSvLastTNum() + 1);

    std::vector<std::uint8_t> debitLog(19);
    System::arraycopy(getApduRequest()->getApdu(), 6, debitLog, 0, 14);
    ByteArrayUtil::copyBytes(balance, debitLog, 14, 3);
    ByteArrayUtil::copyBytes(calypsoCard->getSvLastTNum(), debitLog, 17, 2);
    calypsoCard->addCyclicContent(
        CalypsoCardConstant::SV_DEBIT_LOG_FILE_SFI, debitLog);
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
