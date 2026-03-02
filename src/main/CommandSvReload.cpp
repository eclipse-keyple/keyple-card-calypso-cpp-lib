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

#include "keyple/card/calypso/CommandSvReload.hpp"

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

const std::string CommandSvReload::MSG_CARD_SV_MAC_NOT_VERIFIABLE
    = "Unable to verify the card SV MAC associated to the SV operation";
const std::string CommandSvReload::MSG_INVALID_CARD_SESSION_MAC
    = "Invalid card session MAC";
const int CommandSvReload::SW_POSTPONED_DATA = 0x6200;

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandSvReload::STATUS_TABLE = [] {
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

CommandSvReload::CommandSvReload(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    int amount,
    const std::vector<std::uint8_t>& date,
    const std::vector<std::uint8_t>& time,
    const std::vector<std::uint8_t>& free,
    bool isExtendedModeAllowed)
: Command(
      CardCommandRef::SV_RELOAD,
      std::unique_ptr<int>(new int(computeExpectedResponseLength(
          commandContext, isExtendedModeAllowed))),
      transactionContext,
      commandContext)
/* Keeps a copy of these fields until the builder is finalized */
, mAmount(amount)
, mIsExtendedModeAllowed(isExtendedModeAllowed)
{
    /*
     * Handle the dataIn size with signatureHi length according to card revision
     * (3.2 rev have a 10-byte signature)
     */
    mDataIn = std::vector<std::uint8_t>(18 + (isExtendedModeAllowed ? 10 : 5));

    /* dataIn[0] will be filled in at the finalization phase. */
    mDataIn[1] = date[0];
    mDataIn[2] = date[1];
    mDataIn[3] = free[0];
    mDataIn[4] = transactionContext->getCard()->getSvKvc();
    mDataIn[5] = free[1];
    ByteArrayUtil::copyBytes(amount, mDataIn, 6, 3);
    mDataIn[9] = time[0];
    mDataIn[10] = time[1];

    /*
     * dataIn[11]..dataIn[11+7+sigLen] will be filled in at the finalization
     * phase. Add dummy apdu request to ensure it exists when checking the
     * session buffer usage.
     * APDU Case 3 (in session) or 4 (outside session)
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
CommandSvReload::finalizeRequest()
{
    auto svCommandSecurityData(
        std::make_shared<DtoAdapters::SvCommandSecurityDataApiAdapter>());
    svCommandSecurityData->setSvGetRequest(
        getTransactionContext()->getCard()->getSvGetHeader());
    svCommandSecurityData->setSvGetResponse(
        getTransactionContext()->getCard()->getSvGetData());
    svCommandSecurityData->setSvCommandPartialRequest(getSvReloadData());

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
CommandSvReload::isCryptoServiceRequiredToFinalizeRequest() const
{
    return true;
}

bool
CommandSvReload::synchronizeCryptoServiceBeforeCardProcessing()
{
    return false;
}

void
CommandSvReload::parseResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    decryptResponseAndUpdateTerminalSessionMacIfNeeded(apduResponse);
    Command::setApduResponseAndCheckStatus(apduResponse);

    if (apduResponse->getDataOut().size() != 0
        && apduResponse->getDataOut().size() != 3
        && apduResponse->getDataOut().size() != 6) {
        throw IllegalStateException(
            "SV Reload response is not the correct length. Expected: 0/3/6, "
            "Actual: "
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
CommandSvReload::getStatusTable() const
{
    return STATUS_TABLE;
}

int
CommandSvReload::computeExpectedResponseLength(
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
CommandSvReload::computeLe(
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
CommandSvReload::finalizeCommand(
    std::shared_ptr<DtoAdapters::SvCommandSecurityDataApiAdapter>
        svCommandSecurityData)
{
    const std::uint8_t p1 = svCommandSecurityData->getTerminalChallenge()[0];
    std::uint8_t p2 = svCommandSecurityData->getTerminalChallenge()[1];
    mDataIn[0] = svCommandSecurityData->getTerminalChallenge()[2];
    System::arraycopy(
        svCommandSecurityData->getSerialNumber(), 0, mDataIn, 11, 4);
    System::arraycopy(
        svCommandSecurityData->getTransactionNumber(), 0, mDataIn, 15, 3);
    System::arraycopy(
        svCommandSecurityData->getTerminalSvMac(),
        0,
        mDataIn,
        18,
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
CommandSvReload::getSvReloadData()
{
    std::vector<std::uint8_t> svReloadData(15);
    svReloadData[0] = getCommandRef().getInstructionByte();

    /*
     * svReloadData[1,2] / P1P2 not set because ignored
     * Lc is 5 bytes longer in revision 3.2
     */
    svReloadData[3] = mIsExtendedModeAllowed ? 0x1C : 0x17;

    /* appends the fixed part of dataIn */
    System::arraycopy(mDataIn, 0, svReloadData, 4, 11);

    return svReloadData;
}

void
CommandSvReload::updateCalypsoCardSvHistory(
    std::shared_ptr<CalypsoCardAdapter> calypsoCard)
{
    const int balance = calypsoCard->getSvBalance() + mAmount;
    calypsoCard->updateSvData(balance, calypsoCard->getSvLastTNum() + 1);

    std::vector<std::uint8_t> reloadLog(22);
    System::arraycopy(getApduRequest()->getApdu(), 6, reloadLog, 0, 5);
    ByteArrayUtil::copyBytes(balance, reloadLog, 5, 3);
    ByteArrayUtil::copyBytes(mAmount, reloadLog, 8, 3);
    System::arraycopy(getApduRequest()->getApdu(), 14, reloadLog, 11, 9);
    ByteArrayUtil::copyBytes(calypsoCard->getSvLastTNum(), reloadLog, 20, 2);
    calypsoCard->addCyclicContent(
        CalypsoCardConstant::SV_RELOAD_LOG_FILE_SFI, reloadLog);
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
