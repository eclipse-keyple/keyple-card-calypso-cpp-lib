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

#include "keyple/card/calypso/CommandOpenSecureSession.hpp"

#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardTerminatedException.hpp"
#include "keyple/card/calypso/CardUnexpectedResponseLengthException.hpp"
#include "keyple/core/util/ApduUtil.hpp"
#include "keyple/core/util/ByteArrayUtil.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/card/transaction/UnauthorizedKeyException.hpp"
#include "keypop/calypso/crypto/asymmetric/AsymmetricCryptoException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::ApduUtil;
using keyple::core::util::ByteArrayUtil;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::card::transaction::UnauthorizedKeyException;
using keypop::calypso::crypto::asymmetric::AsymmetricCryptoException;

const std::string CommandOpenSecureSession::PATTERN_1_BYTE_HEX = "%02Xh";

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    CommandOpenSecureSession::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x6700,
              std::make_shared<StatusProperties>(
                  "Lc value not supported",
                  typeid(CardIllegalParameterException))},
             {0x6900,
              std::make_shared<StatusProperties>(
                  "Transaction Counter is 0", typeid(CardTerminatedException))},
             {0x6981,
              std::make_shared<StatusProperties>(
                  "Command forbidden (read requested and current EF is a Binary"
                  " file)",
                  typeid(CardDataAccessException))},
             {0x6982,
              std::make_shared<StatusProperties>(
                  "Security conditions not fulfilled (PIN code not presented, "
                  "AES key forbidding the compatibility mode, encryption "
                  "required)",
                  typeid(CardSecurityContextException))},
             {0x6985,
              std::make_shared<StatusProperties>(
                  "Access forbidden (Never access mode, Session already "
                  "opened)",
                  typeid(CardAccessForbiddenException))},
             {0x6986,
              std::make_shared<StatusProperties>(
                  "Command not allowed (read requested and no current EF)",
                  typeid(CardDataAccessException))},
             {0x6A81,
              std::make_shared<StatusProperties>(
                  "Wrong key index", typeid(CardIllegalParameterException))},
             {0x6A82,
              std::make_shared<StatusProperties>(
                  "File not found", typeid(CardDataAccessException))},
             {0x6A83,
              std::make_shared<StatusProperties>(
                  "Record not found (record index is above NumRec)",
                  typeid(CardDataAccessException))},
             {0x6B00,
              std::make_shared<StatusProperties>(
                  "P1 or P2 value not supported (key index incorrect, wrong P2,"
                  " extended mode not supported)",
                  typeid(CardIllegalParameterException))},
             {0x61FF,
              std::make_shared<StatusProperties>(
                  "Correct execution (ISO7816 T=0)",
                  typeid(CardIllegalParameterException))},
             {0x6200,
              std::make_shared<StatusProperties>(
                  "Successful execution, with warning (Pre-Open variant, secure"
                  " session not opened)",
                  typeid(CardIllegalParameterException))}});
        return m;
    }();

CommandOpenSecureSession::CommandOpenSecureSession(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    WriteAccessLevel writeAccessLevel)
: Command(
      CardCommandRef::OPEN_SECURE_SESSION,
      nullptr,
      transactionContext,
      commandContext)
, mWriteAccessLevel(writeAccessLevel)
, mIsExtendedModeAllowed(true)
, mIsPreOpenModeOnSelection(true)
{
    /* with no SAM challenge */
    createRev3(static_cast<int>(mWriteAccessLevel) + 1, {});
    addSubName("PRE-OPEN");
}

CommandOpenSecureSession::CommandOpenSecureSession(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>
        symmetricCryptoSecuritySetting,
    WriteAccessLevel writeAccessLevel,
    bool isExtendedModeAllowed)
: Command(
      CardCommandRef::OPEN_SECURE_SESSION,
      nullptr,
      transactionContext,
      commandContext)
, mWriteAccessLevel(writeAccessLevel)
, mIsExtendedModeAllowed(isExtendedModeAllowed)
, mSymmetricCryptoSecuritySetting(symmetricCryptoSecuritySetting)
{
    /* C++ */
    std::shared_ptr<CalypsoCardAdapter> card = transactionContext->getCard();
    if (card == nullptr) {
        throw IllegalStateException("Card is required in transaction context");
    }

    mPreOpenDataOut = card->getPreOpenDataOut();
    mIsPreOpenMode = !mPreOpenDataOut.empty();
}

CommandOpenSecureSession::CommandOpenSecureSession(
    const std::shared_ptr<DtoAdapters::TransactionContextDto>&
        transactionContext,
    const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
    const std::vector<std::uint8_t>& terminalChallenge)
: Command(
      CardCommandRef::OPEN_SECURE_SESSION,
      nullptr,
      transactionContext,
      commandContext)
, mWriteAccessLevel(WriteAccessLevel::UNKOWN)
, mIsExtendedModeAllowed(true)
, mIsPreOpenModeOnSelection(false)
{
    createRev3Pki(terminalChallenge);
    addSubName("PKI");
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
CommandOpenSecureSession::getStatusTable() const
{
    return STATUS_TABLE;
}

void
CommandOpenSecureSession::createRev3(
    std::uint8_t keyIndex, const std::vector<std::uint8_t>& samChallenge)
{
    const std::uint8_t p1
        = static_cast<std::uint8_t>((mRecordNumber * 8) + keyIndex);

    std::uint8_t p2;
    std::vector<std::uint8_t> dataIn;

    if (mIsExtendedModeAllowed) {
        p2 = static_cast<std::uint8_t>((mSfi * 8) + 2);
        dataIn.resize(samChallenge.size() + 1);
        System::arraycopy(samChallenge, 0, dataIn, 1, samChallenge.size());
    } else {
        p2 = static_cast<std::uint8_t>((mSfi * 8) + 1);
        dataIn = samChallenge;
    }

    /*
     * Case 4: this command contains incoming and outgoing data. We define le =
     * 0, the actual length will be processed by the lower layers.
     */
    setApduRequest(
        std::unique_ptr<DtoAdapters::ApduRequestAdapter>(
            new DtoAdapters::ApduRequestAdapter(
                ApduUtil::build(
                    CalypsoCardClass::ISO.getValue(),
                    CardCommandRef::OPEN_SECURE_SESSION.getInstructionByte(),
                    p1,
                    p2,
                    dataIn,
                    0))));

    addSubName(
        "Key index: " + std::to_string(keyIndex) + ", "
        + "SFI: " + HexUtil::toHex(static_cast<std::uint8_t>(mSfi)) + "h, "
        + "Rec: " + std::to_string(mRecordNumber));
}

void
CommandOpenSecureSession::createRev24(
    std::uint8_t keyIndex, const std::vector<std::uint8_t>& samChallenge)
{
    const std::uint8_t p1
        = static_cast<std::uint8_t>(0x80 + (mRecordNumber * 8) + keyIndex);
    buildLegacyApduRequest(keyIndex, samChallenge, mSfi, mRecordNumber, p1);
}

void
CommandOpenSecureSession::createRev10(
    std::uint8_t keyIndex, const std::vector<std::uint8_t>& samChallenge)
{
    const std::uint8_t p1
        = static_cast<std::uint8_t>((mRecordNumber * 8) + keyIndex);
    buildLegacyApduRequest(keyIndex, samChallenge, mSfi, mRecordNumber, p1);
}

void
CommandOpenSecureSession::createRev3Pki(
    const std::vector<std::uint8_t>& terminalChallenge)
{
    const std::uint8_t p1 = 0x00;
    const std::uint8_t p2 = 0x03;

    std::vector<std::uint8_t> dataIn(terminalChallenge.size() + 1);
    System::arraycopy(
        terminalChallenge, 0, dataIn, 1, terminalChallenge.size());

    /*
     * Case 4: this command contains incoming and outgoing data. We define le =
     * 0, the actual length will be processed by the lower layers.
     */
    setApduRequest(
        std::unique_ptr<DtoAdapters::ApduRequestAdapter>(
            new DtoAdapters::ApduRequestAdapter(
                ApduUtil::build(
                    CalypsoCardClass::ISO.getValue(),
                    CardCommandRef::OPEN_SECURE_SESSION.getInstructionByte(),
                    p1,
                    p2,
                    dataIn,
                    0))));
}

void
CommandOpenSecureSession::buildLegacyApduRequest(
    std::uint8_t keyIndex,
    const std::vector<std::uint8_t>& samChallenge,
    int sfi,
    int recordNumber,
    std::uint8_t p1)
{
    const std::uint8_t p2 = static_cast<std::uint8_t>(sfi * 8);

    /*
     * case 4: this command contains incoming and outgoing data. We define le =
     * 0, the actual length will be processed by the lower layers.
     */
    setApduRequest(
        std::unique_ptr<DtoAdapters::ApduRequestAdapter>(
            new DtoAdapters::ApduRequestAdapter(
                ApduUtil::build(
                    CalypsoCardClass::LEGACY.getValue(),
                    CardCommandRef::OPEN_SECURE_SESSION.getInstructionByte(),
                    p1,
                    p2,
                    samChallenge,
                    0))));

    addSubName(
        "Key index: " + std::to_string(keyIndex) + ", "
        + "SFI: " + HexUtil::toHex(static_cast<std::uint8_t>(sfi)) + "h, "
        + "Rec: " + std::to_string(recordNumber));
}

void
CommandOpenSecureSession::configureReadMode(
    int sfi, int recordNumber, int expectedRecordDataLength)
{
    if (getTransactionContext()->isPkiMode()) {
        std::shared_ptr<DtoAdapters::ApduRequestAdapter> request
            = getApduRequest();
        std::vector<std::uint8_t> apdu = request->getApdu();

        /* Overwrite p1 & p2 */
        apdu[2] = static_cast<std::uint8_t>(recordNumber * 8);
        apdu[3] = static_cast<std::uint8_t>((sfi * 8) + 3);

        request->setApdu(apdu);

        addSubName(
            std::string("SFI: ")
            + HexUtil::toHex(static_cast<std::uint8_t>(sfi))
            + "h, Rec: " + std::to_string(recordNumber));
    }

    mSfi = sfi;
    mRecordNumber = recordNumber;
    mExpectedRecordDataLength = expectedRecordDataLength;
    mIsReadModeConfigured = true;
}

bool
CommandOpenSecureSession::isReadModeConfigured() const
{
    return mIsReadModeConfigured;
}

void
CommandOpenSecureSession::finalizeRequest()
{
    std::vector<std::uint8_t> samChallenge;

    try {
        samChallenge = getTransactionContext()
                           ->getSymmetricCryptoCardTransactionManagerSpi()
                           ->initTerminalSecureSessionContext();

    } catch (const SymmetricCryptoException& e) {
        throw CryptoException(e.what(), e);

    } catch (const SymmetricCryptoIOException& e) {
        throw CryptoIOException(e.what(), e);
    }

    const std::uint8_t keyIndex
        = static_cast<std::uint8_t>(static_cast<int>(mWriteAccessLevel) + 1);

    switch (getTransactionContext()->getCard()->getProductType()) {
    case CalypsoCard::ProductType::PRIME_REVISION_1:
        createRev10(keyIndex, samChallenge);
        break;
    case CalypsoCard::ProductType::PRIME_REVISION_2:
        createRev24(keyIndex, samChallenge);
        break;
    case CalypsoCard::ProductType::PRIME_REVISION_3:
    case CalypsoCard::ProductType::LIGHT:
    case CalypsoCard::ProductType::BASIC:
        createRev3(keyIndex, samChallenge);
        break;
    default:
        std::stringstream ss;
        ss << "Unsupported ProductType: "
           << getTransactionContext()->getCard()->getProductType();
        throw IllegalArgumentException(ss.str());
    }
}

bool
CommandOpenSecureSession::isCryptoServiceRequiredToFinalizeRequest() const
{
    return true;
}

bool
CommandOpenSecureSession::synchronizeCryptoServiceBeforeCardProcessing()
{
    if (!mIsPreOpenMode) {
        return false;
    }

    /*
     * In pre-open mode, we can synchronize the crypto service without having to
     * execute the card open session command first.
     */
    if (!isCryptoServiceSynchronized()) {
        try {
            parseRev3(mPreOpenDataOut);

        } catch (const CardUnexpectedResponseLengthException& e) {
            throw IllegalStateException(
                "Unexpected response length in pre-open mode", e);
        }

        synchronizeCryptoService(mPreOpenDataOut);
    }

    return true;
}

void
CommandOpenSecureSession::synchronizeCryptoService(
    const std::vector<std::uint8_t>& dataOut)
{
    if (getTransactionContext()->isPkiMode()) {
        try {
            std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
                cryptoManager
                = getTransactionContext()
                      ->getAsymmetricCryptoCardTransactionManagerSpi();
            cryptoManager->initTerminalPkiSession(
                getTransactionContext()->getCard()->getCardPublicKeySpi());
            cryptoManager->updateTerminalPkiSession(
                getApduRequest()->getApdu());
            cryptoManager->updateTerminalPkiSession(
                getApduResponse()->getApdu());

        } catch (const AsymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);
        }

    } else {
        std::shared_ptr<std::uint8_t> computedKvc = computeKvc();
        std::shared_ptr<std::uint8_t> computedKif
            = computeKif(computedKvc.get());
        if (!mSymmetricCryptoSecuritySetting->isSessionKeyAuthorized(
                computedKif, computedKvc)) {
            throw UnauthorizedKeyException(
                std::string("Unauthorized key. KIF: ")
                + HexUtil::toHex(*computedKif)
                + ", KVC: " + std::to_string(*computedKvc));
        }

        try {
            getTransactionContext()
                ->getSymmetricCryptoCardTransactionManagerSpi()
                ->initTerminalSessionMac(dataOut, *computedKif, *computedKvc);

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw CryptoIOException(e.what(), e);
        }
    }

    confirmCryptoServiceSuccessfullySynchronized();
}

void
CommandOpenSecureSession::parseResponse(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    Command::setApduResponseAndCheckStatus(apduResponse);
    std::shared_ptr<CalypsoCardAdapter> card
        = getTransactionContext()->getCard();
    if (!mIsPreOpenModeOnSelection) {
        card->backupFiles();
        getTransactionContext()->setSecureSessionOpen(true);
    }

    /* Parse data */
    const std::vector<std::uint8_t> dataOut = getApduResponse()->getDataOut();
    if (getTransactionContext()->isPkiMode()) {
        parsePki(dataOut);
    } else {
        switch (card->getProductType()) {
        case CalypsoCard::ProductType::PRIME_REVISION_1:
            parseRev10(dataOut);
            break;
        case CalypsoCard::ProductType::PRIME_REVISION_2:
            parseRev24(dataOut);
            break;
        default:
            parseRev3(dataOut);
        }
    }

    /*
     * Update Calypso card image
     * CL-CSS-INFORAT.1
     */
    card->setDfRatified(mIsPreviousSessionRatified);

    /* CL-CSS-INFOTCNT.1 */
    card->setTransactionCounter(
        ByteArrayUtil::extractInt(mChallengeTransactionCounter, 0, 3, false));
    if (mRecordData.size() > 0) {
        card->setContent(
            static_cast<std::uint8_t>(mSfi), mRecordNumber, mRecordData);
    }
    /*
     * If it is a pre-open variant, then we save the pre-open data into the
     * Calypso card image.
     */
    if (mIsPreOpenModeOnSelection && apduResponse->getStatusWord() == 0x6200) {
        card->setPreOpenWriteAccessLevel(mWriteAccessLevel);
        card->setPreOpenDataOut(dataOut);
    }

    /* Synchronize crypto service */
    if (!isCryptoServiceSynchronized()) {
        synchronizeCryptoService(dataOut);
    } else {
        /*
         * If the crypto service is already synchronized, this means you're in
         * pre-open mode.
         */
        if (!Arrays::equals(dataOut, mPreOpenDataOut)) {
            throw CardSecurityContextException(
                "Session has been pre-opened but 'dataOut' fields do not match",
                CardCommandRef::OPEN_SECURE_SESSION);
        }
    }
}

std::shared_ptr<std::uint8_t>
CommandOpenSecureSession::computeKvc()
{
    if (mKvc != nullptr) {
        return mKvc;
    }

    return mSymmetricCryptoSecuritySetting->getDefaultKvc(mWriteAccessLevel);
}

std::shared_ptr<std::uint8_t>
CommandOpenSecureSession::computeKif(const std::uint8_t* kvc)
{
    /* CL-KEY-KIF.1 */
    if ((mKif != nullptr && *mKif != 0xFF) || (kvc == nullptr)) {
        return mKif;
    }

    /* CL-KEY-KIFUNK.1 */
    std::shared_ptr<std::uint8_t> result
        = mSymmetricCryptoSecuritySetting->getKif(mWriteAccessLevel, *kvc);
    if (result == nullptr) {
        result
            = mSymmetricCryptoSecuritySetting->getDefaultKif(mWriteAccessLevel);
    }

    return result;
}

void
CommandOpenSecureSession::parseRev3(
    const std::vector<std::uint8_t>& apduResponseData)
{
    int offset;

    /* CL-CSS-OSSRFU.1 */
    if (mIsExtendedModeAllowed) {
        offset = 4;
        mIsPreviousSessionRatified = (apduResponseData[8] & 0x01) == 0x00;
        bool manageSecureSessionAuthorized
            = (apduResponseData[8] & 0x02) == 0x02;
        if (!manageSecureSessionAuthorized) {
            getTransactionContext()->getCard()->disableExtendedMode();
        }

    } else {
        offset = 0;
        mIsPreviousSessionRatified = (apduResponseData[4] == 0x00);
        getTransactionContext()->getCard()->disableExtendedMode();
    }

    mChallengeTransactionCounter = Arrays::copyOfRange(apduResponseData, 0, 3);
    mKif = std::make_shared<std::uint8_t>(apduResponseData[5 + offset]);
    mKvc = std::make_shared<std::uint8_t>(apduResponseData[6 + offset]);
    int dataLength = apduResponseData[7 + offset];
    if (dataLength != static_cast<int>(apduResponseData.size() - 8 - offset)) {
        throw CardUnexpectedResponseLengthException(
            std::string("APDU response is not the correct length. Command: ")
                + getCommandRef().getName()
                + ", Expected: " + std::to_string(mExpectedRecordDataLength)
                + ", Actual: " + std::to_string(dataLength),
            getCommandRef());
    }
    mRecordData = Arrays::copyOfRange(
        apduResponseData, 8 + offset, 8 + offset + dataLength);
}

void
CommandOpenSecureSession::parseRev24(
    const std::vector<std::uint8_t>& apduResponseData)
{
    switch (apduResponseData.size()) {
    case 5:
        mIsPreviousSessionRatified = true;
        mRecordData = {};
        break;
    case 34:
        checkReceivedDataLength(29);
        mIsPreviousSessionRatified = true;
        mRecordData = Arrays::copyOfRange(apduResponseData, 5, 34);
        break;
    case 7:
        mIsPreviousSessionRatified = false;
        mRecordData = {};
        break;
    case 36:
        checkReceivedDataLength(29);
        mIsPreviousSessionRatified = false;
        mRecordData = Arrays::copyOfRange(apduResponseData, 7, 36);
        break;
    default:
        throw CardUnexpectedResponseLengthException(
            std::string("APDU response is not the correct length. Command: ")
                + getCommandRef().getName() + ", Expected: 5/7/34/36, Actual: "
                + std::to_string(apduResponseData.size()),
            getCommandRef());
    }

    mChallengeTransactionCounter = Arrays::copyOfRange(apduResponseData, 1, 4);
    mKif = nullptr;
    mKvc = std::unique_ptr<std::uint8_t>(new std::uint8_t(apduResponseData[0]));
}

void
CommandOpenSecureSession::parseRev10(
    const std::vector<std::uint8_t>& apduResponseData)
{
    switch (apduResponseData.size()) {
    case 4:
        mIsPreviousSessionRatified = true;
        mRecordData = {};
        break;
    case 33:
        checkReceivedDataLength(29);
        mIsPreviousSessionRatified = true;
        mRecordData = Arrays::copyOfRange(apduResponseData, 4, 33);
        break;
    case 6:
        mIsPreviousSessionRatified = false;
        mRecordData = {};
        break;
    case 35:
        checkReceivedDataLength(29);
        mIsPreviousSessionRatified = false;
        mRecordData = Arrays::copyOfRange(apduResponseData, 6, 35);
        break;
    default:
        throw CardUnexpectedResponseLengthException(
            "APDU response is not the correct length. Command: "
                + getCommandRef().getName() + ", Expected: 4/6/33/35, Actual: "
                + std::to_string(apduResponseData.size()),
            getCommandRef());
    }

    mChallengeTransactionCounter = Arrays::copyOfRange(apduResponseData, 0, 3);
    mKif = nullptr;
    mKvc = nullptr;
}

void
CommandOpenSecureSession::parsePki(
    const std::vector<std::uint8_t>& apduResponseData)
{
    const int li = apduResponseData[0] & 0xFF;
    int offset = 1 + li + 8 + 1;

    mChallengeTransactionCounter
        = Arrays::copyOfRange(apduResponseData, offset, offset + 3);
    offset += 8;

    mIsPreviousSessionRatified = (apduResponseData[offset] & 0x01) == 0x00;
    offset += 1 + 2;

    const int ld = apduResponseData[offset] & 0xFF;
    offset += 1;

    mRecordData = Arrays::copyOfRange(apduResponseData, offset, offset + ld);
}

void
CommandOpenSecureSession::checkReceivedDataLength(int dataLength)
{
    if (dataLength != mExpectedRecordDataLength) {
        throw CardUnexpectedResponseLengthException(
            "APDU response is not the correct length. Command: "
                + getCommandRef().getName()
                + ", Expected: " + std::to_string(mExpectedRecordDataLength)
                + ", Actual: " + std::to_string(dataLength),
            getCommandRef());
    }
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
