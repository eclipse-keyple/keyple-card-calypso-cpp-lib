/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CmdCardOpenSession.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "IllegalArgumentException.h"
#include "IllegalStateException.h"
#include "System.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"
#include "CardTerminatedException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

/* SECURE SESSION -------------------------------------------------------------------------------- */

CmdCardOpenSession::SecureSession::SecureSession(const std::vector<uint8_t>& challengeTransactionCounter,
                             const std::vector<uint8_t>& challengeRandomNumber,
                             const bool previousSessionRatified,
                             const bool manageSecureSessionAuthorized,
                             const std::shared_ptr<uint8_t> kif,
                             const std::shared_ptr<uint8_t> kvc,
                             const std::vector<uint8_t>& originalData,
                             const std::vector<uint8_t>& secureSessionData)
: mChallengeTransactionCounter(challengeTransactionCounter),
  mChallengeRandomNumber(challengeRandomNumber),
  mPreviousSessionRatified(previousSessionRatified),
  mManageSecureSessionAuthorized(manageSecureSessionAuthorized),
  mKif(kif),
  mKvc(kvc),
  mOriginalData(originalData),
  mSecureSessionData(secureSessionData) {}

const std::vector<uint8_t>&
    CmdCardOpenSession::SecureSession::getChallengeTransactionCounter() const
{
    return mChallengeTransactionCounter;
}

const std::vector<uint8_t>& CmdCardOpenSession::SecureSession::getChallengeRandomNumber() const
{
    return mChallengeRandomNumber;
}

bool CmdCardOpenSession::SecureSession::isPreviousSessionRatified() const
{
    return mPreviousSessionRatified;
}

bool CmdCardOpenSession::SecureSession::isManageSecureSessionAuthorized() const
{
    return mManageSecureSessionAuthorized;
}

const std::shared_ptr<uint8_t> CmdCardOpenSession::SecureSession::getKIF() const
{
    return mKif;
}

const std::shared_ptr<uint8_t> CmdCardOpenSession::SecureSession::getKVC() const
{
    return mKvc;
}

const std::vector<uint8_t>& CmdCardOpenSession::SecureSession::getOriginalData() const
{
    return mOriginalData;
}

const std::vector<uint8_t>& CmdCardOpenSession::SecureSession::getSecureSessionData() const
{
    return mSecureSessionData;
}

/* CMD CARD OPEN SESSIO ------------------------------------------------------------------------- */

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardOpenSession::STATUS_TABLE = initStatusTable();

CmdCardOpenSession::CmdCardOpenSession(const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                                       const uint8_t keyIndex,
                                       const std::vector<uint8_t>& samChallenge,
                                       const uint8_t sfi,
                                       const uint8_t recordNumber,
                                       const uint8_t recordSize,
                                       const bool isExtendedModeAllowed)
: AbstractCardCommand(CalypsoCardCommand::OPEN_SESSION, -1, calypsoCard),
  mRecordSize(recordSize),
  mIsExtendedModeAllowed(isExtendedModeAllowed)
{
    switch (getCalypsoCard()->getProductType()) {

        case CalypsoCard::ProductType::PRIME_REVISION_1:
            createRev10(keyIndex, samChallenge, sfi, recordNumber);
            break;

        case CalypsoCard::ProductType::PRIME_REVISION_2:
            createRev24(keyIndex, samChallenge, sfi, recordNumber);
            break;

        case CalypsoCard::ProductType::PRIME_REVISION_3:
        case CalypsoCard::ProductType::LIGHT:
        case CalypsoCard::ProductType::BASIC:
            createRev3(keyIndex, samChallenge, sfi, recordNumber);
            break;

        default:
            std::stringstream ss;
            ss << "Product type " << getCalypsoCard()->getProductType() << " isn't supported";
            throw IllegalArgumentException(ss.str());
    }
}

void CmdCardOpenSession::createRev3(const uint8_t keyIndex,
                                    const std::vector<uint8_t>& samChallenge,
                                    const uint8_t sfi,
                                    const uint8_t recordNumber)
{
    mSfi = sfi;
    mRecordNumber = recordNumber;

    const uint8_t p1 = static_cast<uint8_t>(recordNumber * 8 + keyIndex);
    uint8_t p2;
    std::vector<uint8_t> dataIn;

    if (mIsExtendedModeAllowed) {

        p2 = static_cast<uint8_t>(sfi * 8 + 2);
        dataIn = std::vector<uint8_t>(samChallenge.size() + 1);
        System::arraycopy(samChallenge, 0, dataIn, 1, samChallenge.size());

    } else {

        p2 = static_cast<uint8_t>(sfi * 8 + 1);
        dataIn = samChallenge;
    }

    /*
     * Case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(CalypsoCardClass::ISO.getValue(),
                            CalypsoCardCommand::OPEN_SESSION.getInstructionByte(),
                            p1,
                            p2,
                            dataIn,
                            0)));

    std::stringstream extraInfo;
    extraInfo << "KEYINDEX:" << keyIndex << ", "
              << "SFI:" << sfi << "h, "
              << "REC:" << recordNumber;

    addSubName(extraInfo.str());
}

void CmdCardOpenSession::createRev24(const uint8_t keyIndex,
                                     const std::vector<uint8_t>& samChallenge,
                                     const uint8_t sfi,
                                     const uint8_t recordNumber)
{
    if (keyIndex == 0x00) {
        throw IllegalArgumentException("Key index can't be zero for rev 2.4!");
    }

    mSfi = sfi;
    mRecordNumber = recordNumber;

    const uint8_t p1 = static_cast<uint8_t>(0x80 + recordNumber * 8 + keyIndex);

    buildLegacyApduRequest(keyIndex, samChallenge, sfi, recordNumber, p1);
}

void CmdCardOpenSession::createRev10(const uint8_t keyIndex,
                                     const std::vector<uint8_t>& samChallenge,
                                     const uint8_t sfi,
                                     const uint8_t recordNumber)
{
    if (keyIndex == 0x00) {
        throw IllegalArgumentException("Key index can't be zero for rev 1.0!");
    }

    mSfi = sfi;
    mRecordNumber = recordNumber;

    const uint8_t p1 = static_cast<uint8_t>(recordNumber * 8 + keyIndex);

    buildLegacyApduRequest(keyIndex, samChallenge, sfi, recordNumber, p1);
}

void CmdCardOpenSession::buildLegacyApduRequest(const uint8_t keyIndex,
                                                const std::vector<uint8_t>& samChallenge,
                                                const uint8_t sfi,
                                                const uint8_t recordNumber,
                                                const uint8_t p1)
{
    const uint8_t p2 = static_cast<uint8_t>(sfi * 8);

    /*
     * Case 4: this command contains incoming and outgoing data. We define le = 0, the actual
     * length will be processed by the lower layers.
     */
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(CalypsoCardClass::LEGACY.getValue(),
                            CalypsoCardCommand::OPEN_SESSION.getInstructionByte(),
                            p1,
                            p2,
                            samChallenge,
                            0)));

    std::stringstream extraInfo;
    extraInfo << "KEYINDEX:" << keyIndex << ", "
              << "SFI:" << sfi << "h, "
              << "REC:" << recordNumber;

    addSubName(extraInfo.str());
}

bool CmdCardOpenSession::isSessionBufferUsed() const
{
    return false;
}

uint8_t CmdCardOpenSession::getSfi() const
{
    return mSfi;
}

uint8_t CmdCardOpenSession::getRecordNumber() const
{
    return mRecordNumber;
}

void CmdCardOpenSession::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::parseApduResponse(apduResponse);

    const std::vector<uint8_t> dataOut = getApduResponse()->getDataOut();

    switch (getCalypsoCard()->getProductType()) {

        case CalypsoCard::ProductType::PRIME_REVISION_1:
            parseRev10(dataOut);
            break;

        case CalypsoCard::ProductType::PRIME_REVISION_2:
            parseRev24(dataOut);
            break;

        default:
            parseRev3(dataOut);
    }

    /* CL-CSS-INFORAT.1 */
    getCalypsoCard()->setDfRatified(mSecureSession->isPreviousSessionRatified());

    /* CL-CSS-INFOTCNT.1 */
    getCalypsoCard()->setTransactionCounter(
        ByteArrayUtil::extractInt(mSecureSession->getChallengeTransactionCounter(), 0, 3, false));

    if (mSecureSession->getOriginalData().size() > 0) {

        getCalypsoCard()->setContent(mSfi, mRecordNumber, mSecureSession->getOriginalData());
    }
}

void CmdCardOpenSession::parseRev3(const std::vector<uint8_t>& apduResponseData)
{
    bool previousSessionRatified;
    bool manageSecureSessionAuthorized;
    int offset;

    /* CL-CSS-OSSRFU.1 */
    if (mIsExtendedModeAllowed) {
        offset = 4;
        previousSessionRatified = (apduResponseData[8] & 0x01) == 0x00;
        manageSecureSessionAuthorized = (apduResponseData[8] & 0x02) == 0x02;
    } else {
        offset = 0;
        previousSessionRatified = apduResponseData[4] == 0x00;
        manageSecureSessionAuthorized = false;
    }

    const auto kif = std::make_shared<uint8_t>(apduResponseData[5 + offset]);
    const auto kvc = std::make_shared<uint8_t>(apduResponseData[6 + offset]);
    const int dataLength = apduResponseData[7 + offset];

    if (dataLength != apduResponseData.size() - 8 - offset) {
      throw IllegalStateException("Inconsistent response length for Open Secure Session.");
    }

    const std::vector<uint8_t> data =
        Arrays::copyOfRange(apduResponseData, 8 + offset, 8 + offset + dataLength);

    mSecureSession = std::shared_ptr<SecureSession>(
                         new SecureSession(
                            Arrays::copyOfRange(apduResponseData, 0, 3),
                            Arrays::copyOfRange(apduResponseData, 3, 4 + offset),
                            previousSessionRatified,
                            manageSecureSessionAuthorized,
                            kif,
                            kvc,
                            data,
                            apduResponseData));
}

void CmdCardOpenSession::parseRev24(const std::vector<uint8_t>& apduResponseData)
{
    bool previousSessionRatified;
    std::vector<uint8_t> data;

    switch (apduResponseData.size()) {
    case 5:
        previousSessionRatified = true;
        data = std::vector<uint8_t>(0);
        break;
    case 34:
        if (mRecordSize != 29) {
          throw IllegalStateException("Inconsistent response length for Open Secure Session.");
        }
        previousSessionRatified = true;
        data = Arrays::copyOfRange(apduResponseData, 5, 34);
        break;
    case 7:
        previousSessionRatified = false;
        data = std::vector<uint8_t>(0);
        break;
    case 36:
        if (mRecordSize != 29) {
          throw IllegalStateException("Inconsistent response length for Open Secure Session.");
        }
        previousSessionRatified = false;
        data = Arrays::copyOfRange(apduResponseData, 7, 36);
        break;
    default:
        throw IllegalStateException("Bad response length to Open Secure Session: " +
                                    std::to_string(apduResponseData.size()));
    }

    const auto kvc = std::make_shared<uint8_t>(apduResponseData[0]);

    mSecureSession = std::shared_ptr<SecureSession>(
                         new SecureSession(
                            Arrays::copyOfRange(apduResponseData, 1, 4),
                            Arrays::copyOfRange(apduResponseData, 4, 5),
                            previousSessionRatified,
                            false,
                            nullptr,
                            kvc,
                            data,
                            apduResponseData));
}

void CmdCardOpenSession::parseRev10(const std::vector<uint8_t>& apduResponseData) {

    bool previousSessionRatified;
    std::vector<uint8_t> data;

    switch (apduResponseData.size()) {
    case 4:
        previousSessionRatified = true;
        data = std::vector<uint8_t>(0);
        break;
    case 33:
        if (mRecordSize != 29) {
          throw IllegalStateException("Inconsistent response length for Open Secure Session.");
        }
        previousSessionRatified = true;
        data = Arrays::copyOfRange(apduResponseData, 4, 33);
        break;
    case 6:
        previousSessionRatified = false;
        data = std::vector<uint8_t>(0);
        break;
    case 35:
        if (mRecordSize != 29) {
          throw IllegalStateException("Inconsistent response length for Open Secure Session.");
        }
        previousSessionRatified = false;
        data = Arrays::copyOfRange(apduResponseData, 6, 35);
        break;
    default:
        throw IllegalStateException("Bad response length to Open Secure Session: " +
                                    std::to_string(apduResponseData.size()));
    }

    /* KVC doesn't exist and is set to null for this type of card */
    mSecureSession = std::shared_ptr<SecureSession>(
                         new SecureSession(
                             Arrays::copyOfRange(apduResponseData, 0, 3),
                             Arrays::copyOfRange(apduResponseData, 3, 4),
                             previousSessionRatified,
                             false,
                             nullptr,
                             nullptr,
                             data,
                             apduResponseData));
}

const std::vector<uint8_t>& CmdCardOpenSession::getCardChallenge() const
{
    return mSecureSession->getChallengeRandomNumber();
}

bool CmdCardOpenSession::isManageSecureSessionAuthorized() const
{
    return mSecureSession->isManageSecureSessionAuthorized();
}

const std::shared_ptr<uint8_t> CmdCardOpenSession::getSelectedKif() const
{
    return mSecureSession->getKIF();
}

const std::shared_ptr<uint8_t> CmdCardOpenSession::getSelectedKvc() const
{
    return mSecureSession->getKVC();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardOpenSession::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6900,
              std::make_shared<StatusProperties>("Transaction Counter is 0",
                                                 typeid(CardTerminatedException))});
    m.insert({0x6981,
              std::make_shared<StatusProperties>("Command forbidden (read requested and current " \
                                                 "EF is a Binary file).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (PIN code " \
                                                 "not presented, AES key forbidding the " \
                                                 "compatibility mode, encryption required).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode, Session " \
                                                 "already opened).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Command not allowed (read requested and no " \
                                                 "current EF).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A81,
              std::make_shared<StatusProperties>("Wrong key index.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found (record index is above NumRec).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 value not supported (key index " \
                                                 "incorrect, wrong P2).",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x61FF,
              std::make_shared<StatusProperties>("Correct execution (ISO7816 T=0).",
                                                 typeid(nullptr))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardOpenSession::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
