/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CmdCardSvGet.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "ByteArrayUtil.h"
#include "IllegalStateException.h"
#include "System.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardIllegalParameterException.h"
#include "CardPinException.h"
#include "CardSecurityContextException.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "CardTerminatedException.h"
#include "SvLoadLogRecordAdapter.h"
#include "SvDebitLogRecordAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

const CalypsoCardCommand CmdCardSvGet::mCommand = CalypsoCardCommand::SV_GET;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSvGet::STATUS_TABLE = initStatusTable();

CmdCardSvGet::CmdCardSvGet(const CalypsoCardClass calypsoCardClass,
                           const std::shared_ptr<CalypsoCard> calypsoCard,
                           const SvOperation svOperation)
: AbstractCardCommand(mCommand)
{
    const uint8_t cla = calypsoCardClass == CalypsoCardClass::LEGACY ?
                            CalypsoCardClass::LEGACY_STORED_VALUE.getValue() :
                            CalypsoCardClass::ISO.getValue();

    /* CL-SV-CMDMODE.1 Requirement fullfilled only for SAM C1 */
    const uint8_t p1 = calypsoCard->isExtendedModeSupported() ? 0x01 : 0x00;
    const uint8_t p2 = svOperation == SvOperation::RELOAD ? 0x07 : 0x09;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, 0x00)));

    std::stringstream ss;
    ss << "OPERATION:" << svOperation;
    addSubName(ss.str());

    mHeader = std::vector<uint8_t>(4);
    mHeader[0] = mCommand.getInstructionByte();
    mHeader[1] = p1;
    mHeader[2] = p2;
    mHeader[3] = 0x00;
}

bool CmdCardSvGet::isSessionBufferUsed() const
{
    return false;
}

CmdCardSvGet& CmdCardSvGet::setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::setApduResponse(apduResponse);

    const std::vector<uint8_t> cardResponse = apduResponse->getDataOut();

    switch (cardResponse.size()) {
    case 0x21: /* Compatibility mode, Reload */
    case 0x1E: /* Compatibility mode, Debit or Undebit */
        mChallengeOut = std::vector<uint8_t>(2);
        mPreviousSignatureLo = std::vector<uint8_t>(3);
        mCurrentKVC = cardResponse[0];
        mTransactionNumber = ByteArrayUtil::twoBytesToInt(cardResponse, 1);
        System::arraycopy(cardResponse, 3, mPreviousSignatureLo, 0, 3);
        mChallengeOut[0] = cardResponse[6];
        mChallengeOut[1] = cardResponse[7];
        mBalance = ByteArrayUtil::threeBytesSignedToInt(cardResponse, 8);
        if (cardResponse.size() == 0x21) {
            /* Reload */
            mLoadLog = std::make_shared<SvLoadLogRecordAdapter>(cardResponse, 11);
            mDebitLog = nullptr;
        } else {
            /* Debit */
            mLoadLog = nullptr;
            mDebitLog = std::make_shared<SvDebitLogRecordAdapter>(cardResponse, 11);
        }
        break;
    case 0x3D: /* Revision 3.2 mode */
        mChallengeOut = std::vector<uint8_t>(8);
        mPreviousSignatureLo = std::vector<uint8_t>(6);
        System::arraycopy(cardResponse, 0, mChallengeOut, 0, 8);
        mCurrentKVC = cardResponse[8];
        mTransactionNumber = ByteArrayUtil::twoBytesToInt(cardResponse, 9);
        System::arraycopy(cardResponse, 11, mPreviousSignatureLo, 0, 6);
        mBalance = ByteArrayUtil::threeBytesSignedToInt(cardResponse, 17);
        mLoadLog = std::make_shared<SvLoadLogRecordAdapter>(cardResponse, 20);
        mDebitLog = std::make_shared<SvDebitLogRecordAdapter>(cardResponse, 42);
        break;
    default:
        throw IllegalStateException("Incorrect data length in response to SVGet");
    }

    return *this;
}

const std::vector<uint8_t>& CmdCardSvGet::getSvGetCommandHeader() const
{
    return mHeader;
}

uint8_t CmdCardSvGet::getCurrentKVC() const
{
    return mCurrentKVC;
}

int CmdCardSvGet::getTransactionNumber() const
{
    return mTransactionNumber;
}

const std::vector<uint8_t>& CmdCardSvGet::getPreviousSignatureLo() const
{
    return mPreviousSignatureLo;
}

const std::vector<uint8_t>& CmdCardSvGet::getChallengeOut() const
{
    return mChallengeOut;
}

int CmdCardSvGet::getBalance() const
{
    return mBalance;
}

const std::shared_ptr<SvLoadLogRecord> CmdCardSvGet::getLoadLog() const
{
    return mLoadLog;
}

const std::shared_ptr<SvDebitLogRecord> CmdCardSvGet::getDebitLog() const
{
    return mDebitLog;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardSvGet::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled.",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied (a store value " \
                                                 "operation was already done in the current " \
                                                 "session).",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6A81,
              std::make_shared<StatusProperties>("Incorrect P1 or P2.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6A86,
              std::make_shared<StatusProperties>("Le inconsistent with P2.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6D00,
              std::make_shared<StatusProperties>("SV function not present.",
                                                 typeid(CardIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>& CmdCardSvGet::getStatusTable()
    const
{
    return STATUS_TABLE;
}

}
}
}