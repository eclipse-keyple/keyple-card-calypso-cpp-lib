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

#include "CmdCardSvGet.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "ByteArrayUtil.h"
#include "IllegalStateException.h"
#include "System.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
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

CmdCardSvGet::CmdCardSvGet(const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                           const SvOperation svOperation,
                           const bool useExtendedMode)
: AbstractCardCommand(mCommand, -1, calypsoCard)
{
    const uint8_t cla = calypsoCard->getCardClass() == CalypsoCardClass::LEGACY ?
                        CalypsoCardClass::LEGACY_STORED_VALUE.getValue() :
                        CalypsoCardClass::ISO.getValue();

    const uint8_t p1 = useExtendedMode ? 0x01 : 0x00;
    const uint8_t p2 = svOperation == SvOperation::RELOAD ? 0x07 : 0x09;

    uint8_t le;
    if (useExtendedMode) {
      le = 0x3D;
    } else {
       if (svOperation == SvOperation::RELOAD) {
          le = 0x21;
       } else {
          le = 0x1E;
       }
    }
    setExpectedResponseLength(le);

    // APDU Case 2
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, le)));

    std::stringstream ss;
    ss << "OPERATION:" << svOperation;
    addSubName(ss.str());

    mHeader = std::vector<uint8_t>(4);
    mHeader[0] = mCommand.getInstructionByte();
    mHeader[1] = p1;
    mHeader[2] = p2;
    mHeader[3] = le;
}

bool CmdCardSvGet::isSessionBufferUsed() const
{
    return false;
}

void CmdCardSvGet::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::parseApduResponse(apduResponse);

    const std::vector<uint8_t> cardResponse = apduResponse->getDataOut();

    uint8_t currentKvc = 0;
    int transactionNumber = 0;
    int balance = 0;
    std::shared_ptr<SvLoadLogRecord> loadLog = nullptr;
    std::shared_ptr<SvDebitLogRecord> debitLog = nullptr;

    switch (cardResponse.size()) {
        case 0x21: /* Compatibility mode, Reload */
        case 0x1E: /* Compatibility mode, Debit or Undebit */
        {
            std::vector<uint8_t> challengeOut(2);
            std::vector<uint8_t> previousSignatureLo = std::vector<uint8_t>(3);
            currentKvc = cardResponse[0];
            transactionNumber = ByteArrayUtil::extractInt(cardResponse, 1, 2, false);
            System::arraycopy(cardResponse, 3, previousSignatureLo, 0, 3);
            challengeOut[0] = cardResponse[6];
            challengeOut[1] = cardResponse[7];
            balance = ByteArrayUtil::extractInt(cardResponse, 8, 3, true);

            if (cardResponse.size() == 0x21) {

                /* Reload */
                loadLog = std::make_shared<SvLoadLogRecordAdapter>(cardResponse, 11);
                debitLog = nullptr;

            } else {

                /* Debit */
                loadLog = nullptr;
                debitLog = std::make_shared<SvDebitLogRecordAdapter>(cardResponse, 11);
            }

            break;
        }
        case 0x3D: /* Revision 3.2 mode */
        {
            std::vector<uint8_t> challengeOut(8);
            std::vector<uint8_t> previousSignatureLo(6);
            System::arraycopy(cardResponse, 0, challengeOut, 0, 8);
            currentKvc = cardResponse[8];
            transactionNumber = ByteArrayUtil::extractInt(cardResponse, 9, 2, false);
            System::arraycopy(cardResponse, 11, previousSignatureLo, 0, 6);
            balance = ByteArrayUtil::extractInt(cardResponse, 17, 3, true);
            loadLog = std::make_shared<SvLoadLogRecordAdapter>(cardResponse, 20);
            debitLog = std::make_shared<SvDebitLogRecordAdapter>(cardResponse, 42);
            break;
        }
        default:
            throw IllegalStateException("Incorrect data length in response to SVGet");
    }

    getCalypsoCard()->setSvData(currentKvc,
                                mHeader,
                                apduResponse->getApdu(),
                                balance,
                                transactionNumber,
                                loadLog,
                                debitLog);
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