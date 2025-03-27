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

#include "CmdCardIncreaseOrDecrease.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
#include "ByteArrayUtil.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardDataOutOfBoundsException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"
#include "CardUnknownStatusException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const int CmdCardIncreaseOrDecrease::SW_POSTPONED_DATA = 0x6200;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardIncreaseOrDecrease::STATUS_TABLE = initStatusTable();

CmdCardIncreaseOrDecrease::CmdCardIncreaseOrDecrease(
  const bool isDecreaseCommand,
  const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
  const uint8_t sfi,
  const uint8_t counterNumber,
  const int incDecValue)
: AbstractCardCommand(isDecreaseCommand ? CalypsoCardCommand::DECREASE :
                                          CalypsoCardCommand::INCREASE,
                      3,
                      calypsoCard),
  mSfi(sfi),
  mCounterNumber(counterNumber),
  mIncDecValue(incDecValue)
{
    const uint8_t cla = calypsoCard->getCardClass().getValue();

    /*
     * Convert the integer value into a 3-byte buffer
     * CL-COUN-DATAIN.1
     */
    std::vector<uint8_t> valueBuffer = ByteArrayUtil::extractBytes(incDecValue, 3);

    const uint8_t p2 = sfi * 8;

    std::shared_ptr<ApduRequestAdapter>  apduRequest;

    if (!calypsoCard->isCounterValuePostponed()) {
      /* This is a case4 command, we set Le = 0 */
      apduRequest = std::make_shared<ApduRequestAdapter>(
                             ApduUtil::build(cla,
                                             getCommandRef().getInstructionByte(),
                                             mCounterNumber,
                                             p2,
                                             valueBuffer,
                                             0x00));
    } else {
      /* This command is considered as a case 3, we do not set Le */
      apduRequest = std::make_shared<ApduRequestAdapter>(
                             ApduUtil::build(cla,
                                             getCommandRef().getInstructionByte(),
                                             mCounterNumber,
                                             p2,
                                             valueBuffer));
      setExpectedResponseLength(0);
      apduRequest->addSuccessfulStatusWord(SW_POSTPONED_DATA);
    }

    setApduRequest(apduRequest);

    std::stringstream extraInfo;
    extraInfo << "SFI:" << sfi << "h, "
              << "COUNTER:" << mCounterNumber << ", ";
    if (isDecreaseCommand) {
        extraInfo << "DECREMENT";
    } else {
        extraInfo << "INCREMENT";
    }
    extraInfo << ":" << incDecValue;

    addSubName(extraInfo.str());
}

void CmdCardIncreaseOrDecrease::parseApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractCardCommand::parseApduResponse(apduResponse);

    if (apduResponse->getStatusWord() == SW_POSTPONED_DATA) {

        if (!getCalypsoCard()->isCounterValuePostponed()) {

            throw CardUnknownStatusException("Unexpected status word: 6200h",
                                             getCommandRef(),
                                             std::make_shared<int>(SW_POSTPONED_DATA));
        }

        /* Set computed value */
        getCalypsoCard()->setCounter(mSfi, mCounterNumber, mComputedData);

    } else {

        /* Set returned value */
        getCalypsoCard()->setCounter(mSfi, mCounterNumber, apduResponse->getDataOut());
    }
}

void CmdCardIncreaseOrDecrease::setComputedData(const std::vector<uint8_t>& data)
{
    mComputedData = data;
}

bool CmdCardIncreaseOrDecrease::isSessionBufferUsed() const
{
    return true;
}

uint8_t CmdCardIncreaseOrDecrease::getSfi() const
{
    return mSfi;
}

uint8_t CmdCardIncreaseOrDecrease::getCounterNumber() const
{
    return mCounterNumber;
}

int CmdCardIncreaseOrDecrease::getIncDecValue() const
{
    return mIncDecValue;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardIncreaseOrDecrease::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6400,
              std::make_shared<StatusProperties>("Too many modifications in session.",
                                                 typeid(CardSessionBufferOverflowException))});
    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6981,
              std::make_shared<StatusProperties>("The current EF is not a Counters or Simulated " \
                                                 "Counter EF.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (no session, " \
                                                 "wrong key, encryption required).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (Never access mode, DF is " \
                                                 "invalidated, etc.)",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x6986,
              std::make_shared<StatusProperties>("Command not allowed (no current EF).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Overflow error.",
                                                 typeid(CardDataOutOfBoundsException))});
    m.insert({0x6A82,
              std::make_shared<StatusProperties>("File not found.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 value not supported.",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6103,
              std::make_shared<StatusProperties>("Successful execution (possible only in ISO7816 " \
                                                 "T=0).",
                                                 typeid(nullptr))});
    m.insert({SW_POSTPONED_DATA,
              std::make_shared<StatusProperties>("Successful execution, response data postponed " \
                                                 "until session closing.",
                                                 typeid(nullptr))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardIncreaseOrDecrease::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
