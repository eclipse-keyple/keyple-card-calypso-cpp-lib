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

#include "CmdCardIncreaseOrDecrease.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardDataOutOfBoundsException.h"
#include "CardIllegalParameterException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardIncreaseOrDecrease::STATUS_TABLE = initStatusTable();

CmdCardIncreaseOrDecrease::CmdCardIncreaseOrDecrease(
  const bool isDecreaseCommand,
  const CalypsoCardClass calypsoCardClass,
  const uint8_t sfi,
  const int counterNumber,
  const int incDecValue)
: AbstractCardCommand(isDecreaseCommand ? CalypsoCardCommand::DECREASE : CalypsoCardCommand::INCREASE),
  mSfi(sfi),
  mCounterNumber(counterNumber),
  mIncDecValue(incDecValue)
{
    const uint8_t cla = calypsoCardClass.getValue();

    /*
     * Convert the integer value into a 3-byte buffer
     * CL-COUN-DATAIN.1
     */
    std::vector<uint8_t> valueBuffer(3);
    valueBuffer[0] = ((incDecValue >> 16) & 0xFF);
    valueBuffer[1] = ((incDecValue >> 8) & 0xFF);
    valueBuffer[2] = (incDecValue & 0xFF);

    const uint8_t p2 = sfi * 8;

    /* This is a case4 command, we set Le = 0 */
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla,
                            getCommandRef().getInstructionByte(),
                            mCounterNumber,
                            p2,
                            valueBuffer,
                            0x00)));

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

bool CmdCardIncreaseOrDecrease::isSessionBufferUsed() const
{
    return true;
}

int CmdCardIncreaseOrDecrease::getSfi() const
{
    return mSfi;
}

int CmdCardIncreaseOrDecrease::getCounterNumber() const
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
        CmdCardIncreaseOrDecrease::STATUS_TABLE;

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
