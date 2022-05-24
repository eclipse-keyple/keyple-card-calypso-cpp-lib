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

#include "CmdCardVerifyPin.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"
#include "IllegalStateException.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardDataAccessException.h"
#include "CardIllegalParameterException.h"
#include "CardPinException.h"
#include "CardSecurityContextException.h"
#include "CardSessionBufferOverflowException.h"
#include "CardTerminatedException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const CalypsoCardCommand CmdCardVerifyPin::mCommand = CalypsoCardCommand::VERIFY_PIN;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardVerifyPin::STATUS_TABLE = initStatusTable();

CmdCardVerifyPin::CmdCardVerifyPin(
  const CalypsoCardClass calypsoCardClass,
  const bool encryptPinTransmission,
  const std::vector<uint8_t>& pin)
: AbstractCardCommand(mCommand), mCla(calypsoCardClass.getValue())
{
    if (pin.empty() ||
        (!encryptPinTransmission && pin.size() != 4) ||
        (encryptPinTransmission && pin.size() != 8)) {
        throw IllegalArgumentException("The PIN must be 4 bytes long");
    }

    /* CL-PIN-PP1P2.1 */
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(mCla, mCommand.getInstructionByte(), p1, p2, pin)));

    addSubName(encryptPinTransmission ? "ENCRYPTED" : "PLAIN");

    mReadCounterOnly = false;
}

CmdCardVerifyPin::CmdCardVerifyPin(const CalypsoCardClass calypsoCardClass)
: AbstractCardCommand(mCommand), mCla(calypsoCardClass.getValue())
{
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(mCla, mCommand.getInstructionByte(), p1, p2)));

    addSubName("Read presentation counter");

    mReadCounterOnly = true;
}

bool CmdCardVerifyPin::isSessionBufferUsed() const
{
    return false;
}

bool CmdCardVerifyPin::isReadCounterOnly() const
{
    return mReadCounterOnly;
}

int CmdCardVerifyPin::getRemainingAttemptCounter() const
{
    int attemptCounter;

    switch (getApduResponse()->getStatusWord()) {
    case 0x6983:
        attemptCounter = 0;
        break;
    case 0x63C1:
        attemptCounter = 1;
        break;
    case 0x63C2:
        attemptCounter = 2;
        break;
    case 0x9000:
        attemptCounter = 3;
        break;
    default:
        std::stringstream ss;
        ss << std::setfill ('0') << std::setw(4) << std::hex << getApduResponse()->getStatusWord();
        throw IllegalStateException("Incorrect status word: " + ss.str());
    }

    return attemptCounter;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardVerifyPin::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported (only 00h, 04h or 08h " \
                                                 "are supported).",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6900,
              std::make_shared<StatusProperties>("Transaction Counter is 0.",
                                                 typeid(CardTerminatedException))});
    m.insert({0x6982,
              std::make_shared<StatusProperties>("Security conditions not fulfilled (Get " \
                                                 "Challenge not done: challenge unavailable).",
                                                 typeid(CardSecurityContextException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Access forbidden (a session is open or DF is " \
                                                 "invalidated).",
                                                 typeid(CardAccessForbiddenException))});
    m.insert({0x63C1,
              std::make_shared<StatusProperties>("Incorrect PIN (1 attempt remaining).",
                                                 typeid(CardPinException))});
    m.insert({0x63C2,
              std::make_shared<StatusProperties>("Incorrect PIN (2 attempt remaining).",
                                                 typeid(CardPinException))});
    m.insert({0x6983,
              std::make_shared<StatusProperties>("Presentation rejected (PIN is blocked).",
                                                 typeid(CardPinException))});
    m.insert({0x6D00,
              std::make_shared<StatusProperties>("PIN function not present.",
                                                 typeid(CardIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardVerifyPin::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
