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

#include "CmdCardChangePin.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardIllegalParameterException.h"
#include "CardPinException.h"
#include "CardSecurityContextException.h"
#include "CardSecurityDataException.h"
#include "CardTerminatedException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

const CalypsoCardCommand CmdCardChangePin::mCommand = CalypsoCardCommand::CHANGE_PIN;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardChangePin::STATUS_TABLE = initStatusTable();

CmdCardChangePin::CmdCardChangePin(const CalypsoCardClass calypsoCardClass,
                                   const std::vector<uint8_t>& newPinData)
: AbstractCardCommand(mCommand)
{
    if (newPinData.empty() || (newPinData.size() != 0x04 && newPinData.size() != 0x10)) {
        throw IllegalArgumentException("Bad PIN data length.");
    }

    const uint8_t cla = calypsoCardClass.getValue();
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0xFF; /* CL-PIN-MP1P2.1 */

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, newPinData)));
}

bool CmdCardChangePin::isSessionBufferUsed() const
{
    return false;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardChangePin::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported (not 04h, 10h, 18h, 20h).",
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
    m.insert({0x6988,
              std::make_shared<StatusProperties>("Incorrect Cryptogram.",
                                                 typeid(CardSecurityDataException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Decrypted message incorrect (key algorithm not " \
                                                 "supported, incorrect padding, etc.).",
                                                 typeid(CardSecurityDataException))});
    m.insert({0x6A87,
              std::make_shared<StatusProperties>("Lc not compatible with P2.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("Incorrect P1, P2.",
                                                 typeid(CardIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardChangePin::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
