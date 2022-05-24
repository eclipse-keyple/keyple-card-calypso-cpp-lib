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

#include "CmdCardGetChallenge.h"

#include <sstream>

/* Keyple Core Util */
#include "ApduUtil.h"
#include "Arrays.h"
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

const CalypsoCardCommand CmdCardGetChallenge::mCommand = CalypsoCardCommand::GET_CHALLENGE;

CmdCardGetChallenge::CmdCardGetChallenge(const CalypsoCardClass calypsoCardClass)
: AbstractCardCommand(mCommand)
{
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;
    const uint8_t le = 0x08;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(calypsoCardClass.getValue(),
                            mCommand.getInstructionByte(),
                            p1,
                            p2,
                            le)));
}

bool CmdCardGetChallenge::isSessionBufferUsed() const
{
    return false;
}

const std::vector<uint8_t> CmdCardGetChallenge::getCardChallenge() const
{
    return getApduResponse()->getDataOut();
}

}
}
}
