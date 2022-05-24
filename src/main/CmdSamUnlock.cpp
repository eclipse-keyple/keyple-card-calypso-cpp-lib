/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "CmdSamUnlock.h"

/* Keyple Card Calypso */
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamSecurityDataException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamUnlock::mCommand = CalypsoSamCommand::UNLOCK;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamUnlock::STATUS_TABLE = initStatusTable();


CmdSamUnlock::CmdSamUnlock(const CalypsoSam::ProductType productType, const std::vector<uint8_t>& unlockData)
: AbstractSamCommand(mCommand)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    if (unlockData.empty()) {
        throw IllegalArgumentException("Unlock data null!");
    }

    if (unlockData.size() != 8 && unlockData.size() != 16) {
        throw IllegalArgumentException("Unlock data should be 8 ou 16 bytes long!");
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, unlockData)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>& CmdSamUnlock::getStatusTable()
    const
{
    return STATUS_TABLE;
}

const std::map<const int, const std::shared_ptr<StatusProperties>> CmdSamUnlock::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied (SAM not locked?).",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6988,
              std::make_shared<StatusProperties>("Incorrect UnlockData.",
                                                 typeid(CalypsoSamSecurityDataException))});

    return m;
}

}
}
}
