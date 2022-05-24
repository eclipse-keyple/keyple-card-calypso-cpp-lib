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

#include "CmdCardGetDataTraceabilityInformation.h"

/* Keyple Card Calypso */
#include "CardDataAccessException.h"

/* Keyple Core Util */
#include "ApduUtil.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;

const CalypsoCardCommand CmdCardGetDataTraceabilityInformation::mCommand =
    CalypsoCardCommand::GET_DATA;
const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardGetDataTraceabilityInformation::STATUS_TABLE = initStatusTable();

CmdCardGetDataTraceabilityInformation::CmdCardGetDataTraceabilityInformation(
    const CalypsoCardClass calypsoCardClass)
: AbstractCardCommand(mCommand)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(
                calypsoCardClass.getValue(),
                mCommand.getInstructionByte(),
                0x01,
                0x85,
                0x00)));
}

bool CmdCardGetDataTraceabilityInformation::isSessionBufferUsed() const
{
    return false;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdCardGetDataTraceabilityInformation::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6A88,
              std::make_shared<StatusProperties>("Data object not found (optional mode not " \
                                                 "available).",
                                                 typeid(CardDataAccessException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("P1 or P2 value not supported.",
                                                 typeid(CardDataAccessException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdCardGetDataTraceabilityInformation::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
