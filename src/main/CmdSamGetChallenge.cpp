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

#include "CmdSamGetChallenge.h"

/* Keyple Card Calypso */
#include "CalypsoSamIllegalParameterException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamGetChallenge::mCommand = CalypsoSamCommand::GET_CHALLENGE;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamGetChallenge::STATUS_TABLE = initStatusTable();

CmdSamGetChallenge::CmdSamGetChallenge(const CalypsoSam::ProductType productType,
                                       const int expectedResponseLength)
: AbstractSamCommand(mCommand, expectedResponseLength)
{
    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(SamUtilAdapter::getClassByte(productType),
                            mCommand.getInstructionByte(),
                            0,
                            0,
                            static_cast<uint8_t>(expectedResponseLength))));
}

const std::vector<uint8_t> CmdSamGetChallenge::getChallenge() const
{
    return isSuccessful() ? getApduResponse()->getDataOut() : std::vector<uint8_t>();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamGetChallenge::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamGetChallenge::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
