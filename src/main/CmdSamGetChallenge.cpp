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

const CalypsoSamCommand CmdSamGetChallenge::mCommand = CalypsoSamCommand::DIGEST_INIT;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamGetChallenge::STATUS_TABLE = initStatusTable();

CmdSamGetChallenge::CmdSamGetChallenge(const CalypsoSam::ProductType productType,
                                       const uint8_t expectedResponseLength)
: AbstractSamCommand(mCommand)
{
    if (expectedResponseLength != 0x04 && expectedResponseLength != 0x08) {
        throw IllegalArgumentException("Bad challenge length! Expected 4 or 8, got " +
                                       std::to_string(expectedResponseLength));
    }

    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, expectedResponseLength)));
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
