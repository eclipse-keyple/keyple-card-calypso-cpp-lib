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

#include "CmdSamSvCheck.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CalypsoCardClass.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamSecurityDataException.h"
#include "CardIllegalParameterException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"
#include "IllegalStateException.h"
#include "System.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamSvCheck::mCommand = CalypsoSamCommand::SV_CHECK;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamSvCheck::STATUS_TABLE = initStatusTable();

CmdSamSvCheck::CmdSamSvCheck(const CalypsoSam::ProductType productType,
                             const std::vector<uint8_t>& svCardSignature)
: AbstractSamCommand(mCommand)
{
    if (!svCardSignature.empty() && svCardSignature.size() != 3 && svCardSignature.size() != 6) {
        throw IllegalArgumentException("Invalid svCardSignature.");
    }

    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    if (!svCardSignature.empty()) {
        /* The operation is not "abort" */
        std::vector<uint8_t> data(svCardSignature.size());
        System::arraycopy(svCardSignature, 0, data, 0, svCardSignature.size());
        setApduRequest(
            std::make_shared<ApduRequestAdapter>(
                ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, data)));
    } else {
        setApduRequest(
            std::make_shared<ApduRequestAdapter>(
                ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, 0x00)));
    }
}

const std::map<const int, const std::shared_ptr<StatusProperties>> CmdSamSvCheck::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("No active SV transaction.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6988,
              std::make_shared<StatusProperties>("Incorrect SV signature.",
                                                 typeid(CalypsoSamSecurityDataException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>& CmdSamSvCheck::getStatusTable()
    const
{
    return STATUS_TABLE;
}

}
}
}
