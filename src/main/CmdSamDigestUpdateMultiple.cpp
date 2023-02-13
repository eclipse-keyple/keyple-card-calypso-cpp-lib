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

#include "CmdSamDigestUpdateMultiple.h"

/* Keyple Card Calypso */
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamIncorrectInputDataException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamDigestUpdateMultiple::mCommand =
    CalypsoSamCommand::DIGEST_UPDATE_MULTIPLE;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestUpdateMultiple::STATUS_TABLE = initStatusTable();

CmdSamDigestUpdateMultiple::CmdSamDigestUpdateMultiple(const CalypsoSam::ProductType productType,
                                                     const std::vector<uint8_t>& digestData)
: AbstractSamCommand(mCommand, 0)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t p1 = 0x80;
    const uint8_t p2 = 0x00;

    if (digestData.empty() || digestData.size() > 255) {
        throw IllegalArgumentException("Digest data null or too long!");
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, digestData)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamDigestUpdateMultiple::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect value in the incoming data: incorrect" \
                                                 "structure.",
                                                 typeid(CalypsoSamIncorrectInputDataException))});
    m.insert({0x6B00,
              std::make_shared<StatusProperties>("Incorrect P1.",
                                                 typeid(CalypsoSamIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamDigestUpdateMultiple::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
