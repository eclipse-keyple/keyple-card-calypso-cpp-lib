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

#include "CmdSamSelectDiversifier.h"

/* Keyple Card Calypso */
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamSelectDiversifier::mCommand = CalypsoSamCommand::SELECT_DIVERSIFIER;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamSelectDiversifier::STATUS_TABLE = initStatusTable();

CmdSamSelectDiversifier::CmdSamSelectDiversifier(const CalypsoSam::ProductType productType,
                                                 const std::vector<uint8_t>& diversifier)
: AbstractSamCommand(mCommand)
{
    if (diversifier.empty() || (diversifier.size() != 4 && diversifier.size() != 8)) {
        throw IllegalArgumentException("Bad diversifier value!");
    }

    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t p1 = 0x00;
    const uint8_t p2 = 0x00;

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, diversifier)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamSelectDiversifier::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied: the SAM is locked.",
                                                 typeid(CalypsoSamAccessForbiddenException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamSelectDiversifier::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
