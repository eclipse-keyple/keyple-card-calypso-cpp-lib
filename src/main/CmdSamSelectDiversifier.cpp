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

#include "CmdSamSelectDiversifier.h"

/* Keyple Card Calypso */
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamAccessForbiddenException.h"
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

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamSelectDiversifier::STATUS_TABLE = initStatusTable();

CmdSamSelectDiversifier::CmdSamSelectDiversifier(
  const std::shared_ptr<CalypsoSamAdapter> calypsoSam,
  std::vector<uint8_t>& diversifier)
: AbstractSamCommand(CalypsoSamCommand::SELECT_DIVERSIFIER, -1, calypsoSam)
{
    /* Format the diversifier on 4 or 8 bytes if needed */
    if (static_cast<int>(diversifier.size()) != 4 &&
        static_cast<int>(diversifier.size()) != 8) {
        const int newLength = static_cast<int>(diversifier.size()) < 4 ? 4 : 8;
        std::vector<uint8_t> tmp(newLength);
        System::arraycopy(diversifier, 0, tmp, newLength - diversifier.size(), diversifier.size());
        diversifier = tmp;
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(SamUtilAdapter::getClassByte(calypsoSam->getProductType()),
                            getCommandRef().getInstructionByte(),
                            0,
                            0,
                            diversifier)));
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
