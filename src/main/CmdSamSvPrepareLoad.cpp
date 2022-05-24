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

#include "CmdSamSvPrepareLoad.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CalypsoCardClass.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamIncorrectInputDataException.h"
#include "CalypsoSamIllegalParameterException.h"
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

const CalypsoSamCommand CmdSamSvPrepareLoad::mCommand = CalypsoSamCommand::SV_PREPARE_LOAD;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamSvPrepareLoad::STATUS_TABLE = initStatusTable();

CmdSamSvPrepareLoad::CmdSamSvPrepareLoad(const CalypsoSam::ProductType productType,
                                         const std::vector<uint8_t>& svGetHeader,
                                         const std::vector<uint8_t>& svGetData,
                                         const std::vector<uint8_t>& svReloadCmdBuildData)
: AbstractSamCommand(mCommand)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    const uint8_t p1 = 0x01;
    const uint8_t p2 = 0xFF;
    std::vector<uint8_t> data(19 + svGetData.size()); /* Header(4) + SvReload data (15) = 19 bytes*/

    System::arraycopy(svGetHeader, 0, data, 0, 4);
    System::arraycopy(svGetData, 0, data, 4, svGetData.size());
    System::arraycopy(svReloadCmdBuildData,
                      0,
                      data,
                      4 + svGetData.size(),
                      svReloadCmdBuildData.size());

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, data)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamSvPrepareLoad::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Lc value not supported.",
                                                 typeid(CardIllegalParameterException))});
    m.insert({0x6985,
              std::make_shared<StatusProperties>("Preconditions not satisfied.",
                                                 typeid(CalypsoSamAccessForbiddenException))});
    m.insert({0x6A00,
              std::make_shared<StatusProperties>("Incorrect P1 or P2",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6A80,
              std::make_shared<StatusProperties>("Incorrect incoming data.",
                                                 typeid(CalypsoSamIncorrectInputDataException))});
    m.insert({0x6A83,
              std::make_shared<StatusProperties>("Record not found: ciphering key not found",
                                                 typeid(CalypsoSamDataAccessException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamSvPrepareLoad::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
