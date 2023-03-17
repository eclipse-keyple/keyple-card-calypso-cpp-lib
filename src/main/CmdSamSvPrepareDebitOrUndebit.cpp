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

#include "CmdSamSvPrepareDebitOrUndebit.h"

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

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamSvPrepareDebitOrUndebit::STATUS_TABLE = initStatusTable();

CmdSamSvPrepareDebitOrUndebit::CmdSamSvPrepareDebitOrUndebit(
  const bool isDebitCommand,
  const std::shared_ptr<CalypsoSamAdapter> calypsoSam,
  const std::vector<uint8_t>& svGetHeader,
  const std::vector<uint8_t>& svGetData,
  const std::vector<uint8_t>& svDebitOrUndebitCmdBuildData)
: AbstractSamCommand(isDebitCommand ? CalypsoSamCommand::SV_PREPARE_DEBIT :
                                      CalypsoSamCommand::SV_PREPARE_UNDEBIT,
                     0,
                     calypsoSam)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(calypsoSam->getProductType());
    const uint8_t p1 = 0x01;
    const uint8_t p2 = 0xFF;
    std::vector<uint8_t> data(16 + svGetData.size()); /* Header(4) + SvUndebit data (12) = 16 bytes*/

    System::arraycopy(svGetHeader, 0, data, 0, 4);
    System::arraycopy(svGetData, 0, data, 4, svGetData.size());
    System::arraycopy(svDebitOrUndebitCmdBuildData,
                      0,
                      data,
                      4 + svGetData.size(),
                      svDebitOrUndebitCmdBuildData.size());

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, getCommandRef().getInstructionByte(), p1, p2, data)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamSvPrepareDebitOrUndebit::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6700,
              std::make_shared<StatusProperties>("Incorrect Lc.",
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
    CmdSamSvPrepareDebitOrUndebit::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
