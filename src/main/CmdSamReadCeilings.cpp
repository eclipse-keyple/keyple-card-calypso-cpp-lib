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

#include "CmdSamReadCeilings.h"

/* Keyple Card Calypso */
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "SamUtilAdapter.h"

/* Keyple Core Util */
#include "ApduUtil.h"
#include "ByteArrayUtil.h"
#include "IllegalArgumentException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

const CalypsoSamCommand CmdSamReadCeilings::mCommand = CalypsoSamCommand::READ_CEILINGS;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamReadCeilings::STATUS_TABLE = initStatusTable();

CmdSamReadCeilings::CmdSamReadCeilings(std::shared_ptr<CalypsoSamAdapter> sam,
                                       const CeilingsOperationType ceilingsOperationType,
                                       const int target)
: AbstractSamCommand(mCommand, 48),
  mSam(sam),
  mCeilingsOperationType(ceilingsOperationType),
  mFirstEventCeilingNumber(ceilingsOperationType == CeilingsOperationType::READ_SINGLE_CEILING ?
                           target : (target - 1) * 9)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(sam->getProductType());

    uint8_t p1;
    uint8_t p2;

    if (ceilingsOperationType == CeilingsOperationType::READ_SINGLE_CEILING) {
        p1 = target;
        p2 = 0xB8;
    } else {
        p1 = 0x00;
        p2 = static_cast<uint8_t>(0xB0 + target);
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), p1, p2, 0x00)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamReadCeilings::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6900,
              std::make_shared<StatusProperties>("An event counter cannot be incremented.",
                                                 typeid(CalypsoSamCounterOverflowException))});
    m.insert({0x6A00,
              std::make_shared<StatusProperties>("Incorrect P1 or P2.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6200,
              std::make_shared<StatusProperties>("Correct execution with warning: data not signed.",
                                                 typeid(nullptr))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamReadCeilings::getStatusTable() const
{
    return STATUS_TABLE;
}

void CmdSamReadCeilings::parseApduResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractSamCommand::parseApduResponse(apduResponse);

    const std::vector<uint8_t> dataOut = apduResponse->getDataOut();
    if (mCeilingsOperationType == CeilingsOperationType::READ_SINGLE_CEILING) {
        mSam->putEventCeiling(dataOut[8], ByteArrayUtil::extractInt(dataOut, 9, 3, false));
    } else {
        for (int i = 0; i < 9; i++) {
            mSam->putEventCeiling(mFirstEventCeilingNumber + i,
                                  ByteArrayUtil::extractInt(dataOut, 8 + (3 * i), 3, false));
        }
    }
}

}
}
}
