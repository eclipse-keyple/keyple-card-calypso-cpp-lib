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

#include "CmdSamReadEventCounter.h"

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

const CalypsoSamCommand CmdSamReadEventCounter::mCommand = CalypsoSamCommand::READ_EVENT_COUNTER;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamReadEventCounter::STATUS_TABLE = initStatusTable();

CmdSamReadEventCounter::CmdSamReadEventCounter(std::shared_ptr<CalypsoSamAdapter> sam,
                                               const CounterOperationType counterOperationType,
                                               const int target)
: AbstractSamCommand(mCommand, 48),
  mSam(sam),
  mCounterOperationType(counterOperationType),
  mFirstEventCounterNumber(counterOperationType == CounterOperationType::READ_SINGLE_COUNTER ?
                           target : (target - 1) * 9)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(sam->getProductType());

    uint8_t p2;

    if (counterOperationType == CounterOperationType::READ_SINGLE_COUNTER) {
        p2 = static_cast<uint8_t>(0x81 + target);
    } else {
        p2 = static_cast<uint8_t>(0xE0 + target);
    }

    setApduRequest(
        std::make_shared<ApduRequestAdapter>(
            ApduUtil::build(cla, mCommand.getInstructionByte(), 0x00, p2, 0x00)));
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamReadEventCounter::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractSamCommand::STATUS_TABLE;

    m.insert({0x6900,
              std::make_shared<StatusProperties>("An event counter cannot be incremented.",
                                                 typeid(CalypsoSamCounterOverflowException))});
    m.insert({0x6A00,
              std::make_shared<StatusProperties>("Incorrect P2.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6200,
              std::make_shared<StatusProperties>("Correct execution with warning: data not signed.",
                                                 typeid(nullptr))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamReadEventCounter::getStatusTable() const
{
    return STATUS_TABLE;
}

void CmdSamReadEventCounter::parseApduResponse(std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractSamCommand::parseApduResponse(apduResponse);

    if (isSuccessful()) {
        const std::vector<uint8_t> dataOut = apduResponse->getDataOut();
        if (mCounterOperationType == CounterOperationType::READ_SINGLE_COUNTER) {
            mSam->putEventCounter(dataOut[8], ByteArrayUtil::extractInt(dataOut, 9, 3, false));
        } else {
            for (int i = 0; i < 9; i++) {
                mSam->putEventCounter(mFirstEventCounterNumber + i,
                                      ByteArrayUtil::extractInt(dataOut, 8 + (3 * i), 3, false));
            }
        }
    }
}

}
}
}
