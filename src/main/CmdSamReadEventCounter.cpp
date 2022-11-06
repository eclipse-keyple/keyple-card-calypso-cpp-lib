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

#include "CmdSamReadEventCounter.h"

/* Keyple Card Calypso */
#include "CalypsoSamCounterOverflowException.h"
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

const CalypsoSamCommand CmdSamReadEventCounter::mCommand = CalypsoSamCommand::READ_EVENT_COUNTER;
const int CmdSamReadEventCounter::MAX_COUNTER_NUMB = 26;
const int CmdSamReadEventCounter::MAX_COUNTER_REC_NUMB = 3;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamReadEventCounter::STATUS_TABLE = initStatusTable();

CmdSamReadEventCounter::CmdSamReadEventCounter(const CalypsoSam::ProductType productType, 
                                               const SamEventCounterOperationType operationType,
                                               const int index)
: AbstractSamCommand(mCommand, 0)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    
    uint8_t p2;

    if (operationType == SamEventCounterOperationType::COUNTER_RECORD) {
        if (index < 1 || index > MAX_COUNTER_REC_NUMB) {
            throw IllegalArgumentException("Record Number must be between 1 and " + 
                                           std::to_string(MAX_COUNTER_REC_NUMB) + 
                                           ".");
        }

        p2 = 0xE0 + index;
    
    } else {
        /* SINGLE_COUNTER */
        if (index < 0 || index > MAX_COUNTER_NUMB) {
            throw IllegalArgumentException("Counter Number must be between 0 and " + 
                                           std::to_string(MAX_COUNTER_NUMB) + 
                                           ".");
        }

        p2 = 0x80 + index;
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

const std::vector<uint8_t> CmdSamReadEventCounter::getCounterData() const
{
    return isSuccessful() ? getApduResponse()->getDataOut() : std::vector<uint8_t>();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamReadEventCounter::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
