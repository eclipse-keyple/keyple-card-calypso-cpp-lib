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

#include "CmdSamReadCeilings.h"

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

const CalypsoSamCommand CmdSamReadCeilings::mCommand = CalypsoSamCommand::READ_CEILINGS;
const int CmdSamReadCeilings::MAX_CEILING_NUMB = 26;
const int CmdSamReadCeilings::MAX_CEILING_REC_NUMB = 3;

const std::map<const int, const std::shared_ptr<StatusProperties>>
    CmdSamReadCeilings::STATUS_TABLE = initStatusTable();

CmdSamReadCeilings::CmdSamReadCeilings(const CalypsoSam::ProductType productType, 
                                       const CeilingsOperationType operationType,
                                       const int index)
: AbstractSamCommand(mCommand, 0)
{
    const uint8_t cla = SamUtilAdapter::getClassByte(productType);
    
    uint8_t p1;
    uint8_t p2;

    if (operationType == CeilingsOperationType::CEILING_RECORD) {
        if (index < 0 || index > MAX_CEILING_REC_NUMB) {
            throw IllegalArgumentException("Record Number must be between 1 and " + 
                                           std::to_string(MAX_CEILING_REC_NUMB) + 
                                           ".");
        }

        p1 = 0x00;
        p2 = 0xB0 + index;
    
    } else {
        /* SINGLE_CEILING */
        if (index < 0 || index > MAX_CEILING_NUMB) {
            throw IllegalArgumentException("Counter Number must be between 0 and " + 
                                           std::to_string(MAX_CEILING_NUMB) + 
                                           ".");
        }

        p1 = static_cast<uint8_t>(index);
        p2 = 0xB8;
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

const std::vector<uint8_t> CmdSamReadCeilings::getCeilingsData() const
{
    return isSuccessful() ? getApduResponse()->getDataOut() : std::vector<uint8_t>();
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    CmdSamReadCeilings::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
