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

#include "AbstractSamCommand.h"

/* Keyple Card calypso */
#include "CalypsoCardCommand.h"
#include "CalypsoSamAccessForbiddenException.h"
#include "CalypsoSamCounterOverflowException.h"
#include "CalypsoSamDataAccessException.h"
#include "CalypsoSamIllegalArgumentException.h"
#include "CalypsoSamIllegalParameterException.h"
#include "CalypsoSamIncorrectInputDataException.h"
#include "CalypsoSamSecurityDataException.h"
#include "CalypsoSamUnknownStatusException.h"

namespace keyple {
namespace card {
namespace calypso {

const std::map<const int, const std::shared_ptr<StatusProperties>>
    AbstractSamCommand::STATUS_TABLE = initStatusTable();

AbstractSamCommand::AbstractSamCommand(const CalypsoSamCommand& commandRef)
: AbstractApduCommand(commandRef) {}

const CalypsoSamCommand& AbstractSamCommand::getCommandRef() const
{
    return dynamic_cast<const CalypsoSamCommand&>(AbstractApduCommand::getCommandRef());
}

const CalypsoApduCommandException AbstractSamCommand::buildCommandException(
    const std::type_info& exceptionClass,
    const std::string& message,
    const CardCommand& commandRef,
    const int statusWord) const
{

    const auto& command = dynamic_cast<const CalypsoSamCommand&>(commandRef);
    const auto sw = std::make_shared<int>(statusWord);

    if (exceptionClass == typeid(CalypsoSamAccessForbiddenException)) {
        return CalypsoSamAccessForbiddenException(message, command, sw);
    } else if (exceptionClass == typeid(CalypsoSamCounterOverflowException)) {
        return CalypsoSamCounterOverflowException(message, command, sw);
    } else if (exceptionClass == typeid(CalypsoSamDataAccessException)) {
        return CalypsoSamDataAccessException(message, command, sw);
    } else if (exceptionClass == typeid(CalypsoSamIllegalArgumentException)) {
        return CalypsoSamIllegalArgumentException(message, command);
    } else if (exceptionClass == typeid(CalypsoSamIllegalParameterException)) {
        return CalypsoSamIllegalParameterException(message, command, sw);
    } else if (exceptionClass == typeid(CalypsoSamIncorrectInputDataException)) {
        return CalypsoSamIncorrectInputDataException(message, command, sw);
    } else if (exceptionClass == typeid(CalypsoSamSecurityDataException)) {
        return CalypsoSamSecurityDataException(message, command, sw);
    } else {
        return CalypsoSamUnknownStatusException(message, command, sw);
    }
}

AbstractSamCommand& AbstractSamCommand::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    return dynamic_cast<AbstractSamCommand&>(AbstractApduCommand::setApduResponse(apduResponse));
}

void AbstractSamCommand::checkStatus()
{
    try {
        AbstractApduCommand::checkStatus();
    } catch (const CalypsoApduCommandException& e) {
        throw static_cast<const CalypsoSamCommandException&>(e);
    }
}

const std::map<const int, const std::shared_ptr<StatusProperties>>
    AbstractSamCommand::initStatusTable()
{
    std::map<const int, const std::shared_ptr<StatusProperties>> m =
        AbstractApduCommand::STATUS_TABLE;

    m.insert({0x6D00,
              std::make_shared<StatusProperties>("Instruction unknown.",
                                                 typeid(CalypsoSamIllegalParameterException))});
    m.insert({0x6E00,
              std::make_shared<StatusProperties>("Class not supported.",
                                                 typeid(CalypsoSamIllegalParameterException))});

    return m;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    AbstractSamCommand::getStatusTable() const
{
    return STATUS_TABLE;
}

}
}
}
