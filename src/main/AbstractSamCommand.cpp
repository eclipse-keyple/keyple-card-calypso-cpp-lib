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
#include "CalypsoSamUnexpectedResponseLengthException.h"
#include "CalypsoSamUnknownStatusException.h"

namespace keyple {
namespace card {
namespace calypso {

const std::map<const int, const std::shared_ptr<StatusProperties>>
    AbstractSamCommand::STATUS_TABLE = initStatusTable();

AbstractSamCommand::AbstractSamCommand(const CalypsoSamCommand& commandRef,
                                       const int le,
                                       const std::shared_ptr<CalypsoSamAdapter> calypsoSam)
: AbstractApduCommand(commandRef, le), mCalypsoSam(calypsoSam) {}

const std::shared_ptr<CalypsoSamAdapter> AbstractSamCommand::getCalypsoSam() const
{
    return mCalypsoSam;
}

const CalypsoSamCommand& AbstractSamCommand::getCommandRef() const
{
    return dynamic_cast<const CalypsoSamCommand&>(AbstractApduCommand::getCommandRef());
}

const CalypsoApduCommandException AbstractSamCommand::buildCommandException(
    const std::type_info& exceptionClass, const std::string& message) const
{
    const auto& command = getCommandRef();
    const auto statusWord = std::make_shared<int>(getApduResponse()->getStatusWord());

    if (exceptionClass == typeid(CalypsoSamAccessForbiddenException)) {
        return CalypsoSamAccessForbiddenException(message, command, statusWord);
    } else if (exceptionClass == typeid(CalypsoSamCounterOverflowException)) {
        return CalypsoSamCounterOverflowException(message, command, statusWord);
    } else if (exceptionClass == typeid(CalypsoSamDataAccessException)) {
        return CalypsoSamDataAccessException(message, command, statusWord);
    } else if (exceptionClass == typeid(CalypsoSamIllegalArgumentException)) {
        return CalypsoSamIllegalArgumentException(message, command);
    } else if (exceptionClass == typeid(CalypsoSamIllegalParameterException)) {
        return CalypsoSamIllegalParameterException(message, command, statusWord);
    } else if (exceptionClass == typeid(CalypsoSamIncorrectInputDataException)) {
        return CalypsoSamIncorrectInputDataException(message, command, statusWord);
    } else if (exceptionClass == typeid(CalypsoSamSecurityDataException)) {
        return CalypsoSamSecurityDataException(message, command, statusWord);
    } else {
        return CalypsoSamUnknownStatusException(message, command, statusWord);
    }
}

const CalypsoApduCommandException AbstractSamCommand::buildUnexpectedResponseLengthException(
    const std::string& message) const
{
    return CalypsoSamUnexpectedResponseLengthException(
               message,
               getCommandRef(),
               std::make_shared<int>(getApduResponse()->getStatusWord()));
}

void AbstractSamCommand::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    try {

        AbstractApduCommand::parseApduResponse(apduResponse);

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

void AbstractSamCommand::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse,
                                           const std::shared_ptr<CalypsoSamAdapter> calypsoSam)
{
    mCalypsoSam = calypsoSam;

    parseApduResponse(apduResponse);
}

}
}
}
