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

#include "AbstractCardCommand.h"

/* Keyple Card Calypso */
#include "CardAccessForbiddenException.h"
#include "CardCommandException.h"
#include "CardDataAccessException.h"
#include "CardDataOutOfBoundsException.h"
#include "CardIllegalArgumentException.h"
#include "CardIllegalParameterException.h"
#include "CardPinException.h"
#include "CardSecurityContextException.h"
#include "CardSecurityDataException.h"
#include "CardSessionBufferOverflowException.h"
#include "CardTerminatedException.h"
#include "CardUnknownStatusException.h"

namespace keyple {
namespace card {
namespace calypso {

AbstractCardCommand::AbstractCardCommand(const CalypsoCardCommand& commandRef)
: AbstractApduCommand(commandRef) {}

const CalypsoCardCommand& AbstractCardCommand::getCommandRef() const
{
    return dynamic_cast<const CalypsoCardCommand&>(AbstractApduCommand::getCommandRef());
}

const CalypsoApduCommandException AbstractCardCommand::buildCommandException(
    const std::type_info& exceptionClass,
    const std::string& message,
    const CardCommand& commandRef,
    const int statusWord) const {

    const auto& command = dynamic_cast<const CalypsoCardCommand&>(commandRef);
    const auto sw = std::make_shared<int>(statusWord);

    if (exceptionClass == typeid(CardAccessForbiddenException)) {
        return CardAccessForbiddenException(message, command, sw);
    } else if (exceptionClass == typeid(CardDataAccessException)) {
        return CardDataAccessException(message, command, sw);
    } else if (exceptionClass == typeid(CardDataOutOfBoundsException)) {
        return CardDataOutOfBoundsException(message, command, sw);
    } else if (exceptionClass == typeid(CardIllegalArgumentException)) {
        return CardIllegalArgumentException(message, command);
    } else if (exceptionClass == typeid(CardIllegalParameterException)) {
        return CardIllegalParameterException(message, command, sw);
    } else if (exceptionClass == typeid(CardPinException)) {
        return CardPinException(message, command, sw);
    } else if (exceptionClass == typeid(CardSecurityContextException)) {
        return CardSecurityContextException(message, command, sw);
    } else if (exceptionClass == typeid(CardSecurityDataException)) {
        return CardSecurityDataException(message, command, sw);
    } else if (exceptionClass == typeid(CardSessionBufferOverflowException)) {
        return CardSessionBufferOverflowException(message, command, sw);
    } else if (exceptionClass == typeid(CardTerminatedException)) {
        return CardTerminatedException(message, command, sw);
    } else {
        return CardUnknownStatusException(message, command, sw);
    }
}

AbstractCardCommand& AbstractCardCommand::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    return dynamic_cast<AbstractCardCommand&>(AbstractApduCommand::setApduResponse(apduResponse));
}

void AbstractCardCommand::checkStatus()
{
    try {
        AbstractApduCommand::checkStatus();
    } catch (CalypsoApduCommandException& e) {
        throw dynamic_cast<CardCommandException&>(e);
    }
}

}
}
}
