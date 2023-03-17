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
#include "CardUnexpectedResponseLengthException.h"
#include "CardUnknownStatusException.h"

namespace keyple {
namespace card {
namespace calypso {

AbstractCardCommand::AbstractCardCommand(const CalypsoCardCommand& commandRef,
                                         const int le,
                                         const std::shared_ptr<CalypsoCardAdapter> calypsoCard)
: AbstractApduCommand(commandRef, le), mCalypsoCard(calypsoCard) {}

const CalypsoCardCommand& AbstractCardCommand::getCommandRef() const
{
    return dynamic_cast<const CalypsoCardCommand&>(AbstractApduCommand::getCommandRef());
}

const CalypsoApduCommandException AbstractCardCommand::buildCommandException(
    const std::type_info& exceptionClass, const std::string& message) const
{
    const auto& command = getCommandRef();
    const auto statusWord = std::make_shared<int>(getApduResponse()->getStatusWord());

    if (exceptionClass == typeid(CardAccessForbiddenException)) {
        return CardAccessForbiddenException(message, command, statusWord);
    } else if (exceptionClass == typeid(CardDataAccessException)) {
        return CardDataAccessException(message, command, statusWord);
    } else if (exceptionClass == typeid(CardDataOutOfBoundsException)) {
        return CardDataOutOfBoundsException(message, command, statusWord);
    } else if (exceptionClass == typeid(CardIllegalArgumentException)) {
        return CardIllegalArgumentException(message, command);
    } else if (exceptionClass == typeid(CardIllegalParameterException)) {
        return CardIllegalParameterException(message, command, statusWord);
    } else if (exceptionClass == typeid(CardPinException)) {
        return CardPinException(message, command, statusWord);
    } else if (exceptionClass == typeid(CardSecurityContextException)) {
        return CardSecurityContextException(message, command, statusWord);
    } else if (exceptionClass == typeid(CardSecurityDataException)) {
        return CardSecurityDataException(message, command, statusWord);
    } else if (exceptionClass == typeid(CardSessionBufferOverflowException)) {
        return CardSessionBufferOverflowException(message, command, statusWord);
    } else if (exceptionClass == typeid(CardTerminatedException)) {
        return CardTerminatedException(message, command, statusWord);
    } else {
        return CardUnknownStatusException(message, command, statusWord);
    }
}

const CalypsoApduCommandException AbstractCardCommand::buildUnexpectedResponseLengthException(
    const std::string& message) const
{
    return CardUnexpectedResponseLengthException(
               message,
               getCommandRef(),
               std::make_shared<int>(getApduResponse()->getStatusWord()));
  }

void AbstractCardCommand::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    AbstractApduCommand::parseApduResponse(apduResponse);
}

std::shared_ptr<CalypsoCardAdapter> AbstractCardCommand::getCalypsoCard() const
{
    return mCalypsoCard;
}

void AbstractCardCommand::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse,
                                            const std::shared_ptr<CalypsoCardAdapter> calypsoCard)
{
    mCalypsoCard = calypsoCard;

    parseApduResponse(apduResponse);
}

}
}
}
