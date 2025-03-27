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

#include "AbstractApduCommand.h"

#include <typeinfo>

/* Keyple Core Util */
#include "StringUtils.h"

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

using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/* STATUS PROPERTIES ---------------------------------------------------------------------------- */

StatusProperties::StatusProperties(const std::string& information)
: mInformation(information), mSuccessful(true), mExceptionClass(typeid(nullptr)) {}

StatusProperties::StatusProperties(
  const std::string& information, const std::type_info& exceptionClass)
: mInformation(information),
  mSuccessful(exceptionClass == typeid(nullptr)),
  mExceptionClass(exceptionClass) {}

const std::string& StatusProperties::getInformation() const
{
    return mInformation;
}

bool StatusProperties::isSuccessful() const
{
    return mSuccessful;
}

const std::type_info& StatusProperties::getExceptionClass() const
{
    return mExceptionClass;
}

/* ABSTRACT APDU COMMAND ------------------------------------------------------------------------ */

const std::map<const int, const std::shared_ptr<StatusProperties>>
    AbstractApduCommand::STATUS_TABLE = {
    {0x9000, std::make_shared<StatusProperties>("Success")},
};

AbstractApduCommand::AbstractApduCommand(const CardCommand& commandRef, const int expectedResponseLength)
: mCommandRef(commandRef), mExpectedResponseLength(expectedResponseLength), mName(commandRef.getName()) {}

void AbstractApduCommand::addSubName(const std::string& subName)
{
    mName.append("-").append(subName);
    mApduRequest->setInfo(mName);
}

const CardCommand& AbstractApduCommand::getCommandRef() const
{
    return mCommandRef;
}

const std::string& AbstractApduCommand::getName() const
{
    return mName;
}

void AbstractApduCommand::setExpectedResponseLength(const int expectedResponseLength)
{
    mExpectedResponseLength = expectedResponseLength;
}

void AbstractApduCommand::setApduRequest(const std::shared_ptr<ApduRequestAdapter> apduRequest)
{
    mApduRequest = apduRequest;
    mApduRequest->setInfo(mName);
}

const std::shared_ptr<ApduRequestAdapter> AbstractApduCommand::getApduRequest() const
{
    return mApduRequest;
}

void AbstractApduCommand::parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    mApduResponse = apduResponse;

    checkStatus();
}

const std::shared_ptr<ApduResponseApi> AbstractApduCommand::getApduResponse() const
{
    return mApduResponse;
}

const std::map<const int, const std::shared_ptr<StatusProperties>>&
    AbstractApduCommand::getStatusTable() const
{
    return STATUS_TABLE;
}

const std::shared_ptr<StatusProperties> AbstractApduCommand::getStatusWordProperties() const
{
    const std::map<const int, const std::shared_ptr<StatusProperties>>& table = getStatusTable();

    const auto it = getStatusTable().find(mApduResponse->getStatusWord());

    return it != table.end() ? it->second : nullptr;
}

bool AbstractApduCommand::isSuccessful() const
{
    const std::shared_ptr<StatusProperties> props = getStatusWordProperties();

    return props != nullptr &&
           props->isSuccessful() &&
           /* CL-CSS-RESPLE.1 */
           (mExpectedResponseLength == -1 || static_cast<int>(mApduResponse->getDataOut().size()) == mExpectedResponseLength);
}

void AbstractApduCommand::checkStatus()
{
    const std::shared_ptr<StatusProperties> props = getStatusWordProperties();
    if (props != nullptr && props->isSuccessful()) {

        /* SW is successful, then check the response length (CL-CSS-RESPLE.1) */
        if (mExpectedResponseLength != -1 && static_cast<int>(mApduResponse->getDataOut().size()) != mExpectedResponseLength) {

            /*
             * Throw the exception
             *
             * C++: the buildCommandException() mechanism does not work as all exceptions are casted
             *      into a generic type that prevents try/catch blocks from catching derived type
             *      exceptions.
             *      Copy/pasted the function content here.
             */
            try {

                /* Try with Card Command first */
                (void)dynamic_cast<const CalypsoCardCommand&>(getCommandRef());
                CalypsoApduCommandException ex =
                    buildUnexpectedResponseLengthException(
                        StringUtils::format("Incorrect APDU response length (expected: %d, " \
                                            "actual: %d)",
                                            mExpectedResponseLength,
                                            mApduResponse->getDataOut().size()));

                throw static_cast<const CardUnexpectedResponseLengthException&>(ex);

            } catch (const std::bad_cast& e) {

                /* Assume it's Sam Command then */
                CalypsoApduCommandException ex =
                    buildUnexpectedResponseLengthException(
                        StringUtils::format("Incorrect APDU response length (expected: %d, " \
                                            "actual: %d)",
                                            mExpectedResponseLength,
                                            mApduResponse->getDataOut().size()));

                throw static_cast<const CalypsoSamUnexpectedResponseLengthException&>(ex);
            }
        }

        /* SW and response length are correct */
        return;
    }

    /* Status word is not referenced, or not successful */

    /* Exception class */
    const std::type_info& exceptionClass = props != nullptr ? props->getExceptionClass()
                                                            : typeid(nullptr);

    /* Message */
    const std::string message = props != nullptr ? props->getInformation() : "Unknown status";

    /*
     * Throw the exception
     *
     * C++: the buildCommandException() mechanism does not work as all exceptions are casted into
     *      a generic type that prevents try/catch blocks from catching derived type exceptions.
     *      Copy/pasted the function content here.
     */
    //throw buildCommandException(exceptionClass, message);

    try {

        /* Try with Card Command first */
        const auto& command = dynamic_cast<const CalypsoCardCommand&>(getCommandRef());
        const auto statusWord = std::make_shared<int>(getApduResponse()->getStatusWord());

        if (exceptionClass == typeid(CardAccessForbiddenException)) {

            throw CardAccessForbiddenException(message, command, statusWord);

        } else if (exceptionClass == typeid(CardDataAccessException)) {

            throw CardDataAccessException(message, command, statusWord);

        } else if (exceptionClass == typeid(CardDataOutOfBoundsException)) {

            throw CardDataOutOfBoundsException(message, command, statusWord);

        } else if (exceptionClass == typeid(CardIllegalArgumentException)) {

            throw CardIllegalArgumentException(message, command);

        } else if (exceptionClass == typeid(CardIllegalParameterException)) {

            throw CardIllegalParameterException(message, command, statusWord);

        } else if (exceptionClass == typeid(CardPinException)) {

            throw CardPinException(message, command, statusWord);

        } else if (exceptionClass == typeid(CardSecurityContextException)) {

            throw CardSecurityContextException(message, command, statusWord);

        } else if (exceptionClass == typeid(CardSecurityDataException)) {

            throw CardSecurityDataException(message, command, statusWord);

        } else if (exceptionClass == typeid(CardSessionBufferOverflowException)) {

            throw CardSessionBufferOverflowException(message, command, statusWord);

        } else if (exceptionClass == typeid(CardTerminatedException)) {

            throw CardTerminatedException(message, command, statusWord);

        } else {

            throw CardUnknownStatusException(message, command, statusWord);
        }

    } catch (const std::bad_cast& e) {

        /* It's a Sam Command */
        const auto& command = dynamic_cast<const CalypsoSamCommand&>(getCommandRef());
        const auto statusWord = std::make_shared<int>(getApduResponse()->getStatusWord());

        if (exceptionClass == typeid(CalypsoSamAccessForbiddenException)) {

            throw CalypsoSamAccessForbiddenException(message, command, statusWord);

        } else if (exceptionClass == typeid(CalypsoSamCounterOverflowException)) {

            throw CalypsoSamCounterOverflowException(message, command, statusWord);

        } else if (exceptionClass == typeid(CalypsoSamDataAccessException)) {

            throw CalypsoSamDataAccessException(message, command, statusWord);

        } else if (exceptionClass == typeid(CalypsoSamIllegalArgumentException)) {

            throw CalypsoSamIllegalArgumentException(message, command);

        } else if (exceptionClass == typeid(CalypsoSamIllegalParameterException)) {

            throw CalypsoSamIllegalParameterException(message, command, statusWord);

        } else if (exceptionClass == typeid(CalypsoSamIncorrectInputDataException)) {

            throw CalypsoSamIncorrectInputDataException(message, command, statusWord);

        } else if (exceptionClass == typeid(CalypsoSamSecurityDataException)) {

            throw CalypsoSamSecurityDataException(message, command, statusWord);

        } else {

            throw CalypsoSamUnknownStatusException(message, command, statusWord);
        }
    }
}

const std::string AbstractApduCommand::getStatusInformation() const
{
    const std::shared_ptr<StatusProperties> props = getStatusWordProperties();

    return props != nullptr ? props->getInformation() : "";
}

}
}
}
