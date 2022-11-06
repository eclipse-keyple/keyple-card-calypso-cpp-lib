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

#include "AbstractApduCommand.h"

#include <typeinfo>

/* Keyple Core Util */
#include "StringUtils.h"

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

AbstractApduCommand::AbstractApduCommand(const CardCommand& commandRef, const int le)
: mCommandRef(commandRef), mLe(le), mName(commandRef.getName()) {}

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

void AbstractApduCommand::setApduRequest(const std::shared_ptr<ApduRequestAdapter> apduRequest)
{
    mApduRequest = apduRequest;
    mApduRequest->setInfo(mName);
}

const std::shared_ptr<ApduRequestAdapter> AbstractApduCommand::getApduRequest() const
{
    return mApduRequest;
}

AbstractApduCommand& AbstractApduCommand::setApduResponse(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    mApduResponse = apduResponse;

    return *this;
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
           (mLe == 0 || static_cast<int>(mApduResponse->getDataOut().size()) == mLe);
}

void AbstractApduCommand::checkStatus()
{
    const std::shared_ptr<StatusProperties> props = getStatusWordProperties();
    if (props != nullptr && props->isSuccessful()) {

        /* SW is successful, then check the response length (CL-CSS-RESPLE.1) */
        if (mLe != 0 && static_cast<int>(mApduResponse->getDataOut().size()) != mLe) {
            throw buildUnexpectedResponseLengthException(
                StringUtils::format("Incorrect APDU response length (expected: %d, actual: %d)",
                                    mLe, 
                                    mApduResponse->getDataOut().size()));
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

    /* Throw the exception */
    throw buildCommandException(exceptionClass, message);
}

const std::string AbstractApduCommand::getStatusInformation() const
{
    const std::shared_ptr<StatusProperties> props = getStatusWordProperties();

    return props != nullptr ? props->getInformation() : "";
}

}
}
}
