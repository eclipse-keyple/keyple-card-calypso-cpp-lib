/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#include "keyple/card/calypso/Command.hpp"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "keyple/card/calypso/CalypsoCardConstant.hpp"
#include "keyple/card/calypso/CardAccessForbiddenException.hpp"
#include "keyple/card/calypso/CardDataAccessException.hpp"
#include "keyple/card/calypso/CardDataOutOfBoundsException.hpp"
#include "keyple/card/calypso/CardIllegalArgumentException.hpp"
#include "keyple/card/calypso/CardIllegalParameterException.hpp"
#include "keyple/card/calypso/CardPinException.hpp"
#include "keyple/card/calypso/CardSecurityContextException.hpp"
#include "keyple/card/calypso/CardSecurityDataException.hpp"
#include "keyple/card/calypso/CardSessionBufferOverflowException.hpp"
#include "keyple/card/calypso/CardTerminatedException.hpp"
#include "keyple/card/calypso/CardUnexpectedResponseLengthException.hpp"
#include "keyple/card/calypso/CardUnknownStatusException.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/CryptoIOException.hpp"
#include "keypop/calypso/crypto/asymmetric/AsymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/symmetric/SymmetricCryptoIOException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::System;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::CryptoIOException;
using keypop::calypso::crypto::asymmetric::AsymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoException;
using keypop::calypso::crypto::symmetric::SymmetricCryptoIOException;

const std::vector<std::uint8_t> Command::APDU_RESPONSE_9000 = {0x90, 0x00};

const std::map<int, const std::shared_ptr<Command::StatusProperties>>
    Command::STATUS_TABLE = [] {
        std::map<int, const std::shared_ptr<Command::StatusProperties>> m(
            Command::STATUS_TABLE);

        m.insert(
            {{0x9000, std::make_shared<Command::StatusProperties>("Success")}});
        return m;
    }();

Command::Command(
    const CardCommandRef& commandRef,
    std::unique_ptr<int> expectedResponseLength,
    std::shared_ptr<DtoAdapters::TransactionContextDto> transactionContext,
    std::shared_ptr<DtoAdapters::CommandContextDto> commandContext)
: mCommandRef(commandRef)
, mCommandContext(commandContext)
, mTransactionContext(transactionContext)
, mExpectedResponseLength(std::move(expectedResponseLength))
, mName(commandRef.getName())
{
}

void
Command::addSubName(const std::string& subName)
{
    mName += (" - " + subName);
    mApduRequest->setInfo(mName);
}

const CardCommandRef&
Command::getCommandRef() const
{
    return mCommandRef;
}

const std::string&
Command::getName() const
{
    return mName;
}

void
Command::setApduRequest(
    std::shared_ptr<DtoAdapters::ApduRequestAdapter> apduRequest)
{
    mApduRequest = apduRequest;
    mApduRequest->setInfo(mName);
}

void
Command::setApduRequestInBestEffortMode(
    std::shared_ptr<DtoAdapters::ApduRequestAdapter> apduRequest)
{
    setApduRequest(apduRequest);
    if (mCommandContext->isSecureSessionOpen()) {
        apduRequest
            ->addSuccessfulStatusWord(CalypsoCardConstant::SW_FILE_NOT_FOUND)
            .addSuccessfulStatusWord(CalypsoCardConstant::SW_RECORD_NOT_FOUND);
    }
}

std::shared_ptr<DtoAdapters::ApduRequestAdapter>
Command::getApduRequest() const
{
    return mApduRequest;
}

std::shared_ptr<ApduResponseApi>
Command::getApduResponse() const
{
    return mApduResponse;
}

std::shared_ptr<DtoAdapters::TransactionContextDto>
Command::getTransactionContext() const
{
    return mTransactionContext;
}

std::shared_ptr<DtoAdapters::CommandContextDto>
Command::getCommandContext() const
{
    return mCommandContext;
}

void
Command::setExpectedResponseLength(std::unique_ptr<int> expectedResponseLength)
{
    mExpectedResponseLength = std::move(expectedResponseLength);
}

int*
Command::getExpectedResponseLength() const
{
    return mExpectedResponseLength.get();
}

void
Command::confirmCryptoServiceSuccessfullySynchronized()
{
    mIsCryptoServiceSynchronized = true;
}

bool
Command::isCryptoServiceSynchronized() const
{
    return mIsCryptoServiceSynchronized;
}

void
Command::parseResponseForSelection(
    const std::shared_ptr<ApduResponseApi>& apduResponse,
    std::shared_ptr<CalypsoCardAdapter> calypsoCard)
{
    mTransactionContext->setCard(calypsoCard);
    parseResponse(apduResponse);
}

void
Command::updateTerminalSessionIfNeeded()
{
    updateTerminalSessionIfNeeded(mApduResponse->getApdu());
}

void
Command::updateTerminalSessionIfNeeded(
    const std::vector<std::uint8_t>& apduResponse)
{
    if (mIsCryptoServiceSynchronized) {
        return;
    }

    if (mCommandContext->isSecureSessionOpen()) {
        if (mTransactionContext->isPkiMode()) {
            /* Asymmetric crypto mode */
            std::shared_ptr<AsymmetricCryptoCardTransactionManagerSpi>
                asymmetricCryptoCardTransactionManagerSpi(
                    mTransactionContext
                        ->getAsymmetricCryptoCardTransactionManagerSpi());
            try {
                asymmetricCryptoCardTransactionManagerSpi
                    ->updateTerminalPkiSession(mApduRequest->getApdu());
                asymmetricCryptoCardTransactionManagerSpi
                    ->updateTerminalPkiSession(apduResponse);

            } catch (const AsymmetricCryptoException& e) {
                throw CryptoException(e.what(), e);
            }
        } else {
            /* Symmetric crypto mode */
            std::shared_ptr<SymmetricCryptoCardTransactionManagerSpi>
                symmetricCryptoCardTransactionManager(
                    mTransactionContext
                        ->getSymmetricCryptoCardTransactionManagerSpi());

            try {
                symmetricCryptoCardTransactionManager->updateTerminalSessionMac(
                    mApduRequest->getApdu());
                symmetricCryptoCardTransactionManager->updateTerminalSessionMac(
                    apduResponse);

            } catch (const SymmetricCryptoException& e) {
                throw CryptoException(e.what(), e);

            } catch (const SymmetricCryptoIOException& e) {
                throw CryptoIOException(e.what(), e);
            }
        }
    }

    mIsCryptoServiceSynchronized = true;
}

void
Command::encryptRequestAndUpdateTerminalSessionMacIfNeeded()
{
    if (mCommandContext->isEncryptionActive()) {
        try {
            mApduRequest->setApdu(
                mTransactionContext
                    ->getSymmetricCryptoCardTransactionManagerSpi()
                    ->updateTerminalSessionMac(mApduRequest->getApdu()));

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw CryptoIOException(e.what(), e);
        }
    }
}

void
Command::decryptResponseAndUpdateTerminalSessionMacIfNeeded(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    if (mCommandContext->isEncryptionActive()) {
        try {
            const std::vector<std::uint8_t> decryptedApdu
                = mTransactionContext
                      ->getSymmetricCryptoCardTransactionManagerSpi()
                      ->updateTerminalSessionMac(apduResponse->getApdu());

            apduResponse->setApdu(decryptedApdu);

        } catch (const SymmetricCryptoException& e) {
            throw CryptoException(e.what(), e);

        } catch (const SymmetricCryptoIOException& e) {
            throw CryptoIOException(e.what(), e);
        }

        mIsCryptoServiceSynchronized = true;
    }
}

void
Command::setApduResponseAndCheckStatus(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    mApduResponse = apduResponse;

    checkStatus();
}

bool
Command::setApduResponseAndCheckStatusInBestEffortMode(
    std::shared_ptr<ApduResponseApi> apduResponse)
{
    mApduResponse = apduResponse;

    try {
        checkStatus();

    } catch (const CardDataAccessException& e) {
        if (mCommandContext->isSecureSessionOpen()
            || (apduResponse->getStatusWord()
                    != CalypsoCardConstant::SW_FILE_NOT_FOUND
                && apduResponse->getStatusWord()
                       != CalypsoCardConstant::SW_RECORD_NOT_FOUND)) {
            throw;
        }

        return false;
    }

    return true;
}

const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
Command::getStatusTable() const
{
    return STATUS_TABLE;
}

std::shared_ptr<Command::StatusProperties>
Command::getStatusWordProperties() const
{
    const auto statusTable = getStatusTable();
    auto it = statusTable.find(mApduResponse->getStatusWord());

    return it != statusTable.end() ? it->second : nullptr;
}

void
Command::checkStatus()
{
    std::shared_ptr<StatusProperties> props = getStatusWordProperties();

    if (props != nullptr && props->isSuccessful()) {
        /* SW is successful, then check the response length (CL-CSS-RESPLE.1) */
        if (mExpectedResponseLength != nullptr
            && static_cast<int>(mApduResponse->getDataOut().size())
                   != *mExpectedResponseLength) {
            throw CardUnexpectedResponseLengthException(
                "APDU response is not the expected length. Command: "
                    + mCommandRef.getName() + ", "
                    + "Expected: " + std::to_string(*mExpectedResponseLength)
                    + ", " + "Actual: "
                    + std::to_string(mApduResponse->getDataOut().size()),
                mCommandRef);
        }

        /* SW and response length are correct. */
        return;
    }

    /* status word is not referenced, or not successful. */

    /* Exception class */
    const std::type_info& exceptionClass
        = props != nullptr ? props->getExceptionClass() : typeid(nullptr);

    /* Message */
    const std::string message
        = props != nullptr ? props->getInformation() : "Unknown status";

    /* Throw the exception */
    throw buildCommandException(exceptionClass, message);
}

CardCommandException
Command::buildCommandException(
    const std::type_info& exceptionClass, const std::string& message)
{
    if (exceptionClass == typeid(CardAccessForbiddenException)) {
        return CardAccessForbiddenException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardDataAccessException)) {
        return CardDataAccessException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardDataOutOfBoundsException)) {
        return CardDataOutOfBoundsException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardIllegalArgumentException)) {
        return CardIllegalArgumentException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardIllegalParameterException)) {
        return CardIllegalParameterException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardPinException)) {
        return CardPinException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardSecurityContextException)) {
        return CardSecurityContextException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardSecurityDataException)) {
        return CardSecurityDataException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardSessionBufferOverflowException)) {
        return CardSessionBufferOverflowException(message, mCommandRef);
    } else if (exceptionClass == typeid(CardTerminatedException)) {
        return CardTerminatedException(message, mCommandRef);
    } else {
        return CardUnknownStatusException(message, mCommandRef);
    }
}

Command::StatusProperties::StatusProperties(const std::string& information)
: mInformation(information)
, mSuccessful(true)
, mExceptionClass(typeid(nullptr))
{
}

Command::StatusProperties::StatusProperties(
    const std::string& information, const std::type_info& exceptionClass)
: mInformation(information)
, mSuccessful(exceptionClass == typeid(nullptr))
, mExceptionClass(exceptionClass)
{
}

const std::string&
Command::StatusProperties::getInformation() const
{
    return mInformation;
}

bool
Command::StatusProperties::isSuccessful() const
{
    return mSuccessful;
}

const std::type_info&
Command::StatusProperties::getExceptionClass() const
{
    return mExceptionClass;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
