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

#include "keyple/card/calypso/SecureExtendedModeTransactionManagerAdapter.hpp"

#include <memory>
#include <string>

#include "keyple/card/calypso/CardCommandRef.hpp"
#include "keyple/card/calypso/CommandManageSession.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keyple/core/util/cpp/exception/RuntimeException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::exception::IllegalStateException;
using keyple::core::util::cpp::exception::RuntimeException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;

const std::string
    SecureExtendedModeTransactionManagerAdapter::MSG_MSS_COMMAND_NOT_SUPPORTED
    = std::string("'Manage Secure Session' command is not available for this ")
      + "context (Card and/or SAM does not support extended mode)";
const std::string
    SecureExtendedModeTransactionManagerAdapter::MSG_ENCRYPTION_ALREADY_ACTIVE
    = "Encryption is already active";
const std::string
    SecureExtendedModeTransactionManagerAdapter::MSG_ENCRYPTION_NOT_ACTIVE
    = "Encryption is not active";

SecureExtendedModeTransactionManagerAdapter::
    SecureExtendedModeTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> cardReader,
        std::shared_ptr<CalypsoCardAdapter> card,
        std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>
            symmetricCryptoSecuritySetting)
:

    TransactionManagerAdapter<SecureExtendedModeTransactionManagerBase>(
        cardReader, card)
, SecureSymmetricCryptoTransactionManagerAdapter<
      SecureExtendedModeTransactionManager>(
      cardReader, card, symmetricCryptoSecuritySetting)
{
}

SecureExtendedModeTransactionManager&
SecureExtendedModeTransactionManagerAdapter::prepareEarlyMutualAuthentication()
{
    try {
        if (!mIsExtendedMode) {
            throw UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
        }

        checkSecureSession();

        /*
         * Add a new command or update the last command if it is an MSS command.
         */
        if (!mCommands.empty()
            && mCommands[mCommands.size() - 1]->getCommandRef()
                   == CardCommandRef::MANAGE_SECURE_SESSION) {
            auto& command = mCommands[mCommands.size() - 1];
            auto session
                = std::dynamic_pointer_cast<CommandManageSession>(command);
            session->setMutualAuthenticationRequested(true);

        } else {
            auto session = std::make_shared<CommandManageSession>(
                mTransactionContext, getCommandContext());
            session->setMutualAuthenticationRequested(true)
                .setEncryptionRequested(mIsEncryptionActive);
            mCommands.push_back(session);
        }

    } catch (...) {
        resetTransaction();
        throw;
    }

    return *this;
}

SecureExtendedModeTransactionManager&
SecureExtendedModeTransactionManagerAdapter::prepareActivateEncryption()
{
    try {
        if (!mIsExtendedMode) {
            throw UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
        }

        checkSecureSession();

        if (mIsEncryptionActive) {
            throw IllegalStateException(MSG_ENCRYPTION_ALREADY_ACTIVE);
        }

        /*
         * Add a new command or update the last command if it is an MSS command.
         */
        if (!mCommands.empty()
            && mCommands[mCommands.size() - 1]->getCommandRef()
                   == CardCommandRef::MANAGE_SECURE_SESSION) {
            auto command = mCommands[mCommands.size() - 1];
            auto session
                = std::dynamic_pointer_cast<CommandManageSession>(command);
            session->setEncryptionRequested(true);

        } else {
            auto session = std::make_shared<CommandManageSession>(
                mTransactionContext, getCommandContext());
            session->setEncryptionRequested(mIsEncryptionActive);
            mCommands.push_back(session);
        }

        mIsEncryptionActive = true;

    } catch (...) {
        resetTransaction();
        throw;
    }

    return *this;
}

SecureExtendedModeTransactionManager&
SecureExtendedModeTransactionManagerAdapter::prepareDeactivateEncryption()
{
    try {
        if (!mIsExtendedMode) {
            throw UnsupportedOperationException(MSG_MSS_COMMAND_NOT_SUPPORTED);
        }

        checkSecureSession();

        if (!mIsEncryptionActive) {
            throw IllegalStateException(MSG_ENCRYPTION_NOT_ACTIVE);
        }

        /*
         * Add a new command or update the last command if it is an MSS command.
         */
        if (!mCommands.empty()
            && mCommands[mCommands.size() - 1]->getCommandRef()
                   == CardCommandRef::MANAGE_SECURE_SESSION) {
            auto command = mCommands[mCommands.size() - 1];
            auto session
                = std::dynamic_pointer_cast<CommandManageSession>(command);
            session->setEncryptionRequested(false);

        } else {
            auto session = std::make_shared<CommandManageSession>(
                mTransactionContext, getCommandContext());
            session->setEncryptionRequested(false);
            mCommands.push_back(session);
        }

        mIsEncryptionActive = false;

    } catch (...) {
        resetTransaction();
        throw;
    }

    return *this;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
