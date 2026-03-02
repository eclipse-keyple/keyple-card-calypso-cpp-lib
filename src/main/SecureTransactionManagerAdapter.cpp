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

#include "keyple/card/calypso/SecureTransactionManagerAdapter.hpp"

#include <memory>
#include <string>

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CommandCloseSecureSession.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keyple/core/util/cpp/exception/RuntimeException.hpp"
#include "keypop/calypso/card/WriteAccessLevel.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::exception::IllegalStateException;
using keyple::core::util::cpp::exception::RuntimeException;
using keypop::calypso::card::WriteAccessLevel;

template <typename T>
const std::string
    SecureTransactionManagerAdapter<T>::MSG_SECURE_SESSION_NOT_OPEN
    = "Secure session is not open";
template <typename T>
const std::string SecureTransactionManagerAdapter<T>::MSG_SECURE_SESSION_OPEN
    = "Secure session is open";

template <typename T>
SecureTransactionManagerAdapter<T>::SecureTransactionManagerAdapter(
    std::shared_ptr<ProxyReaderApi> cardReader,
    std::shared_ptr<CalypsoCardAdapter> card)
: TransactionManagerAdapter<T>(cardReader, card)
{
}

template <typename T>
void
SecureTransactionManagerAdapter<T>::checkSecureSession() const
{
    if (!mIsSecureSessionOpen) {
        throw IllegalStateException(MSG_SECURE_SESSION_NOT_OPEN);
    }
}

template <typename T>
void
SecureTransactionManagerAdapter<T>::checkNoSecureSession() const
{
    if (mIsSecureSessionOpen) {
        throw IllegalStateException(MSG_SECURE_SESSION_OPEN);
    }
}

template <typename T>
void
SecureTransactionManagerAdapter<T>::disablePreOpenMode()
{
    TransactionManagerAdapter<T>::mCard->setPreOpenWriteAccessLevel(
        WriteAccessLevel::UNKOWN);
    TransactionManagerAdapter<T>::mCard->setPreOpenDataOut({});
}

template <typename T>
T&
SecureTransactionManagerAdapter<T>::prepareCancelSecureSession()
{
    try {
        TransactionManagerAdapter<T>::mCommands.push_back(
            std::unique_ptr<CommandCloseSecureSession>(
                new CommandCloseSecureSession(
                    this->getTransactionContext(),
                    this->getCommandContext(),
                    true)));

    } catch (const RuntimeException& e) {
        this->resetTransaction();

        /* Finally */
        resetCommandContext();
        disablePreOpenMode();

        throw;
    }

    /* Finally */
    resetCommandContext();
    disablePreOpenMode();

    return dynamic_cast<T&>(*this);
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */

/* Explicit template instantiations for concrete transaction manager bases */
#include "keypop/calypso/card/cpp/SecureExtendedModeTransactionManagerBase.hpp"
#include "keypop/calypso/card/cpp/SecureRegularModeTransactionManagerBase.hpp"
#include "keypop/calypso/card/transaction/SecurePkiModeTransactionManager.hpp"

template class keyple::card::calypso::SecureTransactionManagerAdapter<
    keypop::calypso::card::cpp::SecureExtendedModeTransactionManagerBase>;

template class keyple::card::calypso::SecureTransactionManagerAdapter<
    keypop::calypso::card::cpp::SecureRegularModeTransactionManagerBase>;

template class keyple::card::calypso::SecureTransactionManagerAdapter<
    keypop::calypso::card::transaction::SecurePkiModeTransactionManager>;
