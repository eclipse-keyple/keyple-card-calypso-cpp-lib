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

#pragma once

#include <memory>
#include <string>

#include "keyple/card/calypso/TransactionManagerAdapter.hpp"
#include "keypop/calypso/card/transaction/SecureTransactionManager.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::transaction::SecureTransactionManager;

/**
 * Adapter of SecureTransactionManager.
 *
 * @param <T> The type of the lowest level child object.
 * @since 3.0.0
 */
template <typename T>
class SecureTransactionManagerAdapter
: public virtual TransactionManagerAdapter<T>,
  public virtual SecureTransactionManager<T> {
public:
    /**
     *
     */
    bool mIsSecureSessionOpen = false;

    /**
     * Builds a new instance.
     *
     * @param cardReader The card reader to be used.
     * @param card The selected card on which to operate the transaction.
     * @since 3.0.0
     */
    SecureTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> cardReader,
        std::shared_ptr<CalypsoCardAdapter> card);

    /**
     * Resets the command context.
     *
     * @since 3.0.0
     */
    virtual void resetCommandContext() = 0;

    /**
     * Checks if a secure session is open.
     *
     * @throw IllegalStateException If no secure session is open.
     * @since 3.0.0
     */
    void checkSecureSession() const;

    /**
     * Checks if no secure session is open.
     *
     * @throw IllegalStateException If a secure session is open.
     */
    void checkNoSecureSession() const;

    /**
     * Clears the info associated with the "pre-open" mode.
     *
     * @since 3.0.0
     */
    void disablePreOpenMode();

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    T& prepareCancelSecureSession() final;

private:
    /** */
    static const std::string MSG_SECURE_SESSION_NOT_OPEN;

    /** */
    static const std::string MSG_SECURE_SESSION_OPEN;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
