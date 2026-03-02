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

#include "keyple/card/calypso/SecureSymmetricCryptoTransactionManagerAdapter.hpp"
#include "keypop/calypso/card/cpp/SecureRegularModeTransactionManagerBase.hpp"

namespace keyple {
namespace card {
namespace calypso {

using SecureRegularModeTransactionManager
    = keypop::calypso::card::cpp::SecureRegularModeTransactionManagerBase;

/**
 * Adapter of SecureRegularModeTransactionManager.
 *
 * @since 3.0.0
 */
class SecureRegularModeTransactionManagerAdapter final
: public SecureSymmetricCryptoTransactionManagerAdapter<
      SecureRegularModeTransactionManager>,
  public SecureRegularModeTransactionManager {
public:
    /**
     * Builds a new instance.
     *
     * @param cardReader The card reader to be used.
     * @param card The selected card on which to operate the transaction.
     * @param symmetricCryptoSecuritySetting The symmetric crypto security
     * setting to be used.
     * @since 3.0.0
     */
    SecureRegularModeTransactionManagerAdapter(
        const std::shared_ptr<ProxyReaderApi>& cardReader,
        const std::shared_ptr<CalypsoCardAdapter>& card,
        const std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>&
            symmetricCryptoSecuritySetting);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
