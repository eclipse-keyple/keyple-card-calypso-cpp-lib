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

#include "keyple/card/calypso/SecureRegularModeTransactionManagerAdapter.hpp"

#include <memory>

namespace keyple {
namespace card {
namespace calypso {

SecureRegularModeTransactionManagerAdapter::
    SecureRegularModeTransactionManagerAdapter(
        const std::shared_ptr<ProxyReaderApi>& cardReader,
        const std::shared_ptr<CalypsoCardAdapter>& card,
        const std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>&
            symmetricCryptoSecuritySetting)
: TransactionManagerAdapter<SecureRegularModeTransactionManager>(
      cardReader, card)
, SecureSymmetricCryptoTransactionManagerAdapter(
      cardReader, card, symmetricCryptoSecuritySetting)
{
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
