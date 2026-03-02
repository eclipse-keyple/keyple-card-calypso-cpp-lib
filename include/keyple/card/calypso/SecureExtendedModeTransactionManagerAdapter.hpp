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

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/SecureSymmetricCryptoTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/SymmetricCryptoSecuritySettingAdapter.hpp"
#include "keypop/calypso/card/cpp/SecureExtendedModeTransactionManagerBase.hpp"
#include "keypop/card/ProxyReaderApi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::card::ProxyReaderApi;

using SecureExtendedModeTransactionManager
    = keypop::calypso::card::cpp::SecureExtendedModeTransactionManagerBase;

/**
 * Adapter of SecureExtendedModeTransactionManager.
 *
 * @since 3.0.0
 */
class SecureExtendedModeTransactionManagerAdapter final
: public SecureSymmetricCryptoTransactionManagerAdapter<
      SecureExtendedModeTransactionManager>,
  public SecureExtendedModeTransactionManager {
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
    SecureExtendedModeTransactionManagerAdapter(
        std::shared_ptr<ProxyReaderApi> cardReader,
        std::shared_ptr<CalypsoCardAdapter> card,
        std::shared_ptr<SymmetricCryptoSecuritySettingAdapter>
            symmetricCryptoSecuritySetting);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SecureExtendedModeTransactionManager&
    prepareEarlyMutualAuthentication() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SecureExtendedModeTransactionManager& prepareActivateEncryption() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.1
     */
    SecureExtendedModeTransactionManager&
    prepareDeactivateEncryption() override;

private:
    /** */
    static const std::string MSG_MSS_COMMAND_NOT_SUPPORTED;

    /** */
    static const std::string MSG_ENCRYPTION_ALREADY_ACTIVE;

    /** */
    static const std::string MSG_ENCRYPTION_NOT_ACTIVE;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
