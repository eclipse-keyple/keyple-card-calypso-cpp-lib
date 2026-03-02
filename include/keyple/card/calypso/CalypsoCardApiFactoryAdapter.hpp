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

#include "keyple/core/util/KeypleAssert.hpp"
#include "keypop/calypso/card/CalypsoCardApiFactory.hpp"
#include "keypop/calypso/card/card/CalypsoCard.hpp"
#include "keypop/calypso/card/card/CalypsoCardSelectionExtension.hpp"
#include "keypop/calypso/card/cpp/SecureExtendedModeTransactionManagerBase.hpp"
#include "keypop/calypso/card/cpp/SecureRegularModeTransactionManagerBase.hpp"
#include "keypop/calypso/card/transaction/AsymmetricCryptoSecuritySetting.hpp"
#include "keypop/calypso/card/transaction/FreeTransactionManager.hpp"
#include "keypop/calypso/card/transaction/SearchCommandData.hpp"
#include "keypop/calypso/card/transaction/SecurePkiModeTransactionManager.hpp"
#include "keypop/calypso/card/transaction/SymmetricCryptoSecuritySetting.hpp"
#include "keypop/calypso/card/transaction/spi/AsymmetricCryptoCardTransactionManagerFactory.hpp"
#include "keypop/calypso/card/transaction/spi/SymmetricCryptoCardTransactionManagerFactory.hpp"
#include "keypop/calypso/crypto/asymmetric/transaction/spi/AsymmetricCryptoCardTransactionManagerFactorySpi.hpp"
#include "keypop/card/ProxyReaderApi.hpp"
#include "keypop/reader/CardReader.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::Assert;
using keypop::calypso::card::CalypsoCardApiFactory;
using keypop::calypso::card::card::CalypsoCard;
using keypop::calypso::card::card::CalypsoCardSelectionExtension;
using keypop::calypso::card::transaction::AsymmetricCryptoSecuritySetting;
using keypop::calypso::card::transaction::FreeTransactionManager;
using keypop::calypso::card::transaction::SearchCommandData;
using keypop::calypso::card::transaction::SecurePkiModeTransactionManager;
using keypop::calypso::card::transaction::SymmetricCryptoSecuritySetting;
using keypop::calypso::card::transaction::spi::
    AsymmetricCryptoCardTransactionManagerFactory;
using keypop::calypso::card::transaction::spi::
    SymmetricCryptoCardTransactionManagerFactory;
using keypop::reader::CardReader;

/* C++ specific */
using SecureExtendedModeTransactionManager
    = keypop::calypso::card::cpp::SecureExtendedModeTransactionManagerBase;
using SecureRegularModeTransactionManager
    = keypop::calypso::card::cpp::SecureRegularModeTransactionManagerBase;

/**
 * Adapter of CalypsoCardApiFactory.
 *
 * @since 1.0.0
 */
class CalypsoCardApiFactoryAdapter : public CalypsoCardApiFactory {
public:
    /**
     * Destructor.
     */
    virtual ~CalypsoCardApiFactoryAdapter() = default;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::unique_ptr<CalypsoCardSelectionExtension>
    createCalypsoCardSelectionExtension() override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::unique_ptr<SymmetricCryptoSecuritySetting>
    createSymmetricCryptoSecuritySetting(
        const std::shared_ptr<SymmetricCryptoCardTransactionManagerFactory>&
            cryptoCardTransactionManagerFactory) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    std::unique_ptr<AsymmetricCryptoSecuritySetting>
    createAsymmetricCryptoSecuritySetting(
        const std::shared_ptr<AsymmetricCryptoCardTransactionManagerFactory>&
            cryptoCardTransactionManagerFactory) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::unique_ptr<FreeTransactionManager> createFreeTransactionManager(
        const std::shared_ptr<CardReader>& cardReader,
        const std::shared_ptr<CalypsoCard>& card) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::unique_ptr<SecureRegularModeTransactionManager>
    createSecureRegularModeTransactionManager(
        const std::shared_ptr<CardReader>& cardReader,
        const std::shared_ptr<CalypsoCard>& card,
        const std::shared_ptr<SymmetricCryptoSecuritySetting>& securitySetting)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::unique_ptr<SecureExtendedModeTransactionManager>
    createSecureExtendedModeTransactionManager(
        const std::shared_ptr<CardReader>& cardReader,
        const std::shared_ptr<CalypsoCard>& card,
        const std::shared_ptr<SymmetricCryptoSecuritySetting>& securitySetting)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    std::unique_ptr<SecurePkiModeTransactionManager>
    createSecurePkiModeTransactionManager(
        const std::shared_ptr<CardReader>& cardReader,
        const std::shared_ptr<CalypsoCard>& card,
        const std::shared_ptr<AsymmetricCryptoSecuritySetting>& securitySetting)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 3.0.0
     */
    std::shared_ptr<SearchCommandData> createSearchCommandData() override;

private:
    static const std::string
        MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE;
    static const std::string MSG_CARD_READER;
    static const std::string MSG_CARD;
    static const std::string MSG_SECURITY_SETTING;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
