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

#include "keyple/card/calypso/CalypsoCardApiFactoryAdapter.hpp"

#include <memory>
#include <string>

#include "keyple/card/calypso/AsymmetricCryptoSecuritySettingAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardSelectionExtensionAdapter.hpp"
#include "keyple/card/calypso/FreeTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/SecureExtendedModeTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/SecurePkiModeTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/SecureRegularModeTransactionManagerAdapter.hpp"
#include "keyple/card/calypso/SymmetricCryptoSecuritySettingAdapter.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keypop/calypso/crypto/asymmetric/transaction/spi/AsymmetricCryptoCardTransactionManagerFactorySpi.hpp"
#include "keypop/calypso/crypto/symmetric/spi/SymmetricCryptoCardTransactionManagerFactorySpi.hpp"
#include "keypop/card/ProxyReaderApi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::exception::IllegalArgumentException;
using keypop::calypso::crypto::asymmetric::transaction::spi::
    AsymmetricCryptoCardTransactionManagerFactorySpi;
using keypop::calypso::crypto::symmetric::spi::
    SymmetricCryptoCardTransactionManagerFactorySpi;
using keypop::card::ProxyReaderApi;

const std::string CalypsoCardApiFactoryAdapter ::
    MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE
    = "The provided 'card' has an undefined product type";
const std::string CalypsoCardApiFactoryAdapter::MSG_CARD_READER = "cardReader";
const std::string CalypsoCardApiFactoryAdapter::MSG_CARD = "card";
const std::string CalypsoCardApiFactoryAdapter::MSG_SECURITY_SETTING
    = "securitySetting";

std::unique_ptr<CalypsoCardSelectionExtension>
CalypsoCardApiFactoryAdapter::createCalypsoCardSelectionExtension()
{
    return std::unique_ptr<CalypsoCardSelectionExtensionAdapter>(
        new CalypsoCardSelectionExtensionAdapter());
}

std::unique_ptr<SymmetricCryptoSecuritySetting>
CalypsoCardApiFactoryAdapter::createSymmetricCryptoSecuritySetting(
    const std::shared_ptr<SymmetricCryptoCardTransactionManagerFactory>&
        cryptoCardTransactionManagerFactory)
{
    Assert::getInstance().notNull(
        cryptoCardTransactionManagerFactory,
        "cryptoCardTransactionManagerFactory");

    const auto& symmetricCryptoCardTransactionManagerFactorySpi
        = std::dynamic_pointer_cast<
            SymmetricCryptoCardTransactionManagerFactorySpi>(
            cryptoCardTransactionManagerFactory);

    if (!symmetricCryptoCardTransactionManagerFactorySpi) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'factory' to ")
            + "SymmetricCryptoCardTransactionManagerFactorySpi. Actual type: "
            + typeid(cryptoCardTransactionManagerFactory).name());
    }

    return std::unique_ptr<SymmetricCryptoSecuritySettingAdapter>(
        new SymmetricCryptoSecuritySettingAdapter(
            std::dynamic_pointer_cast<
                SymmetricCryptoCardTransactionManagerFactorySpi>(
                cryptoCardTransactionManagerFactory)));
}

std::unique_ptr<AsymmetricCryptoSecuritySetting>
CalypsoCardApiFactoryAdapter::createAsymmetricCryptoSecuritySetting(
    const std::shared_ptr<AsymmetricCryptoCardTransactionManagerFactory>&
        cryptoCardTransactionManagerFactory)
{
    Assert::getInstance().notNull(
        cryptoCardTransactionManagerFactory,
        "cryptoCardTransactionManagerFactory");

    const auto asymmetric = std::dynamic_pointer_cast<
        AsymmetricCryptoCardTransactionManagerFactorySpi>(
        cryptoCardTransactionManagerFactory);
    if (asymmetric == nullptr) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'factory' to")
            + "AsymmetricCryptoCardTransactionManagerFactorySpi. Actual type: "
            + +typeid(cryptoCardTransactionManagerFactory).name());
    }

    return std::unique_ptr<AsymmetricCryptoSecuritySettingAdapter>(
        new AsymmetricCryptoSecuritySettingAdapter(
            std::dynamic_pointer_cast<
                AsymmetricCryptoCardTransactionManagerFactorySpi>(
                cryptoCardTransactionManagerFactory)));
}

std::unique_ptr<FreeTransactionManager>
CalypsoCardApiFactoryAdapter::createFreeTransactionManager(
    const std::shared_ptr<CardReader>& cardReader,
    const std::shared_ptr<CalypsoCard>& card)
{
    Assert::getInstance()
        .notNull(cardReader, MSG_CARD_READER)
        .notNull(card, MSG_CARD);

    const auto proxyReaderApi
        = std::dynamic_pointer_cast<ProxyReaderApi>(cardReader);
    if (!proxyReaderApi) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'cardReader' to ProxyReaderApi. Actual ")
            + "type: " + typeid(cardReader).name());
    }

    const auto calypsoCardAdapter
        = std::dynamic_pointer_cast<CalypsoCardAdapter>(card);
    if (!calypsoCardAdapter) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'card' to CalypsoCardAdapter. Actual ")
            + "type: " + typeid(card).name());
    }

    if (card->getProductType() == CalypsoCard::ProductType::UNKNOWN) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE);
    }

    return std::unique_ptr<FreeTransactionManagerAdapter>(
        new FreeTransactionManagerAdapter(proxyReaderApi, calypsoCardAdapter));
}

std::unique_ptr<SecureRegularModeTransactionManager>
CalypsoCardApiFactoryAdapter::createSecureRegularModeTransactionManager(
    const std::shared_ptr<CardReader>& cardReader,
    const std::shared_ptr<CalypsoCard>& card,
    const std::shared_ptr<SymmetricCryptoSecuritySetting>& securitySetting)
{
    Assert::getInstance()
        .notNull(cardReader, MSG_CARD_READER)
        .notNull(card, MSG_CARD)
        .notNull(securitySetting, MSG_SECURITY_SETTING);

    const auto proxyReaderApi
        = std::dynamic_pointer_cast<ProxyReaderApi>(cardReader);
    if (!proxyReaderApi) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'cardReader' to ProxyReaderApi. Actual ")
            + "type: " + typeid(cardReader).name());
    }

    const auto calypsoCardAdapter
        = std::dynamic_pointer_cast<CalypsoCardAdapter>(card);
    if (!calypsoCardAdapter) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'card' to CalypsoCardAdapter. Actual ")
            + "type: " + typeid(card).name());
    }

    const auto symmetricCryptoSecuritySettingAdapter
        = std::dynamic_pointer_cast<SymmetricCryptoSecuritySettingAdapter>(
            securitySetting);
    if (!symmetricCryptoSecuritySettingAdapter) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'securitySetting' to ")
            + "SymmetricCryptoSecuritySettingAdapter. Actual type: "
            + typeid(securitySetting).name());
    }

    if (card->getProductType() == CalypsoCard::ProductType::UNKNOWN) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE);
    }

    return std::unique_ptr<SecureRegularModeTransactionManagerAdapter>(
        new SecureRegularModeTransactionManagerAdapter(
            std::dynamic_pointer_cast<ProxyReaderApi>(cardReader),
            std::dynamic_pointer_cast<CalypsoCardAdapter>(card),
            std::dynamic_pointer_cast<SymmetricCryptoSecuritySettingAdapter>(
                securitySetting)));
}

std::unique_ptr<SecureExtendedModeTransactionManager>
CalypsoCardApiFactoryAdapter::createSecureExtendedModeTransactionManager(
    const std::shared_ptr<CardReader>& cardReader,
    const std::shared_ptr<CalypsoCard>& card,
    const std::shared_ptr<SymmetricCryptoSecuritySetting>& securitySetting)
{
    Assert::getInstance()
        .notNull(cardReader, MSG_CARD_READER)
        .notNull(card, MSG_CARD)
        .notNull(securitySetting, MSG_SECURITY_SETTING);

    const auto proxyReaderApi
        = std::dynamic_pointer_cast<ProxyReaderApi>(cardReader);
    if (!proxyReaderApi) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'cardReader' to ProxyReaderApi. Actual ")
            + "type: " + typeid(cardReader).name());
    }

    const auto calypsoCardAdapter
        = std::dynamic_pointer_cast<CalypsoCardAdapter>(card);
    if (!calypsoCardAdapter) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'card' to CalypsoCardAdapter. Actual ")
            + "type: " + typeid(card).name());
    }

    const auto symmetricCryptoSecuritySettingAdapter
        = std::dynamic_pointer_cast<SymmetricCryptoSecuritySettingAdapter>(
            securitySetting);
    if (!symmetricCryptoSecuritySettingAdapter) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'securitySetting' to ")
            + "SymmetricCryptoSecuritySettingAdapter. Actual type: "
            + typeid(securitySetting).name());
    }

    if (card->getProductType() == CalypsoCard::ProductType::UNKNOWN) {
        throw IllegalArgumentException(
            MSG_THE_PROVIDED_CARD_HAS_AN_UNDEFINED_PRODUCT_TYPE);
    }

    return std::unique_ptr<SecureExtendedModeTransactionManagerAdapter>(
        new SecureExtendedModeTransactionManagerAdapter(
            std::dynamic_pointer_cast<ProxyReaderApi>(cardReader),
            std::dynamic_pointer_cast<CalypsoCardAdapter>(card),
            std::dynamic_pointer_cast<SymmetricCryptoSecuritySettingAdapter>(
                securitySetting)));
}

std::unique_ptr<SecurePkiModeTransactionManager>
CalypsoCardApiFactoryAdapter::createSecurePkiModeTransactionManager(
    const std::shared_ptr<CardReader>& cardReader,
    const std::shared_ptr<CalypsoCard>& card,
    const std::shared_ptr<AsymmetricCryptoSecuritySetting>& securitySetting)
{
    Assert::getInstance()
        .notNull(cardReader, MSG_CARD_READER)
        .notNull(card, MSG_CARD)
        .notNull(securitySetting, MSG_SECURITY_SETTING);

    const auto proxyReaderApi
        = std::dynamic_pointer_cast<ProxyReaderApi>(cardReader);
    if (!proxyReaderApi) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'cardReader' to ProxyReaderApi. Actual ")
            + "type: " + typeid(cardReader).name());
    }

    const auto calypsoCardAdapter
        = std::dynamic_pointer_cast<CalypsoCardAdapter>(card);
    if (!calypsoCardAdapter) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'card' to CalypsoCardAdapter. Actual ")
            + "type: " + typeid(card).name());
    }

    const auto asymmetricCryptoSecuritySettingAdapter
        = std::dynamic_pointer_cast<AsymmetricCryptoSecuritySettingAdapter>(
            securitySetting);
    if (!asymmetricCryptoSecuritySettingAdapter) {
        throw IllegalArgumentException(
            std::string("Cannot cast 'securitySetting' to ")
            + "AsymmetricCryptoSecuritySettingAdapter. Actual type: "
            + typeid(securitySetting).name());
    }

    return std::unique_ptr<SecurePkiModeTransactionManagerAdapter>(
        new SecurePkiModeTransactionManagerAdapter(
            std::dynamic_pointer_cast<ProxyReaderApi>(cardReader),
            std::dynamic_pointer_cast<CalypsoCardAdapter>(card),
            std::dynamic_pointer_cast<AsymmetricCryptoSecuritySettingAdapter>(
                securitySetting)));
}

std::shared_ptr<SearchCommandData>
CalypsoCardApiFactoryAdapter::createSearchCommandData()
{
    return std::make_shared<DtoAdapters::SearchCommandDataAdapter>();
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
