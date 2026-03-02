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

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "keypop/calypso/card/transaction/AsymmetricCryptoSecuritySetting.hpp"
#include "keypop/calypso/card/transaction/spi/CaCertificate.hpp"
#include "keypop/calypso/card/transaction/spi/CaCertificateParser.hpp"
#include "keypop/calypso/card/transaction/spi/CardCertificateParser.hpp"
#include "keypop/calypso/card/transaction/spi/PcaCertificate.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CaCertificateContentSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CaCertificateParserSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CardCertificateParserSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/transaction/spi/AsymmetricCryptoCardTransactionManagerFactorySpi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::transaction::AsymmetricCryptoSecuritySetting;
using keypop::calypso::card::transaction::spi::CaCertificate;
using keypop::calypso::card::transaction::spi::CaCertificateParser;
using keypop::calypso::card::transaction::spi::CardCertificateParser;
using keypop::calypso::card::transaction::spi::PcaCertificate;
using keypop::calypso::crypto::asymmetric::certificate::spi ::
    CaCertificateContentSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi ::
    CaCertificateParserSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi ::
    CardCertificateParserSpi;
using keypop::calypso::crypto::asymmetric::transaction::spi ::
    AsymmetricCryptoCardTransactionManagerFactorySpi;

/**
 * Adapter of AsymmetricCryptoSecuritySetting.
 *
 * @since 3.1.0
 */
class AsymmetricCryptoSecuritySettingAdapter final
: public AsymmetricCryptoSecuritySetting {
public:
    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    AsymmetricCryptoSecuritySetting&
    addPcaCertificate(std::shared_ptr<PcaCertificate> pcaCertificate) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    AsymmetricCryptoSecuritySetting&
    addCaCertificate(std::shared_ptr<CaCertificate> caCertificate) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    AsymmetricCryptoSecuritySetting& addCaCertificateParser(
        std::shared_ptr<CaCertificateParser> caCertificateParser) override;

    /**
     * {@inheritDoc}
     *
     * @since 3.1.0
     */
    AsymmetricCryptoSecuritySetting& addCardCertificateParser(
        std::shared_ptr<CardCertificateParser> cardCertificateParser) override;

    /**
     * Retrieves the CA certificate from the provided public key reference.
     *
     * @param publicKeyReference The public key reference as a 29-byte byte
     * array.
     * @return null if no certificate matches the provided reference.
     * @since 3.1.0
     */
    std::shared_ptr<CaCertificateContentSpi>
    getCaCertificate(const std::vector<std::uint8_t>& publicKeyReference);

    /**
     * Retrieves the CA certificate parser for the provided type.
     *
     * @param certificateType The type of certificate.
     * @return null if no CA certificate parser matches the provided type.
     * @since 3.1.0
     */
    std::shared_ptr<CaCertificateParserSpi>
    getCaCertificateParser(std::uint8_t certificateType);

    /**
     * Retrieves the card certificate parser for the provided type.
     *
     * @param certificateType The type of certificate.
     * @return null if no card certificate parser matches the provided type.
     * @since 3.1.0
     */
    std::shared_ptr<CardCertificateParserSpi>
    getCardCertificateParser(std::uint8_t certificateType);

    /**
     * Constructor.
     *
     * Note: private in Java.
     *
     * @param cryptoCardTransactionManagerFactorySpi The asymmetric transaction
     * manager factory.
     * @since 3.1.0
     */
    explicit AsymmetricCryptoSecuritySettingAdapter(
        std::shared_ptr<AsymmetricCryptoCardTransactionManagerFactorySpi>
            cryptoCardTransactionManagerFactorySpi);

    /**
     * @return The AsymmetricCryptoCardTransactionManagerFactorySpi.
     * @since 3.1.0
     * @note Private in Java.
     */
    std::shared_ptr<AsymmetricCryptoCardTransactionManagerFactorySpi>
    getCryptoCardTransactionManagerFactorySpi() const;

private:
    /**
     *
     */
    static const std::string MSG_INVALID_CERTIFICATE;
    static const std::string MSG_FAILED_TO_CHECK_THE_CERTIFICATE;
    static const std::string
        MSG_A_CERTIFICATE_IS_ALREADY_REGISTERED_FOR_THE_PROVIDED_PUBLIC_KEY_REFERENCE;  // NOLINT
    static const std::string MSG_THE_ISSUER_CERTIFICATE_IS_NOT_REGISTERED;
    static const std::string
        MSG_A_PARSER_IS_ALREADY_REGISTERED_FOR_THE_CERTIFICATE_TYPE;

    /**
     *
     */
    const std::shared_ptr<AsymmetricCryptoCardTransactionManagerFactorySpi>
        mCryptoCardTransactionManagerFactorySpi;

    /**
     *
     */
    std::map<const std::string, std::shared_ptr<CaCertificateContentSpi>>
        mCaCertificates;

    /**
     *
     */
    std::map<std::uint8_t, std::shared_ptr<CaCertificateParserSpi>>
        mCaCertificateParsers;

    /**
     *
     */
    std::map<std::uint8_t, std::shared_ptr<CardCertificateParserSpi>>
        mCardCertificateParsers;
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
