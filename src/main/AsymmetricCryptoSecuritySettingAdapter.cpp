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

#include "keyple/card/calypso/AsymmetricCryptoSecuritySettingAdapter.hpp"

#include <memory>
#include <string>
#include <typeinfo>
#include <vector>

#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/KeypleAssert.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/transaction/CryptoException.hpp"
#include "keypop/calypso/card/transaction/InvalidCertificateException.hpp"
#include "keypop/calypso/crypto/asymmetric/AsymmetricCryptoException.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/CertificateValidationException.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/CaCertificateSpi.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/spi/PcaCertificateSpi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::Assert;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::transaction::CryptoException;
using keypop::calypso::card::transaction::InvalidCertificateException;
using keypop::calypso::crypto::asymmetric::AsymmetricCryptoException;
using keypop::calypso::crypto::asymmetric::certificate::
    CertificateValidationException;
using keypop::calypso::crypto::asymmetric::certificate::spi::CaCertificateSpi;
using keypop::calypso::crypto::asymmetric::certificate::spi::PcaCertificateSpi;

const std::string
    AsymmetricCryptoSecuritySettingAdapter::MSG_INVALID_CERTIFICATE
    = "Invalid certificate";
const std::string
    AsymmetricCryptoSecuritySettingAdapter ::MSG_FAILED_TO_CHECK_THE_CERTIFICATE
    = "Failed to check the certificate";
const std::string AsymmetricCryptoSecuritySettingAdapter ::
    MSG_A_CERTIFICATE_IS_ALREADY_REGISTERED_FOR_THE_PROVIDED_PUBLIC_KEY_REFERENCE  // NOLINT
    = "A certificate is already registered for the provided public key "
      "reference: ";
const std::string AsymmetricCryptoSecuritySettingAdapter ::
    MSG_THE_ISSUER_CERTIFICATE_IS_NOT_REGISTERED
    = "The issuer certificate is not registered: ";
const std::string AsymmetricCryptoSecuritySettingAdapter ::
    MSG_A_PARSER_IS_ALREADY_REGISTERED_FOR_THE_CERTIFICATE_TYPE
    = "A parser is already registered for the certificate type ";

AsymmetricCryptoSecuritySettingAdapter::AsymmetricCryptoSecuritySettingAdapter(
    std::shared_ptr<AsymmetricCryptoCardTransactionManagerFactorySpi>
        cryptoCardTransactionManagerFactorySpi)
: mCryptoCardTransactionManagerFactorySpi(
      cryptoCardTransactionManagerFactorySpi)
{
}

std::shared_ptr<AsymmetricCryptoCardTransactionManagerFactorySpi>
AsymmetricCryptoSecuritySettingAdapter ::
    getCryptoCardTransactionManagerFactorySpi() const
{
    return mCryptoCardTransactionManagerFactorySpi;
}

AsymmetricCryptoSecuritySetting&
AsymmetricCryptoSecuritySettingAdapter::addPcaCertificate(
    std::shared_ptr<PcaCertificate> pcaCertificate)
{
    Assert::getInstance().notNull(pcaCertificate, "pcaCertificate");

    const auto pcaCertificateSpi(
        std::dynamic_pointer_cast<PcaCertificateSpi>(pcaCertificate));
    if (!pcaCertificateSpi) {
        std::string certificateName = "null";
        if (pcaCertificate.get()) {
            const auto& r = *pcaCertificate.get();
            certificateName = typeid(r).name();
        }

        throw IllegalArgumentException(
            std::string("Cannot cast 'pcaCertificate' to PcaCertificateSpi.")
            + " Actual type: " + certificateName);
    }

    /* Check certificate and get content */
    std::shared_ptr<CaCertificateContentSpi> certificateContent;
    try {
        certificateContent = pcaCertificateSpi->checkCertificateAndGetContent();

    } catch (const CertificateValidationException& e) {
        throw InvalidCertificateException(MSG_INVALID_CERTIFICATE, e);

    } catch (const AsymmetricCryptoException& e) {
        throw CryptoException(MSG_FAILED_TO_CHECK_THE_CERTIFICATE, e);
    }

    // Save the certificate content into the store
    const std::string pcaKeyRef(
        HexUtil::toHex(certificateContent->getPublicKeyReference()));
    if (mCaCertificates.count(pcaKeyRef)) {
        throw IllegalStateException(
            MSG_A_CERTIFICATE_IS_ALREADY_REGISTERED_FOR_THE_PROVIDED_PUBLIC_KEY_REFERENCE  // NOLINT
            + pcaKeyRef);
    }
    mCaCertificates.insert({pcaKeyRef, certificateContent});

    return *this;
}

AsymmetricCryptoSecuritySetting&
AsymmetricCryptoSecuritySettingAdapter::addCaCertificate(
    std::shared_ptr<CaCertificate> caCertificate)
{
    Assert::getInstance().notNull(caCertificate, "caCertificate");

    const auto caCertificateSpi(
        std::dynamic_pointer_cast<CaCertificateSpi>(caCertificate));
    if (!caCertificateSpi) {
        std::string certificateName = "null";
        if (caCertificateSpi.get()) {
            const auto& r = *caCertificateSpi.get();
            certificateName = typeid(r).name();
        }

        throw IllegalArgumentException(
            "Cannot cast 'caCertificate' to CaCertificateSpi. Actual type: "
            + certificateName);
    }

    /* Get the issuer public key reference */
    const std::string issuerKeyRef
        = HexUtil::toHex(caCertificateSpi->getIssuerPublicKeyReference());

    /* Search the issuer certificate */
    std::shared_ptr<CaCertificateContentSpi> issuerCertificateContent
        = mCaCertificates.count(issuerKeyRef) ? mCaCertificates[issuerKeyRef]
                                              : nullptr;
    if (issuerCertificateContent == nullptr) {
        throw IllegalStateException(
            MSG_THE_ISSUER_CERTIFICATE_IS_NOT_REGISTERED + issuerKeyRef);
    }

    /* Check the CA certificate using the issuer's certificate content */
    std::shared_ptr<CaCertificateContentSpi> caCertificateContent;
    try {
        caCertificateContent = caCertificateSpi->checkCertificateAndGetContent(
            issuerCertificateContent);

    } catch (const CertificateValidationException& e) {
        throw InvalidCertificateException(MSG_INVALID_CERTIFICATE, e);

    } catch (const AsymmetricCryptoException& e) {
        throw CryptoException(MSG_FAILED_TO_CHECK_THE_CERTIFICATE, e);
    }

    /* Save the certificate content into the store */
    const std::string caKeyRef
        = HexUtil::toHex(caCertificateContent->getPublicKeyReference());
    if (mCaCertificates.count(caKeyRef)) {
        throw IllegalStateException(
            MSG_A_CERTIFICATE_IS_ALREADY_REGISTERED_FOR_THE_PROVIDED_PUBLIC_KEY_REFERENCE  // NOLINT
            + caKeyRef);
    }

    mCaCertificates.insert({caKeyRef, caCertificateContent});

    return *this;
}

AsymmetricCryptoSecuritySetting&
AsymmetricCryptoSecuritySettingAdapter::addCaCertificateParser(
    std::shared_ptr<CaCertificateParser> caCertificateParser)
{
    Assert::getInstance().notNull(caCertificateParser, "caCertificateParser");

    auto caCertificateParserSpi(
        std::dynamic_pointer_cast<CaCertificateParserSpi>(caCertificateParser));
    if (!caCertificateParserSpi) {
        std::string certificateName = "null";
        if (caCertificateParserSpi.get()) {
            const auto& r = *caCertificateParserSpi.get();
            certificateName = typeid(r).name();
        }

        throw IllegalArgumentException(
            std::string("Cannot cast 'caCertificateParser' to ")
            + "CaCertificateParserSpi. Actual type: " + certificateName);
    }

    /* Save the parser into the store */
    const uint8_t certificateType
        = caCertificateParserSpi->getCertificateType();
    if (mCaCertificateParsers.count(certificateType)) {
        throw IllegalStateException(
            MSG_A_PARSER_IS_ALREADY_REGISTERED_FOR_THE_CERTIFICATE_TYPE
            + HexUtil::toHex(certificateType));
    }

    mCaCertificateParsers.insert({certificateType, caCertificateParserSpi});

    return *this;
}

AsymmetricCryptoSecuritySetting&
AsymmetricCryptoSecuritySettingAdapter::addCardCertificateParser(
    std::shared_ptr<CardCertificateParser> cardCertificateParser)
{
    Assert::getInstance().notNull(
        cardCertificateParser, "cardCertificateParser");

    auto cardCertificateParserSpi(
        std::dynamic_pointer_cast<CardCertificateParserSpi>(
            cardCertificateParser));
    if (!cardCertificateParserSpi) {
        std::string certificateName = "null";
        if (cardCertificateParserSpi.get()) {
            const auto& r = *cardCertificateParserSpi.get();
            certificateName = typeid(r).name();
        }

        throw IllegalArgumentException(
            std::string("Cannot cast 'cardCertificateParser' to ")
            + "CardCertificateParserSpi. Actual type: " + certificateName);
    }

    /* Save the parser into the store */
    const std::uint8_t certificateType
        = cardCertificateParserSpi->getCertificateType();
    if (mCardCertificateParsers.count(certificateType)) {
        throw IllegalStateException(
            MSG_A_PARSER_IS_ALREADY_REGISTERED_FOR_THE_CERTIFICATE_TYPE
            + HexUtil::toHex(certificateType));
    }

    mCardCertificateParsers.insert({certificateType, cardCertificateParserSpi});

    return *this;
}

std::shared_ptr<CaCertificateContentSpi>
AsymmetricCryptoSecuritySettingAdapter::getCaCertificate(
    const std::vector<std::uint8_t>& publicKeyReference)
{
    const std::string ref = HexUtil::toHex(publicKeyReference);
    return mCaCertificates.count(ref) ? mCaCertificates[ref] : nullptr;
}

std::shared_ptr<CaCertificateParserSpi>
AsymmetricCryptoSecuritySettingAdapter::getCaCertificateParser(
    std::uint8_t certificateType)
{
    return mCaCertificateParsers.count(certificateType)
               ? mCaCertificateParsers[certificateType]
               : nullptr;
}

std::shared_ptr<CardCertificateParserSpi>
AsymmetricCryptoSecuritySettingAdapter::getCardCertificateParser(
    std::uint8_t certificateType)
{
    return mCardCertificateParsers.count(certificateType)
               ? mCardCertificateParsers[certificateType]
               : nullptr;
}

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
