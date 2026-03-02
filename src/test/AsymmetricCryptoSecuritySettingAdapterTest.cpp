/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/AsymmetricCryptoSecuritySettingAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/StringUtils.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/card/CalypsoCard.hpp"
#include "keypop/calypso/card/transaction/InvalidCertificateException.hpp"
#include "keypop/calypso/crypto/asymmetric/certificate/CertificateValidationException.hpp"

#include "mock/AsymmetricCryptoCardTransactionManagerFactorySpiMock.hpp"
#include "mock/CaCertificateContentSpiMock.hpp"
#include "mock/CaCertificateParserMock.hpp"
#include "mock/CaCertificateParser_CaCertificateParserSpiMock.hpp"
#include "mock/CaCertificate_CaCertificateContentSpiMock.hpp"
#include "mock/CaCertificate_CaCertificateSpi_CaCertificateContentSpiMock.hpp"
#include "mock/CardCertificateParserMock.hpp"
#include "mock/CardCertificateParser_CardCertificateParserSpiMock.hpp"
#include "mock/PcaCertificate_CaCertificateContentSpiMock.hpp"
#include "mock/PcaCertificate_PcaCertificateSpi_CaCertificateContentSpiMock.hpp"

using keyple::card::calypso::AsymmetricCryptoSecuritySettingAdapter;
using keyple::card::calypso::CalypsoCardAdapter;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::StringUtils;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::card::CalypsoCard;
using keypop::calypso::card::transaction::InvalidCertificateException;
using keypop::calypso::crypto::asymmetric::certificate::
    CertificateValidationException;

using testing::Return;
using testing::ReturnRef;
using testing::Throw;

static const std::vector<std::uint8_t> PUBLIC_KEY_REFERENCE_1
    = HexUtil::toByteArray(
        "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCC");
static const std::vector<std::uint8_t> PUBLIC_KEY_REFERENCE_2
    = HexUtil::toByteArray(
        "112233445566778899AABBCCDDEEFF00112233445566778899AABBCC00");
static const std::uint8_t CA_CERTIFICATE_TYPE = 0x90;
static const std::uint8_t CARD_CERTIFICATE_TYPE = 0x91;
static std::shared_ptr<AsymmetricCryptoCardTransactionManagerFactorySpi>
    asymmetricCryptoCardTransactionManagerFactorySpi
    = std::make_shared<AsymmetricCryptoCardTransactionManagerFactorySpiMock>();
std::shared_ptr<CalypsoCardAdapter> calypsoCardAdapter;

class AsymmetricCryptoSecuritySettingAdapterTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
        asymmetricCryptoSecuritySettingAdapter
            = std::make_shared<AsymmetricCryptoSecuritySettingAdapter>(
                asymmetricCryptoCardTransactionManagerFactorySpi);
    }

    void
    TearDown() override
    {
        asymmetricCryptoSecuritySettingAdapter.reset();
    }

    std::shared_ptr<AsymmetricCryptoSecuritySettingAdapter>
        asymmetricCryptoSecuritySettingAdapter;
};

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    getCryptoCardTransactionManagerFactorySpi_shouldReturnFactory)
{
    ASSERT_EQ(
        asymmetricCryptoSecuritySettingAdapter
            ->getCryptoCardTransactionManagerFactorySpi(),
        asymmetricCryptoCardTransactionManagerFactorySpi);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addPcaCertificate_whenValidCertificate_shouldFillCertificateStore)
{
    /* Mock PcaCertificateSpi and necessary methods */
    auto mockPcaCert(
        std::make_shared<
            PcaCertificate_PcaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockPcaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    /* Mocking methods of PcaCertificateSpi */
    EXPECT_CALL(*mockPcaCert, checkCertificateAndGetContent())
        .WillRepeatedly(Return(mockPcaCertContent));
    EXPECT_CALL(*mockPcaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));

    /* Run the method being tested */
    asymmetricCryptoSecuritySettingAdapter->addPcaCertificate(mockPcaCert);

    ASSERT_EQ(
        asymmetricCryptoSecuritySettingAdapter->getCaCertificate(
            PUBLIC_KEY_REFERENCE_1),
        mockPcaCertContent);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addPcaCertificate_whenInvalidInstance_shouldThrowIAE)
{
    /* Mock PcaCertificateSpi and necessary methods */
    auto mockPcaCert(
        std::make_shared<PcaCertificate_CaCertificateContentSpiMock>());

    /* Run the method being tested */
    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addPcaCertificate(mockPcaCert),
        IllegalArgumentException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addPcaCertificate_whenInvalidCertificate_shouldThrowInvalidCertificateException)  // NOLINT
{
    /* Mock PcaCertificateSpi and necessary methods */
    auto mockPcaCert(
        std::make_shared<
            PcaCertificate_PcaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockPcaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    /* Mocking methods of PcaCertificateSpi */
    EXPECT_CALL(*mockPcaCert, checkCertificateAndGetContent())
        .WillRepeatedly(Throw(CertificateValidationException("")));
    EXPECT_CALL(*mockPcaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));

    /* Run the method being tested */
    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addPcaCertificate(mockPcaCert),
        InvalidCertificateException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addPcaCertificate_whenValidCertificateAlreadyRegistered_shouldThrowISE)
{
    /* Mock PcaCertificateSpi and necessary methods */
    auto mockPcaCert(
        std::make_shared<
            PcaCertificate_PcaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockPcaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    /* Mocking methods of PcaCertificateSpi */
    EXPECT_CALL(*mockPcaCert, checkCertificateAndGetContent())
        .WillRepeatedly(Return(mockPcaCertContent));
    EXPECT_CALL(*mockPcaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));

    /* Run twice the method being tested */
    asymmetricCryptoSecuritySettingAdapter->addPcaCertificate(mockPcaCert);
    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addPcaCertificate(mockPcaCert),
        IllegalStateException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCaCertificate_whenValidCertificate_shouldFillCertificateStore)
{
    /* Mock PcaCertificateSpi and necessary methods */
    auto mockPcaCert(
        std::make_shared<
            PcaCertificate_PcaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockPcaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    EXPECT_CALL(*mockPcaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));
    EXPECT_CALL(*mockPcaCert, checkCertificateAndGetContent())
        .WillRepeatedly(Return(mockPcaCertContent));

    asymmetricCryptoSecuritySettingAdapter->addPcaCertificate(mockPcaCert);

    /* Mock CaCertificateSpi and necessary methods */
    auto mockCaCert(
        std::make_shared<
            CaCertificate_CaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockCaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    EXPECT_CALL(
        *mockCaCert,
        checkCertificateAndGetContent(
            std::dynamic_pointer_cast<CaCertificateContentSpi>(mockPcaCert)))
        .WillRepeatedly(Return(mockCaCertContent));
    EXPECT_CALL(*mockCaCert, getIssuerPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));
    EXPECT_CALL(*mockCaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_2));
    EXPECT_CALL(
        *mockCaCert,
        checkCertificateAndGetContent(
            std::dynamic_pointer_cast<CaCertificateContentSpi>(
                mockPcaCertContent)))
        .WillRepeatedly(Return(mockCaCertContent));

    /* Run the method being tested */
    asymmetricCryptoSecuritySettingAdapter->addCaCertificate(mockCaCert);

    ASSERT_EQ(
        asymmetricCryptoSecuritySettingAdapter->getCaCertificate(
            PUBLIC_KEY_REFERENCE_2),
        mockCaCertContent);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCaCertificate_whenInvalidInstance_shouldThrowIAE)
{
    /* Mock CaCertificateSpi and necessary methods */
    auto mockCaCert(
        std::make_shared<CaCertificate_CaCertificateContentSpiMock>());

    /* Run the method being tested */
    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addCaCertificate(mockCaCert),
        IllegalArgumentException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCaCertificate_whenIssuerIsUnknown_shouldThrowISE)
{
    /* Mock PcaCertificateSpi and necessary methods */
    auto mockPcaCert(
        std::make_shared<
            PcaCertificate_PcaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockPcaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    EXPECT_CALL(*mockPcaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));
    EXPECT_CALL(*mockPcaCert, checkCertificateAndGetContent())
        .WillRepeatedly(Return(mockPcaCertContent));

    /* Mock CaCertificateSpi and necessary methods */
    auto mockCaCert(
        std::make_shared<
            CaCertificate_CaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockCaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    EXPECT_CALL(
        *mockCaCert,
        checkCertificateAndGetContent(
            std::dynamic_pointer_cast<CaCertificateContentSpi>(mockPcaCert)))
        .WillRepeatedly(Return(mockCaCertContent));
    EXPECT_CALL(*mockCaCert, getIssuerPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));
    EXPECT_CALL(*mockCaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_2));
    EXPECT_CALL(
        *mockCaCert,
        checkCertificateAndGetContent(
            std::dynamic_pointer_cast<CaCertificateContentSpi>(
                mockPcaCertContent)))
        .WillRepeatedly(Return(mockCaCertContent));

    /* Run the method being tested */
    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addCaCertificate(mockCaCert),
        IllegalStateException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCaCertificate_whenInvalidCertificate_shouldThrowInvalidCertificateException)  // NOLINT
{
    /* Mock PcaCertificateSpi and necessary methods */
    auto mockPcaCert(
        std::make_shared<
            PcaCertificate_PcaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockPcaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    EXPECT_CALL(*mockPcaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));
    EXPECT_CALL(*mockPcaCert, checkCertificateAndGetContent())
        .WillRepeatedly(Return(mockPcaCertContent));

    asymmetricCryptoSecuritySettingAdapter->addPcaCertificate(mockPcaCert);

    /* Mock CaCertificateSpi and necessary methods */
    auto mockCaCert(
        std::make_shared<
            CaCertificate_CaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockCaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    EXPECT_CALL(
        *mockCaCert,
        checkCertificateAndGetContent(
            std::dynamic_pointer_cast<CaCertificateContentSpi>(mockPcaCert)))
        .WillRepeatedly(Return(mockCaCertContent));
    EXPECT_CALL(*mockCaCert, getIssuerPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));
    EXPECT_CALL(*mockCaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_2));
    EXPECT_CALL(
        *mockCaCert,
        checkCertificateAndGetContent(
            std::dynamic_pointer_cast<CaCertificateContentSpi>(
                mockPcaCertContent)))
        .WillRepeatedly(Throw(CertificateValidationException("")));

    /* Run the method being tested */
    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addCaCertificate(mockCaCert),
        InvalidCertificateException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCaCertificate_whenValidCertificateAlreadyRegistered_shouldThrowISE)
{
    /* Mock PcaCertificateSpi and necessary methods */
    auto mockPcaCert(
        std::make_shared<
            PcaCertificate_PcaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockPcaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    EXPECT_CALL(*mockPcaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));
    EXPECT_CALL(*mockPcaCert, checkCertificateAndGetContent())
        .WillRepeatedly(Return(mockPcaCertContent));

    asymmetricCryptoSecuritySettingAdapter->addPcaCertificate(mockPcaCert);

    /* Mock CaCertificateSpi and necessary methods */
    auto mockCaCert(
        std::make_shared<
            CaCertificate_CaCertificateSpi_CaCertificateContentSpiMock>());
    auto mockCaCertContent(std::make_shared<CaCertificateContentSpiMock>());

    EXPECT_CALL(
        *mockCaCert,
        checkCertificateAndGetContent(
            std::dynamic_pointer_cast<CaCertificateContentSpi>(mockPcaCert)))
        .WillRepeatedly(Return(mockCaCertContent));
    EXPECT_CALL(*mockCaCert, getIssuerPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_1));
    EXPECT_CALL(*mockCaCertContent, getPublicKeyReference())
        .WillRepeatedly(ReturnRef(PUBLIC_KEY_REFERENCE_2));
    EXPECT_CALL(
        *mockCaCert,
        checkCertificateAndGetContent(
            std::dynamic_pointer_cast<CaCertificateContentSpi>(
                mockPcaCertContent)))
        .WillRepeatedly(Return(mockCaCertContent));

    /* Run twice the method being tested */
    asymmetricCryptoSecuritySettingAdapter->addCaCertificate(mockCaCert);
    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addCaCertificate(mockCaCert),
        IllegalStateException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCaCertificateParser_whenValidParser_shouldFillParserStore)
{
    /* Mocking methods of CaCertificateParserSpi */
    auto mockCaCertParser(
        std::make_shared<CaCertificateParser_CaCertificateParserSpiMock>());

    EXPECT_CALL(*mockCaCertParser, getCertificateType())
        .WillRepeatedly(Return(CA_CERTIFICATE_TYPE));

    asymmetricCryptoSecuritySettingAdapter->addCaCertificateParser(
        mockCaCertParser);

    ASSERT_EQ(
        asymmetricCryptoSecuritySettingAdapter->getCaCertificateParser(
            CA_CERTIFICATE_TYPE),
        mockCaCertParser);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCaCertificateParser_whenInvalidParser_shouldIAE)
{
    /* Mocking methods of CaCertificateParser */
    auto mockCaCertParser(std::make_shared<CaCertificateParserMock>());

    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addCaCertificateParser(
            mockCaCertParser),
        IllegalArgumentException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCaCertificateParser_whenValidParserAlreadyRegistered_shouldThrowISE)
{
    /* Mocking methods of CaCertificateParserSpi */
    auto mockCaCertParser(
        std::make_shared<CaCertificateParser_CaCertificateParserSpiMock>());

    EXPECT_CALL(*mockCaCertParser, getCertificateType())
        .WillRepeatedly(Return(CA_CERTIFICATE_TYPE));

    asymmetricCryptoSecuritySettingAdapter->addCaCertificateParser(
        mockCaCertParser);

    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addCaCertificateParser(
            mockCaCertParser),
        IllegalStateException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCardCertificateParser_whenValidParser_shouldFillParserStore)
{
    /* Mocking methods of CardCertificateParserSpi */
    auto mockCardCertParser(
        std::make_shared<CardCertificateParser_CardCertificateParserSpiMock>());

    EXPECT_CALL(*mockCardCertParser, getCertificateType())
        .WillRepeatedly(Return(CARD_CERTIFICATE_TYPE));

    asymmetricCryptoSecuritySettingAdapter->addCardCertificateParser(
        mockCardCertParser);

    ASSERT_EQ(
        asymmetricCryptoSecuritySettingAdapter->getCardCertificateParser(
            CARD_CERTIFICATE_TYPE),
        mockCardCertParser);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCardCertificateParser_whenInvalidParser_shouldIAE)
{
    /* Mocking methods of CardCertificateParser */
    auto mockCardCertParser(std::make_shared<CardCertificateParserMock>());

    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addCardCertificateParser(
            mockCardCertParser),
        IllegalArgumentException);
}

TEST_F(
    AsymmetricCryptoSecuritySettingAdapterTest,
    addCardCertificateParser_whenValidParserAlreadyRegistered_shouldThrowISE)
{
    /* Mocking methods of CardCertificateParserSpi */
    auto mockCardCertParser(
        std::make_shared<CardCertificateParser_CardCertificateParserSpiMock>());

    EXPECT_CALL(*mockCardCertParser, getCertificateType())
        .WillRepeatedly(Return(CARD_CERTIFICATE_TYPE));

    asymmetricCryptoSecuritySettingAdapter->addCardCertificateParser(
        mockCardCertParser);

    EXPECT_THROW(
        asymmetricCryptoSecuritySettingAdapter->addCardCertificateParser(
            mockCardCertParser),
        IllegalStateException);
}
