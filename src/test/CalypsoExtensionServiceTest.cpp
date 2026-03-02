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

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/card/calypso/CalypsoCardSelectionExtensionAdapter.hpp"
#include "keyple/card/calypso/CalypsoExtensionService.hpp"
#include "keyple/card/calypso/SymmetricCryptoSecuritySettingAdapter.hpp"
#include "keyple/card/generic/GenericCardSelectionExtension.hpp"
#include "keyple/core/common/CommonApiProperties.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keypop/calypso/card/transaction/SymmetricCryptoSecuritySetting.hpp"
#include "keypop/card/CardApiProperties.hpp"
#include "keypop/card/spi/CardSelectionExtensionSpi.hpp"
#include "keypop/reader/ReaderApiProperties.hpp"

#include "mock/CardSelectionResponseAdapterMock.hpp"
#include "mock/ReaderMock.hpp"
#include "mock/SymmetricCryptoCardTransactionManagerFactoryMock.hpp"
#include "mock/SymmetricCryptoCardTransactionManagerMock.hpp"

using keyple::card::calypso::CalypsoCardAdapter;
using keyple::card::calypso::CalypsoCardSelectionExtensionAdapter;
using keyple::card::calypso::CalypsoExtensionService;
using keyple::card::calypso::SymmetricCryptoSecuritySettingAdapter;
using keyple::card::generic::GenericCardSelectionExtension;
using keyple::core::common::CommonApiProperties_VERSION;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keypop::calypso::card::transaction::SymmetricCryptoSecuritySetting;
using keypop::card::CardApiProperties_VERSION;
using keypop::card::spi::CardSelectionExtensionSpi;
using keypop::reader::ReaderApiProperties_VERSION;

static const std::string POWER_ON_DATA
    = "3B8F8001805A0A010320031124B77FE7829000F7";
static const std::string SAM_C1_POWER_ON_DATA
    = "3B3F9600805A4880C120501711223344829000";
static const std::string SAM_F1_POWER_ON_DATA
    = "3B3F9600805A4880F120501711223344829000";

static std::shared_ptr<CalypsoExtensionService> service
    = CalypsoExtensionService::getInstance();
static std::shared_ptr<ReaderMock> reader;
static std::shared_ptr<CalypsoCardAdapter> calypsoCard;
static std::shared_ptr<SymmetricCryptoSecuritySetting> cardSecuritySetting;
static std::shared_ptr<SymmetricCryptoCardTransactionManagerFactoryMock>
    symmetricCryptoCardTransactionManagerFactory;
static std::shared_ptr<SymmetricCryptoCardTransactionManagerMock>
    symmetricCryptoCardTransactionManager;
static const std::vector<uint8_t> serial = {1, 2, 3, 4, 5, 6};

class CalypsoExtensionServiceTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
        reader = std::make_shared<ReaderMock>();
        symmetricCryptoCardTransactionManagerFactory = std::make_shared<
            SymmetricCryptoCardTransactionManagerFactoryMock>();
        symmetricCryptoCardTransactionManager
            = std::make_shared<SymmetricCryptoCardTransactionManagerMock>();
        calypsoCard = std::make_shared<CalypsoCardAdapter>();
        cardSecuritySetting
            = std::make_shared<SymmetricCryptoSecuritySettingAdapter>(nullptr);
    }

    void
    TearDown() override
    {
        reader.reset();
        symmetricCryptoCardTransactionManagerFactory.reset();
        symmetricCryptoCardTransactionManager.reset();
        calypsoCard.reset();
        cardSecuritySetting.reset();
    }
};

TEST_F(
    CalypsoExtensionServiceTest,
    getInstance_whenIsInvokedTwice_shouldReturnSameInstance)
{
    ASSERT_EQ(CalypsoExtensionService::getInstance(), service);
}

TEST_F(
    CalypsoExtensionServiceTest,
    getReaderApiVersion_whenInvoked_shouldReturn_ExpectedVersion)
{
    ASSERT_EQ(service->getReaderApiVersion(), ReaderApiProperties_VERSION);
}

TEST_F(
    CalypsoExtensionServiceTest, getCardApiVersion_shouldReturnExpectedVersion)
{
    ASSERT_EQ(service->getCardApiVersion(), CardApiProperties_VERSION);
}

TEST_F(
    CalypsoExtensionServiceTest,
    getCommonApiVersion_shouldReturnExpectedVersion)
{
    ASSERT_EQ(service->getCommonApiVersion(), CommonApiProperties_VERSION);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSearchCommandData_shouldReturnNewReference)
{
    const auto command(
        service->getCalypsoCardApiFactory()->createSearchCommandData());

    ASSERT_NE(command, nullptr);

    const auto command2(
        service->getCalypsoCardApiFactory()->createSearchCommandData());

    ASSERT_NE(command, command2);
}

TEST_F(
    CalypsoExtensionServiceTest, createCardSelection_shouldReturnNewReference)
{
    const auto selection(service->getCalypsoCardApiFactory()
                             ->createCalypsoCardSelectionExtension());

    ASSERT_NE(selection, nullptr);

    const auto selection2(service->getCalypsoCardApiFactory()
                              ->createCalypsoCardSelectionExtension());

    ASSERT_NE(selection, selection2);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createCardSelection_shouldReturnInstanceOfInternalSpi)
{
    const auto selection(service->getCalypsoCardApiFactory()
                             ->createCalypsoCardSelectionExtension());

    const auto cardExtension(
        dynamic_cast<CardSelectionExtensionSpi*>(selection.get()));

    ASSERT_NE(cardExtension, nullptr);

    const auto calypsoExtension(
        dynamic_cast<CalypsoCardSelectionExtensionAdapter*>(selection.get()));

    ASSERT_NE(calypsoExtension, nullptr);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createCardSecuritySetting_shouldReturnANewReference)
{
    const auto securitySetting(
        service->getCalypsoCardApiFactory()
            ->createSymmetricCryptoSecuritySetting(
                symmetricCryptoCardTransactionManagerFactory));
    ASSERT_NE(cardSecuritySetting, nullptr);

    const auto securitySetting2(
        service->getCalypsoCardApiFactory()
            ->createSymmetricCryptoSecuritySetting(
                symmetricCryptoCardTransactionManagerFactory));

    ASSERT_NE(securitySetting, securitySetting2);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createCardSecuritySetting_shouldReturnInstanceOfCardSecuritySettingAdapter)
{
    const auto securitySetting(
        service->getCalypsoCardApiFactory()
            ->createSymmetricCryptoSecuritySetting(
                symmetricCryptoCardTransactionManagerFactory));

    const auto adapter(
        dynamic_cast<SymmetricCryptoSecuritySettingAdapter*>(
            securitySetting.get()));

    ASSERT_NE(adapter, nullptr);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createFreeTransactionManager_whenInvokedWithNullReader_shouldThrowIAE)
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()->createFreeTransactionManager(
            nullptr, calypsoCard),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createFreeTransactionManager_whenInvokedWithNullCalypsoCard_shouldThrowIAE)
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()->createFreeTransactionManager(
            reader, nullptr),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createFreeTransactionManager_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()->createFreeTransactionManager(
            reader, calypsoCard),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createFreeTransactionManager_whenInvoked_shouldReturnANewReference)
{
    calypsoCard = std::make_shared<CalypsoCardAdapter>();
    calypsoCard->initialize(
        std::make_shared<CardSelectionResponseAdapterMock>(POWER_ON_DATA));

    auto cardTransaction(
        service->getCalypsoCardApiFactory()->createFreeTransactionManager(
            reader, calypsoCard));

    auto cardTransaction2(
        service->getCalypsoCardApiFactory()->createFreeTransactionManager(
            reader, calypsoCard));

    ASSERT_NE(cardTransaction, cardTransaction2);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSecureRegularModeTransactionManager_whenInvokedWithNullReader_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()
            ->createSecureRegularModeTransactionManager(
                nullptr, calypsoCard, cardSecuritySetting),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSecureRegularModeTransactionManager_whenInvokedWithNullCalypsoCard_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()
            ->createSecureRegularModeTransactionManager(
                reader, nullptr, cardSecuritySetting),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSecureRegularModeTransactionManager_whenInvokedWithNullCardSecuritySetting_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()
            ->createSecureRegularModeTransactionManager(
                reader, calypsoCard, nullptr),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSecureRegularModeTransactionManager_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()
            ->createSecureRegularModeTransactionManager(
                reader, calypsoCard, cardSecuritySetting),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSecureExtendedModeTransactionManager_whenInvokedWithNullReader_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()
            ->createSecureExtendedModeTransactionManager(
                nullptr, calypsoCard, cardSecuritySetting),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSecureExtendedModeTransactionManager_whenInvokedWithNullCalypsoCard_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()
            ->createSecureExtendedModeTransactionManager(
                reader, nullptr, cardSecuritySetting),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSecureExtendedModeTransactionManager_whenInvokedWithNullCardSecuritySetting_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()
            ->createSecureExtendedModeTransactionManager(
                reader, calypsoCard, nullptr),
        IllegalArgumentException);
}

TEST_F(
    CalypsoExtensionServiceTest,
    createSecureExtendedModeTransactionManager_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        service->getCalypsoCardApiFactory()
            ->createSecureExtendedModeTransactionManager(
                reader, calypsoCard, cardSecuritySetting),
        IllegalArgumentException);
}
