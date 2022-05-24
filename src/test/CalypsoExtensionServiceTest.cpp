/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
 *                                                                                                *
 * See the NOTICE file(s) distributed with this work for additional information regarding         *
 * copyright ownership.                                                                           *
 *                                                                                                *
 * This program and the accompanying materials are made available under the terms of the Eclipse  *
 * Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0                  *
 *                                                                                                *
 * SPDX-License-Identifier: EPL-2.0                                                               *
 **************************************************************************************************/

#include "gmock/gmock.h"
#include "gtest/gtest.h"

/* Calypsonet Terminal Card */
#include "CardApiProperties.h"
#include "ProxyReaderApi.h"

/* Calypsonet Terminal Reader */
#include "ReaderApiProperties.h"

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"
#include "CalypsoExtensionService.h"
#include "CalypsoSamSelectionMock.h"
#include "CardSecuritySettingAdapter.h"

/* Keyple Core Common */
#include "CommonApiProperties.h"

/* Keyple Core Util */
#include "IllegalArgumentException.h"

/* Mock */
#include "CalypsoSamMock.h"
#include "ReaderMock.h"

using namespace testing;

using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::reader;
using namespace keyple::card::calypso;
using namespace keyple::core::common;
using namespace keyple::core::util::cpp::exception;

static const std::string POWER_ON_DATA = "3B8F8001805A0A010320031124B77FE7829000F7";
static CalypsoExtensionService& service = CalypsoExtensionService::getInstance();
static std::shared_ptr<CalypsoSamSelection> calypsoSamSelection;
static std::shared_ptr<ReaderMock> reader;
static std::shared_ptr<CalypsoCardAdapter> calypsoCard;
static std::shared_ptr<CalypsoSamMock> calypsoSam;
static std::shared_ptr<CardSecuritySetting> cardSecuritySetting;
static const std::vector<uint8_t> serial = {1, 2, 3, 4, 5, 6};

static void setUp()
{
    reader = std::make_shared<ReaderMock>();
    calypsoCard = std::make_shared<CalypsoCardAdapter>();
    calypsoSam = std::make_shared<CalypsoSamMock>();
    EXPECT_CALL(*calypsoSam, getProductType()).WillRepeatedly(Return(CalypsoSam::ProductType::SAM_C1));
    EXPECT_CALL(*calypsoSam, getSerialNumber()).WillRepeatedly(ReturnRef(serial));
    calypsoSamSelection = std::make_shared<CalypsoSamSelectionMock>();
    cardSecuritySetting = std::make_shared<CardSecuritySettingAdapter>();
}

static void tearDown()
{
    reader.reset();
    calypsoCard.reset();
    calypsoSam.reset();
    calypsoSamSelection.reset();
    cardSecuritySetting.reset();
}

TEST(CalypsoExtensionServiceTest, getInstance_whenIsInvokedTwice_shouldReturnSameInstance)
{
    setUp();

    ASSERT_EQ(&CalypsoExtensionService::getInstance(), &service);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, getReaderApiVersion_whenInvoked_shouldReturn_ExpectedVersion)
{
    setUp();

    ASSERT_EQ(service.getReaderApiVersion(), ReaderApiProperties_VERSION);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, getCardApiVersion_shouldReturnExpectedVersion)
{
    setUp();

    ASSERT_EQ(service.getCardApiVersion(), CardApiProperties_VERSION);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, getCommonApiVersion_shouldReturnExpectedVersion)
{
    setUp();

    ASSERT_EQ(service.getCommonApiVersion(), CommonApiProperties_VERSION);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardSelection_shouldReturnNewReference)
{
    setUp();

    const std::shared_ptr<CalypsoCardSelection> cardSelection = service.createCardSelection();

    ASSERT_NE(cardSelection, nullptr);
    ASSERT_NE(service.createCardSelection(), cardSelection);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardSelection_shouldReturnInstanceOfInternalSpi)
{
    setUp();

    const std::shared_ptr<CalypsoCardSelection> cardSelection = service.createCardSelection();

    ASSERT_NE(std::dynamic_pointer_cast<CardSelectionSpi>(cardSelection), nullptr);
    ASSERT_NE(std::dynamic_pointer_cast<CalypsoCardSelectionAdapter>(cardSelection), nullptr);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSamSelection_shouldReturnNewReference)
{
    setUp();

    const std::shared_ptr<CalypsoSamSelection> samSelection = service.createSamSelection();

    ASSERT_NE(samSelection, nullptr);
    ASSERT_NE(service.createSamSelection(), samSelection);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSamSelection_shouldReturnInstanceOfInternalSpi)
{
    setUp();

    const std::shared_ptr<CalypsoSamSelection> samSelection = service.createSamSelection();
    ASSERT_NE(std::dynamic_pointer_cast<CardSelectionSpi>(samSelection), nullptr);
    ASSERT_NE(std::dynamic_pointer_cast<CalypsoSamSelectionAdapter>(samSelection), nullptr);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSamResourceProfileExtension_shouldReturnANewReference)
{
    setUp();

    const std::shared_ptr<CardResourceProfileExtension> samResourceProfileExtension =
        service.createSamResourceProfileExtension(calypsoSamSelection);

    ASSERT_NE(samResourceProfileExtension, nullptr);
    ASSERT_NE(service.createSamResourceProfileExtension(calypsoSamSelection),
              samResourceProfileExtension);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardSecuritySetting_shouldReturnANewReference)
{
    setUp();

    const std::shared_ptr<CardSecuritySetting> cardSecuritySetting =
        service.createCardSecuritySetting();

    ASSERT_NE(cardSecuritySetting, nullptr);
    ASSERT_NE(service.createCardSecuritySetting(), cardSecuritySetting);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardSecuritySetting_shouldReturnInstanceOfCardSecuritySettingAdapter)
{
    setUp();

    const std::shared_ptr<CardSecuritySetting> cardSecuritySetting =
        service.createCardSecuritySetting();

    ASSERT_NE(std::dynamic_pointer_cast<CardSecuritySettingAdapter>(cardSecuritySetting), nullptr);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardTransaction_whenInvokedWithNullReader_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service.createCardTransaction(nullptr,
                                               calypsoCard,
                                               cardSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransaction_whenInvokedWithNullCalypsoCard_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service.createCardTransaction(reader, nullptr, cardSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransaction_whenInvokedWithNullCardSecuritySetting_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service.createCardTransaction(reader, calypsoCard, nullptr),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransaction_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service.createCardTransaction(reader, calypsoCard, cardSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardTransaction_shouldReturnANewReference)
{
    setUp();

    calypsoCard->initializeWithPowerOnData(POWER_ON_DATA);

    auto adapter = std::dynamic_pointer_cast<CardSecuritySettingAdapter>(cardSecuritySetting);
    adapter->setSamResource(reader, calypsoSam);

    const std::shared_ptr<CardTransactionManager> cardTransaction =
        service.createCardTransaction(reader, calypsoCard, cardSecuritySetting);

    ASSERT_NE(service.createCardTransaction(reader, calypsoCard, cardSecuritySetting),
              cardTransaction);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransactionWithoutSecurity_whenInvokedWithNullReader_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service.createCardTransactionWithoutSecurity(nullptr, calypsoCard),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransactionWithoutSecurity_whenInvokedWithNullCalypsoCard_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service.createCardTransactionWithoutSecurity(reader, nullptr),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransactionWithoutSecurity_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service.createCardTransactionWithoutSecurity(reader, calypsoCard),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransactionWithoutSecurity_whenInvoked_shouldReturnANewReference)
{
    setUp();

    calypsoCard->initializeWithPowerOnData(POWER_ON_DATA);


    auto adapter = std::dynamic_pointer_cast<CardSecuritySettingAdapter>(cardSecuritySetting);
    adapter->setSamResource(reader, calypsoSam);

    const std::shared_ptr<CardTransactionManager> cardTransaction =
        service.createCardTransactionWithoutSecurity(reader, calypsoCard);

    ASSERT_NE(service.createCardTransactionWithoutSecurity(reader, calypsoCard), cardTransaction);

    tearDown();
}
