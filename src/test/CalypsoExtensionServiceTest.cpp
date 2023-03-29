/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
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

/* Keyple Core Service */
#include "CardSelectionResponseAdapter.h"

/* Mock */
#include "CalypsoSamMock.h"
#include "CardSelectionResponseApiMock.h"
#include "ReaderMock.h"

using namespace testing;

using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::reader;
using namespace keyple::card::calypso;
using namespace keyple::core::common;
using namespace keyple::core::service;
using namespace keyple::core::util::cpp::exception;

static const std::string POWER_ON_DATA = "3B8F8001805A0A010320031124B77FE7829000F7";
static const std::string SAM_C1_POWER_ON_DATA = "3B3F9600805A4880C120501711223344829000";
static const std::string SAM_F1_POWER_ON_DATA = "3B3F9600805A4880F120501711223344829000";
static std::shared_ptr<CalypsoExtensionService> service = CalypsoExtensionService::getInstance();
static std::shared_ptr<CalypsoSamSelection> calypsoSamSelection;
static std::shared_ptr<ReaderMock> reader;
static std::shared_ptr<CalypsoCardAdapter> calypsoCard;
static std::shared_ptr<CardSecuritySetting> cardSecuritySetting;
static std::shared_ptr<CalypsoSamAdapter> calypsoSam;
static std::shared_ptr<SamSecuritySetting> samSecuritySetting;
static const std::vector<uint8_t> serial = {1, 2, 3, 4, 5, 6};

static void setUp()
{
    reader = std::make_shared<ReaderMock>();
    calypsoCard = std::make_shared<CalypsoCardAdapter>();
    cardSecuritySetting = std::make_shared<CardSecuritySettingAdapter>();
    calypsoSamSelection = std::make_shared<CalypsoSamSelectionMock>();
    auto samCardSelectionResponse = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*samCardSelectionResponse, getPowerOnData()).WillRepeatedly(ReturnRef(SAM_C1_POWER_ON_DATA));
    calypsoSam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);
    samSecuritySetting = std::make_shared<SamSecuritySettingAdapter>();
}

static void tearDown()
{
    reader.reset();
    calypsoCard.reset();
    calypsoSam.reset();
    calypsoSamSelection.reset();
    cardSecuritySetting.reset();
    samSecuritySetting.reset();
}

TEST(CalypsoExtensionServiceTest, getInstance_whenIsInvokedTwice_shouldReturnSameInstance)
{
    setUp();

    ASSERT_EQ(CalypsoExtensionService::getInstance(), service);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, getReaderApiVersion_whenInvoked_shouldReturn_ExpectedVersion)
{
    setUp();

    ASSERT_EQ(service->getReaderApiVersion(), ReaderApiProperties_VERSION);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, getCardApiVersion_shouldReturnExpectedVersion)
{
    setUp();

    ASSERT_EQ(service->getCardApiVersion(), CardApiProperties_VERSION);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, getCommonApiVersion_shouldReturnExpectedVersion)
{
    setUp();

    ASSERT_EQ(service->getCommonApiVersion(), CommonApiProperties_VERSION);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSearchCommandData_shouldReturnNewReference)
{
    setUp();

    const auto data = service->createSearchCommandData();

    ASSERT_NE(data, nullptr);
    ASSERT_NE(data, service->createSearchCommandData());

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createBasicSignatureComputationData_shouldReturnNewReference)
{
    setUp();

    const auto data = service->createBasicSignatureComputationData();

    ASSERT_NE(data, nullptr);
    ASSERT_NE(data, service->createBasicSignatureComputationData());

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createTraceableSignatureComputationData_shouldReturnNewReference)
{
    setUp();

    const auto data = service->createTraceableSignatureComputationData();

    ASSERT_NE(data, nullptr);
    ASSERT_NE(data, service->createTraceableSignatureComputationData());

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createBasicSignatureVerificationData_shouldReturnNewReference)
{
    setUp();

    const auto data = service->createBasicSignatureVerificationData();

    ASSERT_NE(data, nullptr);
    ASSERT_NE(data, service->createBasicSignatureVerificationData());

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createTraceableSignatureVerificationData_shouldReturnNewReference)
{
    setUp();

    const auto data = service->createTraceableSignatureVerificationData();

    ASSERT_NE(data, nullptr);
    ASSERT_NE(data, service->createTraceableSignatureVerificationData());

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardSelection_shouldReturnNewReference)
{
    setUp();

    const auto selection = service->createCardSelection();

    ASSERT_NE(selection, nullptr);
    ASSERT_NE(selection, service->createCardSelection());

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardSelection_shouldReturnInstanceOfInternalSpi)
{
    setUp();

    const std::shared_ptr<CalypsoCardSelection> cardSelection = service->createCardSelection();

    ASSERT_NE(std::dynamic_pointer_cast<CardSelectionSpi>(cardSelection), nullptr);
    ASSERT_NE(std::dynamic_pointer_cast<CalypsoCardSelectionAdapter>(cardSelection), nullptr);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSamSelection_shouldReturnNewReference)
{
    setUp();

    const auto selection = service->createSamSelection();

    ASSERT_NE(selection, nullptr);
    ASSERT_NE(selection, service->createSamSelection());

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSamSelection_shouldReturnInstanceOfInternalSpi)
{
    setUp();

    const std::shared_ptr<CalypsoSamSelection> samSelection = service->createSamSelection();

    ASSERT_NE(std::dynamic_pointer_cast<CardSelectionSpi>(samSelection), nullptr);
    ASSERT_NE(std::dynamic_pointer_cast<CalypsoSamSelectionAdapter>(samSelection), nullptr);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSamResourceProfileExtension_shouldReturnANewReference)
{
    setUp();

    const std::shared_ptr<CardResourceProfileExtension> samResourceProfileExtension =
        service->createSamResourceProfileExtension(calypsoSamSelection);

    ASSERT_NE(samResourceProfileExtension, nullptr);
    ASSERT_NE(service->createSamResourceProfileExtension(calypsoSamSelection),
              samResourceProfileExtension);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardSecuritySetting_shouldReturnANewReference)
{
    setUp();

    const std::shared_ptr<CardSecuritySetting> lCardSecuritySetting =
        service->createCardSecuritySetting();

    ASSERT_NE(lCardSecuritySetting, nullptr);
    ASSERT_NE(service->createCardSecuritySetting(), lCardSecuritySetting);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardSecuritySetting_shouldReturnInstanceOfCardSecuritySettingAdapter)
{
    setUp();

    const std::shared_ptr<CardSecuritySetting> lCardSecuritySetting =
        service->createCardSecuritySetting();

    ASSERT_NE(std::dynamic_pointer_cast<CardSecuritySettingAdapter>(lCardSecuritySetting), nullptr);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createCardTransaction_whenInvokedWithNullReader_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createCardTransaction(nullptr, calypsoCard, cardSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransaction_whenInvokedWithNullCalypsoCard_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createCardTransaction(reader, nullptr, cardSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransaction_whenInvokedWithNullCardSecuritySetting_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createCardTransaction(reader, calypsoCard, nullptr),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransaction_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createCardTransaction(reader, calypsoCard, cardSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransactionWithoutSecurity_whenInvokedWithNullReader_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createCardTransactionWithoutSecurity(nullptr, calypsoCard),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransactionWithoutSecurity_whenInvokedWithNullCalypsoCard_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createCardTransactionWithoutSecurity(reader, nullptr),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransactionWithoutSecurity_whenInvokedWithUndefinedCalypsoCardProductType_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createCardTransactionWithoutSecurity(reader, calypsoCard),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createCardTransactionWithoutSecurity_whenInvoked_shouldReturnANewReference)
{
    setUp();

    calypsoCard = std::make_shared<CalypsoCardAdapter>();
    calypsoCard->initialize(std::make_shared<CardSelectionResponseAdapter>(POWER_ON_DATA));

    auto adapter = std::dynamic_pointer_cast<CardSecuritySettingAdapter>(cardSecuritySetting);
    adapter->setSamResource(reader, calypsoSam);

    const std::shared_ptr<CardTransactionManager> cardTransaction =
        service->createCardTransactionWithoutSecurity(reader, calypsoCard);

    ASSERT_NE(service->createCardTransactionWithoutSecurity(reader, calypsoCard), cardTransaction);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSamSecuritySetting_shouldReturnANewReference)
{
    setUp();

    const auto samSecuritySetting = service->createSamSecuritySetting();

    ASSERT_NE(samSecuritySetting, nullptr);
    ASSERT_NE(service->createSamSecuritySetting(), samSecuritySetting);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createSamSecuritySetting_shouldReturnInstanceOfSamSecuritySettingAdapter)
{
    setUp();

    const auto setting = service->createSamSecuritySetting();
    const auto adapter = std::dynamic_pointer_cast<SamSecuritySettingAdapter>(setting);

    ASSERT_NE(adapter, nullptr);

    tearDown();
}

TEST(CalypsoExtensionServiceTest, createSamTransaction_whenInvokedWithNullReader_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createSamTransaction(nullptr, calypsoSam, samSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createSamTransaction_whenInvokedWithNullCalypsoCard_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createSamTransaction(reader, nullptr, samSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createSamTransaction_whenInvokedWithNullSamSecuritySetting_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createSamTransaction(reader, calypsoSam, nullptr),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createSamTransaction_whenInvokedWithUndefinedCalypsoSamProductType_shouldThrowIAE)
{
    setUp();

    /*
     * C++: use specific power on data to make sure product type is unknow (we can't create a mock
     * on a final function.
     *
     * EXPECT_CALL(*calypsoSam, getProductType())
     *    .WillRepeatedly(Return(CalypsoSam::ProductType::UNKNOWN));
     */
    auto samCardSelectionResponse = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*samCardSelectionResponse, getPowerOnData())
        .WillRepeatedly(ReturnRef(SAM_F1_POWER_ON_DATA));
    calypsoSam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);

    EXPECT_THROW(service->createSamTransaction(reader, calypsoSam, samSecuritySetting),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createSamTransactionWithoutSecurity_whenInvokedWithNullReader_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createSamTransactionWithoutSecurity(nullptr, calypsoSam),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createSamTransactionWithoutSecurity_whenInvokedWithNullCalypsoSam_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(service->createSamTransactionWithoutSecurity(reader, nullptr),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createSamTransactionWithoutSecurity_whenInvokedWithUndefinedCalypsoSamProductType_shouldThrowIAE)
{
    setUp();

    /*
     * C++: use specific power on data to make sure product type is unknow (we can't create a mock
     * on a final function.
     *
     * EXPECT_CALL(*calypsoSam, getProductType())
     *    .WillRepeatedly(Return(CalypsoSam::ProductType::UNKNOWN));
     */
    auto samCardSelectionResponse = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*samCardSelectionResponse, getPowerOnData())
        .WillRepeatedly(ReturnRef(SAM_F1_POWER_ON_DATA));
    calypsoSam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);

    EXPECT_THROW(service->createSamTransactionWithoutSecurity(reader, calypsoSam),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoExtensionServiceTest,
     createSamTransactionWithoutSecurity_whenInvoked_shouldReturnANewReference)
{
    setUp();

    const auto samTransaction = service->createSamTransactionWithoutSecurity(reader, calypsoSam);

    ASSERT_NE(service->createSamTransactionWithoutSecurity(reader, calypsoSam), samTransaction);

    tearDown();
}
