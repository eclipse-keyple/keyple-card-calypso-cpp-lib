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

/* Calypsonet Terminal Calypso */
#include "DesynchronizedExchangesException.h"

/* Calypsonet Terminal Card */
#include "ParseException.h"

/* Keyple Card Calypso */
#include "CalypsoExtensionService.h"
#include "CalypsoSamSelectionAdapter.h"

/* Keyple Core Utils */
#include "ByteArrayUtil.h"
#include "IllegalArgumentException.h"
#include "StringUtils.h"

/* Mock */
#include "ApduResponseApiMock.h"
#include "CardResponseApiMock.h"
#include "CardSelectionResponseApiMock.h"

using namespace testing;

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::card::spi;
using namespace keyple::card::calypso;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

static const std::string SAM_ATR = "3B3F9600805AAABBC1DDEEFF11223344829000";
std::shared_ptr<CalypsoSamSelectionAdapter> samSelection;

static void setUp()
{
    samSelection = std::dynamic_pointer_cast<CalypsoSamSelectionAdapter>(
                       CalypsoExtensionService::getInstance().createSamSelection());
}

static void tearDown()
{
    samSelection.reset();
}

TEST(CalypsoSamSelectionAdapterTest,
     filterByProductType_whenProductTypeIsNotDefined_shouldReturnResponseContainingACardSelectorWithPowerDataRegexAllowingAnyType)
{
    setUp();

    const std::shared_ptr<CardSelectorSpi> cardSelector =
        samSelection->getCardSelectionRequest()->getCardSelector();

    ASSERT_EQ(cardSelector->getPowerOnDataRegex(), ".*");

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest,
     filterByProductType_whenProductTypeIsDefined_shouldReturnResponseContainingACardSelectorWithPowerDataRegex)
{
    setUp();

    samSelection->filterByProductType(CalypsoSam::ProductType::SAM_C1);

    const std::shared_ptr<CardSelectorSpi> cardSelector =
        samSelection->getCardSelectionRequest()->getCardSelector();

    ASSERT_TRUE(StringUtils::contains(cardSelector->getPowerOnDataRegex(), "80C120"));

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest,
     filterBySerialNumber_whenSerialNumberRegexIsInvalid_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(samSelection->filterBySerialNumber("["), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest,
     filterBySerialNumber_shouldReturnResponseContainingACardSelectorWithPowerDataRegex)
{
    setUp();

    samSelection->filterByProductType(CalypsoSam::ProductType::SAM_C1)
                 .filterBySerialNumber("112233..");

    const std::shared_ptr<CardSelectorSpi> cardSelector =
        samSelection->getCardSelectionRequest()->getCardSelector();

    ASSERT_TRUE(StringUtils::contains(cardSelector->getPowerOnDataRegex(), "112233.."));

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest, setUnlockData_whenUnlockDataHasABadLength_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(samSelection->setUnlockData("00112233445566778899AABBCCDDEE"),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest, setUnlockData_whenUnlockDataIsInvalide_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(samSelection->setUnlockData("00112233445566778899AABBCCDDEEGG"),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest, setUnlockData_whenUnlockData_shouldProduceUnlockDataApdu)
{
    setUp();

    samSelection->setUnlockData("00112233445566778899AABBCCDDEEFF");

    const std::vector<uint8_t> unlockDataApdu =
        samSelection->getCardSelectionRequest()->getCardRequest()->getApduRequests()[0]->getApdu();

    ASSERT_EQ(unlockDataApdu,
              ByteArrayUtil::fromHex("802000001000112233445566778899AABBCCDDEEFF"));

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest,
     parse_whenCommandsResponsesMismatch_shouldThrowDesynchronizedExchangesException)
{
    setUp();

    auto cardSelectionResponseApi = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*cardSelectionResponseApi, getCardResponse()).WillOnce(Return(nullptr));
    ON_CALL(*cardSelectionResponseApi, getPowerOnData()).WillByDefault(ReturnRef(SAM_ATR));

    samSelection->setUnlockData("00112233445566778899AABBCCDDEEFF");
    samSelection->getCardSelectionRequest();

    EXPECT_THROW(samSelection->parse(cardSelectionResponseApi), DesynchronizedExchangesException);

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest, parse_whenUnlockFailed_shouldThrowParseException)
{
    setUp();

    auto cardSelectionResponseApi = std::make_shared<CardSelectionResponseApiMock>();
    auto cardResponseApi = std::make_shared<CardResponseApiMock>();
    auto apduResponseApi = std::make_shared<ApduResponseApiMock>();
    EXPECT_CALL(*apduResponseApi, getStatusWord()).WillRepeatedly(Return(0));
    const std::vector<std::shared_ptr<ApduResponseApi>> apduResponseApis = {apduResponseApi};
    EXPECT_CALL(*cardSelectionResponseApi, getPowerOnData()).WillRepeatedly(ReturnRef(SAM_ATR));
    auto unlockApduResponse = std::make_shared<ApduResponseApiMock>();
    EXPECT_CALL(*unlockApduResponse, getApdu()).WillRepeatedly(ReturnRefOfCopy(ByteArrayUtil::fromHex("6988")));
    EXPECT_CALL(*unlockApduResponse, getStatusWord()).WillRepeatedly(Return(0x6988));
    EXPECT_CALL(*cardSelectionResponseApi, getSelectApplicationResponse()).WillRepeatedly(Return(unlockApduResponse));
    EXPECT_CALL(*cardSelectionResponseApi, getCardResponse()).WillRepeatedly(Return(cardResponseApi));
    EXPECT_CALL(*cardResponseApi, getApduResponses()).WillRepeatedly(ReturnRef(apduResponseApis));

    samSelection->setUnlockData("00112233445566778899AABBCCDDEEFF");
    samSelection->getCardSelectionRequest();

    EXPECT_THROW(samSelection->parse(cardSelectionResponseApi), ParseException);

    tearDown();
}

TEST(CalypsoSamSelectionAdapterTest, parse_whenUnlockSucceed_shouldReturnCalypsoSam)
{
    setUp();

    auto cardSelectionResponseApi = std::make_shared<CardSelectionResponseApiMock>();
    auto cardResponseApi = std::make_shared<CardResponseApiMock>();
    EXPECT_CALL(*cardSelectionResponseApi, getPowerOnData()).WillRepeatedly(ReturnRef(SAM_ATR));
    auto unlockApduResponse = std::make_shared<ApduResponseApiMock>();
    const std::vector<std::shared_ptr<ApduResponseApi>> apduResponseApis = {unlockApduResponse};
    EXPECT_CALL(*unlockApduResponse, getApdu()).WillRepeatedly(ReturnRefOfCopy(ByteArrayUtil::fromHex("9000")));
    EXPECT_CALL(*unlockApduResponse, getStatusWord()).WillRepeatedly(Return(0x9000));
    EXPECT_CALL(*cardSelectionResponseApi, getSelectApplicationResponse()).WillRepeatedly(Return(unlockApduResponse));
    EXPECT_CALL(*cardSelectionResponseApi, getCardResponse()).WillRepeatedly(Return(cardResponseApi));
    EXPECT_CALL(*cardResponseApi, getApduResponses()).WillRepeatedly(ReturnRef(apduResponseApis));

    samSelection->filterByProductType(CalypsoSam::ProductType::SAM_C1);
    samSelection->setUnlockData("00112233445566778899AABBCCDDEEFF");
    samSelection->getCardSelectionRequest();

    auto calypsoSam = std::dynamic_pointer_cast<CalypsoSam>(
                          samSelection->parse(cardSelectionResponseApi));

    ASSERT_NE(calypsoSam, nullptr);
    ASSERT_EQ(calypsoSam->getProductType(), CalypsoSam::ProductType::SAM_C1);
    ASSERT_EQ(calypsoSam->getSerialNumber(), ByteArrayUtil::fromHex("11223344"));
    ASSERT_EQ(calypsoSam->getPlatform(), 0xAA);
    ASSERT_EQ(calypsoSam->getApplicationType(), 0xBB);
    ASSERT_EQ(calypsoSam->getApplicationSubType(), 0xC1);
    ASSERT_EQ(calypsoSam->getSoftwareIssuer(), 0xDD);
    ASSERT_EQ(calypsoSam->getSoftwareVersion(), 0xEE);
    ASSERT_EQ(calypsoSam->getSoftwareRevision(), 0xFF);

    tearDown();
}
