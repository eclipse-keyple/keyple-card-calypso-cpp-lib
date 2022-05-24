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
#include "ParseException.h"

/* Keyple Card Calypso */
#include "CalypsoCardSelectionAdapter.h"
#include "CalypsoExtensionService.h"

/* Keyple Core Util */
#include "Arrays.h"
#include "ByteArrayUtil.h"
#include "IllegalArgumentException.h"

/* Mock */
#include "CardSelectionResponseApiMock.h"

using namespace testing;

using namespace calypsonet::terminal::card::spi;
using namespace keyple::card::calypso;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

static std::shared_ptr<CalypsoCardSelectionAdapter> cardSelection;

static void setUp()
{
    cardSelection = std::dynamic_pointer_cast<CalypsoCardSelectionAdapter>(
                        CalypsoExtensionService::getInstance().createCardSelection());
}

static void tearDown()
{
    cardSelection.reset();
}

TEST(CalypsoCardSelectionAdapterTest, filterByCardProtocol_whenCardProtocolIsEmpty_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->filterByCardProtocol(""), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     filterByPowerOnData_whenPowerOnDataRegexIsEmpty_shouldThrowIAE)
{
    EXPECT_THROW(cardSelection->filterByPowerOnData(""), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     filterByPowerOnData_whenPowerOnDataRegexIsInvalid_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->filterByPowerOnData("["), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest, filterByDfName_whenAidIsNull_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->filterByDfName(std::vector<uint8_t>(0)), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest, filterByDfName_whenAidLengthIsLessThan5_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->filterByDfName(std::vector<uint8_t>(4)), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest, filterByDfName_whenAidLengthIsMoreThan16_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->filterByDfName(std::vector<uint8_t>(17)), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest, filterByDfName_whenAidIsNotHexString_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->filterByDfName("11223344Z5"), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     addSuccessfulStatusWord_whenStatusWordIsNegative_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->addSuccessfulStatusWord(-1), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     addSuccessfulStatusWord_whenStatusWordIsHigherThanFFFF_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->addSuccessfulStatusWord(0x10000), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest, prepareSelectFile_whenLidIsNull_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->prepareSelectFile(std::vector<uint8_t>(0)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest, prepareSelectFile_whenLidIsLessThan2ByteLong_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->prepareSelectFile(std::vector<uint8_t>(1)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest, prepareSelectFile_whenLidIsMoreThan2ByteLong_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(cardSelection->prepareSelectFile(std::vector<uint8_t>(3)),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     repareSelectFile_whenLidIs1234_shouldProduceSelectFileApduWithLid1234)
{
    setUp();

    cardSelection->filterByDfName("1122334455");
    cardSelection->prepareSelectFile(0x1234);

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<ApduRequestSpi> commandApdu =
        cardSelectionRequest->getCardRequest()->getApduRequests()[0];

    ASSERT_EQ(commandApdu->getApdu(), ByteArrayUtil::fromHex("00A4090002123400"));

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     prepareSelectFile_whenSelectFileControlIsNext_shouldProduceSelectFileApduWithSelectFileControlNext)
{
    setUp();

    cardSelection->filterByDfName("1122334455");
    cardSelection->prepareSelectFile(SelectFileControl::NEXT_EF);

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<ApduRequestSpi> commandApdu =
        cardSelectionRequest->getCardRequest()->getApduRequests()[0];

    ASSERT_EQ(commandApdu->getApdu(), ByteArrayUtil::fromHex("00A4020202000000"));

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     prepareReadRecordFile_whenSfiIs07_shouldProduceReadRecordsApduWithSfi07)
{
    setUp();

    cardSelection->filterByDfName("1122334455");
    cardSelection->prepareReadRecordFile(0x07, 1);

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<ApduRequestSpi> commandApdu =
        cardSelectionRequest->getCardRequest()->getApduRequests()[0];

    ASSERT_EQ(commandApdu->getApdu(), ByteArrayUtil::fromHex("00B2013C00"));

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     getCardSelectionRequest_whenNotSettingAreAdded_shouldReturnResponseContainingANotDefaultCardSelector)
{
    setUp();

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<CardSelectorSpi> cardSelector = cardSelectionRequest->getCardSelector();

    ASSERT_NE(cardSelector, nullptr);
    ASSERT_EQ(cardSelector->getCardProtocol(), "");
    ASSERT_EQ(cardSelector->getPowerOnDataRegex(), "");
    ASSERT_EQ(cardSelector->getAid().size(), 0);
    ASSERT_EQ(cardSelector->getFileOccurrence(), CardSelectorSpi::FileOccurrence::FIRST);
    ASSERT_EQ(cardSelector->getFileControlInformation(),
              CardSelectorSpi::FileControlInformation::FCI);
    ASSERT_TRUE(Arrays::containsOnly(cardSelector->getSuccessfulSelectionStatusWords(), 0x9000));

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     getCardSelectionRequest_whenCardProtocolIsSet_shouldReturnResponseContainingACardSelectorWithCardProtocol)
{
    setUp();

    cardSelection->filterByCardProtocol("PROTOCOL_1");

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<CardSelectorSpi> cardSelector = cardSelectionRequest->getCardSelector();

    ASSERT_EQ(cardSelector->getCardProtocol(), "PROTOCOL_1");

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     getCardSelectionRequest_whenPowerOnDataRegexIsSet_shouldReturnResponseContainingACardSelectorWithPowerOnDataRegex)
{
    setUp();

    cardSelection->filterByPowerOnData("1122334455*");

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<CardSelectorSpi> cardSelector = cardSelectionRequest->getCardSelector();

    ASSERT_EQ(cardSelector->getPowerOnDataRegex(), "1122334455*");

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     getCardSelectionRequest_whenAidIsSet_shouldReturnResponseContainingACardSelectorWithAid)
{
    setUp();

    cardSelection->filterByDfName("6677889900");

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<CardSelectorSpi> cardSelector = cardSelectionRequest->getCardSelector();

    ASSERT_EQ(cardSelector->getAid(), ByteArrayUtil::fromHex("6677889900"));

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     getCardSelectionRequest_whenFileOccurrenceIsSet_shouldReturnResponseContainingACardSelectorWithFileOccurrence)
{
    setUp();

    cardSelection->setFileOccurrence(CalypsoCardSelection::FileOccurrence::PREVIOUS);

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<CardSelectorSpi> cardSelector = cardSelectionRequest->getCardSelector();

    ASSERT_EQ(cardSelector->getFileOccurrence(), CardSelectorSpi::FileOccurrence::PREVIOUS);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     getCardSelectionRequest_whenFileControlIsSet_shouldReturnResponseContainingACardSelectorWithFileControl)
{
    setUp();

    cardSelection->setFileControlInformation(
        CalypsoCardSelection::FileControlInformation::NO_RESPONSE);

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<CardSelectorSpi> cardSelector = cardSelectionRequest->getCardSelector();

    ASSERT_EQ(cardSelector->getFileControlInformation(),
              CardSelectorSpi::FileControlInformation::NO_RESPONSE);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     getCardSelectionRequest_whenSuccessfulStatusWordIsAdded_shouldReturnResponseContainingACardSelectorWithSuccessfulStatusWord)
{
    setUp();

    cardSelection->addSuccessfulStatusWord(0x1234);

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<CardSelectorSpi> cardSelector = cardSelectionRequest->getCardSelector();

    ASSERT_TRUE(Arrays::contains(cardSelector->getSuccessfulSelectionStatusWords(), 0x9000));
    ASSERT_TRUE(Arrays::contains(cardSelector->getSuccessfulSelectionStatusWords(), 0x1234));
    ASSERT_EQ(cardSelector->getSuccessfulSelectionStatusWords().size(), 2);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest,
     getCardSelectionRequest_whenAcceptInvalidatedCardIsInvoked_shouldReturnResponseContainingACardSelectorWithSuccessfulStatusWord6283)
{
    setUp();

    cardSelection->acceptInvalidatedCard();

    const std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest =
        cardSelection->getCardSelectionRequest();
    const std::shared_ptr<CardSelectorSpi> cardSelector = cardSelectionRequest->getCardSelector();

    ASSERT_TRUE(Arrays::contains(cardSelector->getSuccessfulSelectionStatusWords(), 0x9000));
    ASSERT_TRUE(Arrays::contains(cardSelector->getSuccessfulSelectionStatusWords(), 0x6283));
    ASSERT_EQ(cardSelector->getSuccessfulSelectionStatusWords().size(), 2);

    tearDown();
}

TEST(CalypsoCardSelectionAdapterTest, parse_whenCommandsResponsesMismatch_shouldThrowParseException)
{
    setUp();

    auto cardSelectionResponseApi = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*cardSelectionResponseApi, getCardResponse()).WillOnce(Return(nullptr));

    cardSelection->prepareGetData(GetDataTag::FCI_FOR_CURRENT_DF);

    EXPECT_THROW(cardSelection->parse(cardSelectionResponseApi), ParseException);

    tearDown();
}
