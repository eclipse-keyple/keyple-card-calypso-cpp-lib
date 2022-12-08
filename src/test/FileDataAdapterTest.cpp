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
#include "FileDataAdapter.h"

/* Keyple Core Util */
#include "HexUtil.h"
#include "IllegalArgumentException.h"
#include "IndexOutOfBoundsException.h"

using namespace testing;

using namespace keyple::card::calypso;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

static std::shared_ptr<FileDataAdapter> file;
static const std::vector<uint8_t> data1 = HexUtil::toByteArray("11");
static const std::vector<uint8_t> data2 = HexUtil::toByteArray("2222");
static const std::vector<uint8_t> data3 = HexUtil::toByteArray("333333");
static const std::vector<uint8_t> data4 = HexUtil::toByteArray("44444444");

static void setUp()
{
    file = std::make_shared<FileDataAdapter>();
}

static void tearDown()
{
    file->reset();
}

TEST(FileDataAdapterTest, getAllRecordsContent_shouldReturnAReference)
{
    setUp();

    file->setContent(1, data1);
    const auto copy1 = file->getAllRecordsContent();
    const auto copy2 = file->getAllRecordsContent();

    ASSERT_EQ(copy1, copy2);
    ASSERT_EQ(copy1.at(1), copy2.at(1));

    tearDown();
}

TEST(FileDataAdapterTest, getContent_whenRecord1IsNotSet_shouldReturnAnEmptyArray)
{
    setUp();

    ASSERT_EQ(static_cast<int>(file->getContent().size()), 0);

    tearDown();
}

TEST(FileDataAdapterTest, getContent_shouldReturnAReference)
{
    setUp();

    file->setContent(1, data1);
    const auto copy = file->getContent();

    ASSERT_EQ(copy, data1);

    tearDown();
}

TEST(FileDataAdapterTest, getContent_shouldReturnRecord1)
{
    setUp();

    file->setContent(1, data1);
    const auto copy = file->getContent();

    ASSERT_EQ(copy, data1);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP1_whenRecordIsNotSet_shouldReturnAnEmptyArray)
{
    setUp();

    ASSERT_EQ(static_cast<int>(file->getContent(1).size()), 0);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP1_shouldReturnAReference)
{
    setUp();

    file->setContent(1, data1);
    const auto copy = file->getContent(1);

    ASSERT_EQ(copy, data1);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP1_shouldReturnRecord)
{
    setUp();

    file->setContent(1, data1);
    const auto copy = file->getContent(1);

    ASSERT_EQ(copy, data1);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP3_whenOffsetLt0_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(file->getContent(1, -1, 1), IllegalArgumentException);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP3_whenLengthLt1_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(file->getContent(1, 0, 0), IllegalArgumentException);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP3_whenRecordIsNotSet_shouldReturnAnEmptyArray)
{
    setUp();

    ASSERT_EQ(static_cast<int>(file->getContent(1, 0, 1).size()), 0);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP3_whenOffsetGeSize_shouldThrowIOOBE)
{
    setUp();

    file->setContent(1, data1);

    EXPECT_THROW(file->getContent(1, 1, 1), IndexOutOfBoundsException);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP3_whenOffsetLengthGtSize_shouldThrowIOOBE)
{
    setUp();

    file->setContent(2, data2);

    EXPECT_THROW(file->getContent(2, 1, 2), IndexOutOfBoundsException);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP3_shouldReturnACopy)
{
    setUp();

    file->setContent(1, data1);
    const auto copy = file->getContent(1, 0, 1);

    ASSERT_NE(copy, data1);

    tearDown();
}

TEST(FileDataAdapterTest, getContentP3_shouldReturnASubset)
{
    setUp();

    file->setContent(2, data2);
    const auto copy = file->getContent(2, 1, 1);

    ASSERT_EQ(copy, HexUtil::toByteArray("22"));

    tearDown();
}

TEST(FileDataAdapterTest, getContentAsCounterValue_whenNumRecordLt1_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(file->getContentAsCounterValue(0), IllegalArgumentException);

    tearDown();
}

TEST(FileDataAdapterTest, getContentAsCounterValue_whenRecordIsNotSet_shouldReturnNull)
{
    setUp();

    ASSERT_EQ(file->getContentAsCounterValue(1), nullptr);

    tearDown();
}

TEST(FileDataAdapterTest, getContentAsCounterValue_whenCounterIsNotSet_shouldReturnNull)
{
    setUp();

    file->setContent(1, data3);

    ASSERT_EQ(file->getContentAsCounterValue(2), nullptr);

    tearDown();
}

TEST(FileDataAdapterTest, getContentAsCounterValue_whenCounterIsTruncated_shouldThrowIOOBE)
{
    setUp();

    file->setContent(1, data4);

    EXPECT_THROW(file->getContentAsCounterValue(2), IndexOutOfBoundsException);

    tearDown();
}

TEST(FileDataAdapterTest, getContentAsCounterValue_shouldReturnCounterValue)
{
    setUp();

    file->setContent(1, data3);
    const int val = *file->getContentAsCounterValue(1);

    ASSERT_EQ(val, 0x333333);

    tearDown();
}

TEST(FileDataAdapterTest, getAllCountersValue_whenRecordIsNotSet_shouldReturnAnEmptyMap)
{
    setUp();

    ASSERT_EQ(static_cast<int>(file->getAllCountersValue().size()), 0);

    tearDown();
}

TEST(FileDataAdapterTest, getAllCountersValue_shouldReturnAllNonTruncatedCounters)
{
    setUp();

    file->setContent(1, data4);
    const auto counters = file->getAllCountersValue();

    ASSERT_EQ(static_cast<int>(counters.size()), 1);
    ASSERT_EQ(counters.at(1), 0x444444);

    tearDown();
}

TEST(FileDataAdapterTest, setContentP2_shouldPutAReference)
{
    setUp();

    file->setContent(1, data1);
    const auto copy = file->getContent(1);

    ASSERT_EQ(copy, data1);

    tearDown();
}

TEST(FileDataAdapterTest, setContentP2_shouldBeSuccess)
{
    setUp();

    file->setContent(1, data1);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, data1);

    tearDown();
}

TEST(FileDataAdapterTest, setContentP2_shouldReplaceExistingContent)
{
    setUp();

    file->setContent(1, data1);
    file->setContent(1, data2);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, data2);

    tearDown();
}

// TEST(FileDataAdapterTest, setCounter_whenRecord1IsNotSet_shouldCreateRecord1)
// {
//     setUp();

//     file->setCounter(1, data3);
//     const auto val = file->getContent(1);
//     assertThat(val).isNotNull();

//     tearDown();
// }

TEST(FileDataAdapterTest, setCounter_shouldPutACopy)
{
    setUp();

    file->setCounter(1, data3);
    const auto copy = file->getContent(1);
    ASSERT_NE(copy, data3);

    tearDown();
}

TEST(FileDataAdapterTest, setCounter_shouldSetOrReplaceCounterValue)
{
    setUp();

    file->setContent(1, data4);
    file->setCounter(2, data3);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, HexUtil::toByteArray("444444333333"));

    tearDown();
}

TEST(FileDataAdapterTest, setContentP3_shouldPutACopy)
{
    setUp();

    file->setContent(1, data1, 0);
    const auto copy = file->getContent(1);

    ASSERT_NE(copy, data1);

    tearDown();
}

TEST(FileDataAdapterTest, setContentP3_whenRecordIsNotSet_shouldPadWith0)
{
    setUp();

    file->setContent(1, data1, 1);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, HexUtil::toByteArray("0011"));

    tearDown();
}

TEST(FileDataAdapterTest, setContentP3_whenOffsetGeSize_shouldPadWith0)
{
    setUp();

    file->setContent(1, data1);
    file->setContent(1, data2, 2);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, HexUtil::toByteArray("11002222"));

    tearDown();
}

TEST(FileDataAdapterTest, setContentP3_shouldReplaceInRange)
{
    setUp();

    file->setContent(1, data4);
    file->setContent(1, data2, 1);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, HexUtil::toByteArray("44222244"));

    tearDown();
}

TEST(FileDataAdapterTest, fillContent_whenRecordIsNotSet_shouldPutContentAndPadWith0)
{
    setUp();

    file->fillContent(1, data2, 1);
    const auto content = file->getContent(1);

    ASSERT_EQ(content, HexUtil::toByteArray("002222"));

    tearDown();
}

TEST(FileDataAdapterTest,
     fillContent_whenLengthGtActualSize_shouldApplyBinaryOperationAndRightPadWithContent)
{
    setUp();

    file->setContent(1, data2);
    file->fillContent(1, data4, 1);
    const auto content = file->getContent(1);

    ASSERT_EQ(content, HexUtil::toByteArray("2266444444"));

    tearDown();
}

TEST(FileDataAdapterTest, fillContent_whenLengthLeActualSize_shouldApplyBinaryOperation)
{
    setUp();

    file->setContent(1, data4);
    file->fillContent(1, data2, 1);
    const auto content = file->getContent(1);

    ASSERT_EQ(content, HexUtil::toByteArray("44666644"));

    tearDown();
}

TEST(FileDataAdapterTest, addCyclicContent_whenNoContent_shouldSetContentToRecord1)
{
    setUp();

    file->addCyclicContent(data1);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, data1);

    tearDown();
}

TEST(FileDataAdapterTest, addCyclicContent_shouldShiftAllRecordsAndSetContentToRecord1)
{
    setUp();

    file->setContent(1, data1);
    file->setContent(2, data2);
    file->addCyclicContent(data3);
    const auto content = file->getAllRecordsContent();
    auto it = content.begin();

    ASSERT_EQ(static_cast<int>(content.size()), 3);
    ASSERT_EQ(*it++, HexUtil::toByteArray("333333"));
    ASSERT_EQ(*it++, HexUtil::toByteArray("11"));
    ASSERT_EQ(*it++, HexUtil::toByteArray("2222"));

    tearDown();
}

TEST(FileDataAdapterTest, cloningConstructor_shouldReturnACopy)
{
    setUp();

    file->setContent(1, data1);
    const auto clone = std::make_shared<FileDataAdapter>(file);

    ASSERT_NE(clone, file);
    ASSERT_NE(clone->getContent(1), file->getContent(1));

    tearDown();
}
