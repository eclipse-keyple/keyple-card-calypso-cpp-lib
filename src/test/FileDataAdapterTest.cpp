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
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/FileDataAdapter.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IndexOutOfBoundsException.hpp"

using keyple::card::calypso::FileDataAdapter;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IndexOutOfBoundsException;

static std::shared_ptr<FileDataAdapter> file;
static const std::vector<uint8_t> data1 = HexUtil::toByteArray("11");
static const std::vector<uint8_t> data2 = HexUtil::toByteArray("2222");
static const std::vector<uint8_t> data3 = HexUtil::toByteArray("333333");
static const std::vector<uint8_t> data4 = HexUtil::toByteArray("44444444");

class FileDataAdapterTest : public ::testing::Test {
protected:
    void
    SetUp()
    {
        file = std::make_shared<FileDataAdapter>();
    }

    void
    TearDown()
    {
        file.reset();
    }
};

TEST_F(FileDataAdapterTest, getAllRecordsContent_shouldReturnAReference)
{
    file->setContent(1, data1);
    const auto copy1 = file->getAllRecordsContent();
    const auto copy2 = file->getAllRecordsContent();

    ASSERT_EQ(copy1, copy2);
    ASSERT_EQ(copy1.at(1), copy2.at(1));
}

TEST_F(
    FileDataAdapterTest,
    getContent_whenRecord1IsNotSet_shouldReturnAnEmptyArray)
{
    ASSERT_EQ(static_cast<int>(file->getContent().size()), 0);
}

TEST_F(FileDataAdapterTest, getContent_shouldReturnAReference)
{
    file->setContent(1, data1);
    const auto copy = file->getContent();

    ASSERT_EQ(copy, data1);
}

TEST_F(FileDataAdapterTest, getContent_shouldReturnRecord1)
{
    file->setContent(1, data1);
    const auto copy = file->getContent();

    ASSERT_EQ(copy, data1);
}

TEST_F(
    FileDataAdapterTest,
    getContentP1_whenRecordIsNotSet_shouldReturnAnEmptyArray)
{
    ASSERT_EQ(static_cast<int>(file->getContent(1).size()), 0);
}

TEST_F(FileDataAdapterTest, getContentP1_shouldReturnAReference)
{
    file->setContent(1, data1);
    const auto copy = file->getContent(1);

    ASSERT_EQ(copy, data1);
}

TEST_F(FileDataAdapterTest, getContentP1_shouldReturnRecord)
{
    file->setContent(1, data1);
    const auto copy = file->getContent(1);

    ASSERT_EQ(copy, data1);
}

/*
 *C++: this test does not make sense since dataOffset is of type uint8_t and
 * therefore cannot be negative.
 */
// TEST_F(
// FileDataAdapterTest,
// getContentP3_whenOffsetLt0_shouldThrowIAE)
// {
//     EXPECT_THROW(file->getContent(1, -1, 1), IllegalArgumentException);
// }

TEST_F(FileDataAdapterTest, getContentP3_whenLengthLt1_shouldThrowIAE)
{
    EXPECT_THROW(file->getContent(1, 0, 0), IllegalArgumentException);
}

TEST_F(
    FileDataAdapterTest,
    getContentP3_whenRecordIsNotSet_shouldReturnAnEmptyArray)
{
    ASSERT_EQ(static_cast<int>(file->getContent(1, 0, 1).size()), 0);
}

TEST_F(FileDataAdapterTest, getContentP3_whenOffsetGeSize_shouldThrowIOOBE)
{
    file->setContent(1, data1);

    EXPECT_THROW(file->getContent(1, 1, 1), IndexOutOfBoundsException);
}

TEST_F(
    FileDataAdapterTest, getContentP3_whenOffsetLengthGtSize_shouldThrowIOOBE)
{
    file->setContent(2, data2);

    EXPECT_THROW(file->getContent(2, 1, 2), IndexOutOfBoundsException);
}

TEST_F(FileDataAdapterTest, getContentP3_shouldReturnACopy)
{
    file->setContent(1, data1);
    const auto copy = file->getContent(1, 0, 1);

    ASSERT_NE(&copy, &data1);
}

TEST_F(FileDataAdapterTest, getContentP3_shouldReturnASubset)
{
    file->setContent(2, data2);
    const auto copy = file->getContent(2, 1, 1);

    ASSERT_EQ(copy, HexUtil::toByteArray("22"));
}

TEST_F(
    FileDataAdapterTest,
    getContentAsCounterValue_whenNumRecordLt1_shouldThrowIAE)
{
    EXPECT_THROW(file->getContentAsCounterValue(0), IllegalArgumentException);
}

TEST_F(
    FileDataAdapterTest,
    getContentAsCounterValue_whenRecordIsNotSet_shouldReturnNull)
{
    ASSERT_EQ(file->getContentAsCounterValue(1), nullptr);
}

TEST_F(
    FileDataAdapterTest,
    getContentAsCounterValue_whenCounterIsNotSet_shouldReturnNull)
{
    file->setContent(1, data3);

    ASSERT_EQ(file->getContentAsCounterValue(2), nullptr);
}

TEST_F(
    FileDataAdapterTest,
    getContentAsCounterValue_whenCounterIsTruncated_shouldThrowIOOBE)
{
    file->setContent(1, data4);

    EXPECT_THROW(file->getContentAsCounterValue(2), IndexOutOfBoundsException);
}

TEST_F(FileDataAdapterTest, getContentAsCounterValue_shouldReturnCounterValue)
{
    file->setContent(1, data3);
    const int val = *file->getContentAsCounterValue(1);

    ASSERT_EQ(val, 0x333333);
}

TEST_F(
    FileDataAdapterTest,
    getAllCountersValue_whenRecordIsNotSet_shouldReturnAnEmptyMap)
{
    ASSERT_EQ(static_cast<int>(file->getAllCountersValue().size()), 0);
}

TEST_F(
    FileDataAdapterTest,
    getAllCountersValue_shouldReturnAllNonTruncatedCounters)
{
    file->setContent(1, data4);
    const auto counters = file->getAllCountersValue();

    ASSERT_EQ(static_cast<int>(counters.size()), 1);
    ASSERT_EQ(counters.at(1), 0x444444);
}

TEST_F(FileDataAdapterTest, setContentP2_shouldPutAReference)
{
    file->setContent(1, data1);
    const auto copy = file->getContent(1);

    ASSERT_EQ(copy, data1);
}

TEST_F(FileDataAdapterTest, setContentP2_shouldBeSuccess)
{
    file->setContent(1, data1);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, data1);
}

TEST_F(FileDataAdapterTest, setContentP2_shouldReplaceExistingContent)
{
    file->setContent(1, data1);
    file->setContent(1, data2);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, data2);
}

/* C++: test is irrelevan as getContent() returns a vector and therefore cannot
 * be null */
// TEST_F(
//      FileDataAdapterTest,
//      setCounter_whenRecord1IsNotSet_shouldCreateRecord1)
// {
//     file->setCounter(1, data3);
//     const auto val = file->getContent(1);
//     assertThat(val).isNotNull();
// }

TEST_F(FileDataAdapterTest, setCounter_shouldPutACopy)
{
    file->setCounter(1, data3);
    const auto copy = file->getContent(1);
    ASSERT_NE(&copy, &data3);
}

TEST_F(FileDataAdapterTest, setCounter_shouldSetOrReplaceCounterValue)
{
    file->setContent(1, data4);
    file->setCounter(2, data3);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, HexUtil::toByteArray("444444333333"));
}

TEST_F(FileDataAdapterTest, setContentP3_shouldPutACopy)
{
    file->setContent(1, data1, 0);
    const auto copy = file->getContent(1);

    ASSERT_NE(&copy, &data1);
}

TEST_F(FileDataAdapterTest, setContentP3_whenRecordIsNotSet_shouldPadWith0)
{
    file->setContent(1, data1, 1);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, HexUtil::toByteArray("0011"));
}

TEST_F(FileDataAdapterTest, setContentP3_whenOffsetGeSize_shouldPadWith0)
{
    file->setContent(1, data1);
    file->setContent(1, data2, 2);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, HexUtil::toByteArray("11002222"));
}

TEST_F(FileDataAdapterTest, setContentP3_shouldReplaceInRange)
{
    file->setContent(1, data4);
    file->setContent(1, data2, 1);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, HexUtil::toByteArray("44222244"));
}

TEST_F(
    FileDataAdapterTest,
    fillContent_whenRecordIsNotSet_shouldPutContentAndPadWith0)
{
    file->fillContent(1, data2, 1);
    const auto content = file->getContent(1);

    ASSERT_EQ(content, HexUtil::toByteArray("002222"));
}

TEST_F(
    FileDataAdapterTest,
    fillContent_whenLengthGtActualSize_shouldApplyBinaryOperationAndRightPadWithContent)  // NOLINT
{
    file->setContent(1, data2);
    file->fillContent(1, data4, 1);
    const auto content = file->getContent(1);

    ASSERT_EQ(content, HexUtil::toByteArray("2266444444"));
}

TEST_F(
    FileDataAdapterTest,
    fillContent_whenLengthLeActualSize_shouldApplyBinaryOperation)
{
    file->setContent(1, data4);
    file->fillContent(1, data2, 1);
    const auto content = file->getContent(1);

    ASSERT_EQ(content, HexUtil::toByteArray("44666644"));
}

TEST_F(
    FileDataAdapterTest,
    addCyclicContent_whenNoContent_shouldSetContentToRecord1)
{
    file->addCyclicContent(data1);
    const auto val = file->getContent(1);

    ASSERT_EQ(val, data1);
}

TEST_F(
    FileDataAdapterTest,
    addCyclicContent_shouldShiftAllRecordsAndSetContentToRecord1)
{
    file->setContent(1, data1);
    file->setContent(2, data2);
    file->addCyclicContent(data3);
    const auto content = file->getAllRecordsContent();
    auto it = content.begin();

    ASSERT_EQ(static_cast<int>(content.size()), 3);
    ASSERT_EQ(it->second, HexUtil::toByteArray("333333"));
    it++;
    ASSERT_EQ(it->second, HexUtil::toByteArray("11"));
    it++;
    ASSERT_EQ(it->second, HexUtil::toByteArray("2222"));
}

/* C++: test is irrelevant since getContent() returns a copy already, can't be
 * the same */
// TEST_F(
//      FileDataAdapterTest,
//      cloningConstructor_shouldReturnACopy)
// {
//     file->setContent(1, data1);
//     const auto clone = std::make_shared<FileDataAdapter>(file);
//
//     ASSERT_NE(clone, file);
//     ASSERT_NE(clone->getContent(1), file->getContent(1));
// }
