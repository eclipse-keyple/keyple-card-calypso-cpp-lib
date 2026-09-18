/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/StringUtils.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IndexOutOfBoundsException.hpp"

using keyple::card::calypso::DtoAdapters;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::StringUtils;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IndexOutOfBoundsException;

static std::shared_ptr<DtoAdapters::SvDebitLogRecordAdapter>
    svDebitLogRecordAdapter;

static const std::string HEADER = "79007013DE31A75F00001A";
static const std::string AMOUNT_STR = "FFFE";
static const std::string DATE_STR = "1234";
static const std::string TIME_STR = "5678";
static const std::string KVC_STR = "90";
static const std::string SAMID_STR = "AABBCCDD";

static const int AMOUNT = -2;
static const std::vector<uint8_t> DATE = HexUtil::toByteArray(DATE_STR);
static const std::vector<uint8_t> TIME = HexUtil::toByteArray(TIME_STR);
static const uint8_t KVC = (uint8_t)0x90;
static const std::vector<uint8_t> SAMID = HexUtil::toByteArray(SAMID_STR);
static const int SAM_TNUM = 0x123456;
static const int BALANCE = 0x445566;
static const int SV_TNUM = 0x7890;

static const std::string BALANCE_STR = StringUtils::format("%06X", BALANCE);
static const std::string SAM_TNUM_STR = StringUtils::format("%06X", SAM_TNUM);
static const std::string SV_TNUM_STR = StringUtils::format("%04X", SV_TNUM);

class SvDebitLogRecordTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
        const std::vector<uint8_t> svGetDebitData = HexUtil::toByteArray(
            HEADER + AMOUNT_STR + DATE_STR + TIME_STR + KVC_STR + SAMID_STR
            + SAM_TNUM_STR + BALANCE_STR + SV_TNUM_STR);

        svDebitLogRecordAdapter
            = std::make_shared<DtoAdapters::SvDebitLogRecordAdapter>(
                svGetDebitData, static_cast<int>(HEADER.size() / 2));
    }

    static void
    tearDown()
    {
        svDebitLogRecordAdapter.reset();
    }
};

TEST_F(SvDebitLogRecordTest, getAmount_shouldReturnAmount)
{
    ASSERT_EQ(svDebitLogRecordAdapter->getAmount(), AMOUNT);
}

TEST_F(SvDebitLogRecordTest, getBalance_shouldReturnBalance)
{
    ASSERT_EQ(svDebitLogRecordAdapter->getBalance(), BALANCE);
}

TEST_F(SvDebitLogRecordTest, getDebitDate_shouldReturnDebitDate)
{
    ASSERT_EQ(svDebitLogRecordAdapter->getDebitDate(), DATE);
}

TEST_F(SvDebitLogRecordTest, getDebitTime_shouldReturnDebitTime)
{
    ASSERT_EQ(svDebitLogRecordAdapter->getDebitTime(), TIME);
}

TEST_F(SvDebitLogRecordTest, getKvc_shouldReturnKvc)
{
    ASSERT_EQ(svDebitLogRecordAdapter->getKvc(), KVC);
}

TEST_F(SvDebitLogRecordTest, getSamId_shouldReturnSamId)
{
    ASSERT_EQ(svDebitLogRecordAdapter->getSamId(), SAMID);
}

TEST_F(SvDebitLogRecordTest, getSamTNum_shouldReturnSamTNum)
{
    ASSERT_EQ(svDebitLogRecordAdapter->getSamTNum(), SAM_TNUM);
}

TEST_F(SvDebitLogRecordTest, getSvTNum_shouldReturnSvTNum)
{
    ASSERT_EQ(svDebitLogRecordAdapter->getSvTNum(), SV_TNUM);
}

TEST_F(SvDebitLogRecordTest, toString_shouldContainSamID)
{
    std::stringstream ss;
    ss << svDebitLogRecordAdapter;

    std::cout << svDebitLogRecordAdapter << std::endl;
    std::cout << ss.str() << std::endl;

    ASSERT_TRUE(StringUtils::contains(ss.str(), SAMID_STR));
}
