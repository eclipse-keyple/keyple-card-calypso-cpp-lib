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

static std::shared_ptr<DtoAdapters::SvLoadLogRecordAdapter>
    svLoadLogRecordAdapter;

static const std::string HEADER = "79007013DE31A75F00001A";
static const std::string AMOUNT_STR = "FFFFFE";
static const std::string DATE_STR = "1234";
static const std::string TIME_STR = "5678";
static const std::string FREE1_STR = "41";
static const std::string FREE2_STR = "42";
static const std::string KVC_STR = "90";
static const std::string SAMID_STR = "AABBCCDD";

static const int AMOUNT = -2;
static const std::vector<uint8_t> DATE = HexUtil::toByteArray(DATE_STR);
static const std::vector<uint8_t> TIME = HexUtil::toByteArray(TIME_STR);
static const std::vector<uint8_t> FREE
    = HexUtil::toByteArray(FREE1_STR + FREE2_STR);
static const uint8_t KVC = 0x90;
static const std::vector<uint8_t> SAMID = HexUtil::toByteArray(SAMID_STR);
static const int SAM_TNUM = 0x123456;
static const int BALANCE = 0x445566;
static const int SV_TNUM = 0x7890;

static const std::string BALANCE_STR = StringUtils::format("%06X", BALANCE);
static const std::string SAM_TNUM_STR = StringUtils::format("%06X", SAM_TNUM);
static const std::string SV_TNUM_STR = StringUtils::format("%04X", SV_TNUM);

class SvLoadLogRecordTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
        const std::vector<uint8_t> svGetLoadData = HexUtil::toByteArray(
            HEADER + DATE_STR + FREE1_STR + KVC_STR + FREE2_STR + BALANCE_STR
            + AMOUNT_STR + TIME_STR + SAMID_STR + SAM_TNUM_STR + SV_TNUM_STR);

        svLoadLogRecordAdapter
            = std::make_shared<DtoAdapters::SvLoadLogRecordAdapter>(
                svGetLoadData, static_cast<int>(HEADER.size() / 2));
    }

    void
    TearDown() override
    {
        svLoadLogRecordAdapter.reset();
    }
};

TEST_F(SvLoadLogRecordTest, getAmount_shouldReturnAmount)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getAmount(), AMOUNT);
}

TEST_F(SvLoadLogRecordTest, getBalance_shouldReturnBalance)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getBalance(), BALANCE);
}

TEST_F(SvLoadLogRecordTest, getLoadDate_shouldReturnLoadDate)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getLoadDate(), DATE);
}

TEST_F(SvLoadLogRecordTest, getLoadTime_shouldReturnLoadTime)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getLoadTime(), TIME);
}

TEST_F(SvLoadLogRecordTest, getFreeData_shouldReturnFreeData)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getFreeData(), FREE);
}

TEST_F(SvLoadLogRecordTest, getKvc_shouldReturnKvc)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getKvc(), KVC);
}

TEST_F(SvLoadLogRecordTest, getSamId_shouldReturnSamId)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getSamId(), SAMID);
}

TEST_F(SvLoadLogRecordTest, getSamTNum_shouldReturnSamTNum)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getSamTNum(), SAM_TNUM);
}

TEST_F(SvLoadLogRecordTest, getSvTNum_shouldReturnSvTNum)
{
    ASSERT_EQ(svLoadLogRecordAdapter->getSvTNum(), SV_TNUM);
}

TEST_F(SvLoadLogRecordTest, toString_shouldContainSamID)
{
    std::stringstream ss;
    ss << svLoadLogRecordAdapter;

    ASSERT_TRUE(StringUtils::contains(ss.str(), SAMID_STR));
}
