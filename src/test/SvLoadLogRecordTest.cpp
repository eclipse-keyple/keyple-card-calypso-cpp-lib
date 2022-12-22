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

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

/* Calypsonet Terminal Calypso */
#include "SvLoadLogRecordAdapter.h"

/* Keyple Core Util */
#include "HexUtil.h"
#include "IllegalArgumentException.h"
#include "IndexOutOfBoundsException.h"
#include "StringUtils.h"

using namespace testing;

using namespace keyple::card::calypso;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

static std::shared_ptr<SvLoadLogRecordAdapter> svLoadLogRecordAdapter;

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
static const std::vector<uint8_t> FREE = HexUtil::toByteArray(FREE1_STR + FREE2_STR);
static const uint8_t KVC = 0x90;
static const std::vector<uint8_t> SAMID = HexUtil::toByteArray(SAMID_STR);
static const int SAM_TNUM = 0x123456;
static const int BALANCE = 0x445566;
static const int SV_TNUM = 0x7890;

static const std::string BALANCE_STR = StringUtils::format("%06X", BALANCE);
static const std::string SAM_TNUM_STR = StringUtils::format("%06X", SAM_TNUM);
static const std::string SV_TNUM_STR = StringUtils::format("%04X", SV_TNUM);

static void setUp()
{
    const std::vector<uint8_t> svGetLoadData = HexUtil::toByteArray(HEADER +
                                                                    DATE_STR +
                                                                    FREE1_STR +
                                                                    KVC_STR +
                                                                    FREE2_STR +
                                                                    BALANCE_STR +
                                                                    AMOUNT_STR +
                                                                    TIME_STR +
                                                                    SAMID_STR +
                                                                    SAM_TNUM_STR +
                                                                    SV_TNUM_STR);

    svLoadLogRecordAdapter = std::make_shared<SvLoadLogRecordAdapter>(svGetLoadData,
                                                                      HEADER.size() / 2);
}

static void tearDown()
{
    svLoadLogRecordAdapter.reset();
}

TEST(SvLoadLogRecordAdapterTest, getAmount_shouldReturnAmount)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getAmount(), AMOUNT);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, getBalance_shouldReturnBalance)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getBalance(), BALANCE);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, getLoadDate_shouldReturnLoadDate)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getLoadDate(), DATE);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, getLoadTime_shouldReturnLoadTime)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getLoadTime(), TIME);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, getFreeData_shouldReturnFreeData)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getFreeData(), FREE);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, getKvc_shouldReturnKvc)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getKvc(), KVC);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, getSamId_shouldReturnSamId)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getSamId(), SAMID);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, getSamTNum_shouldReturnSamTNum)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getSamTNum(), SAM_TNUM);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, getSvTNum_shouldReturnSvTNum)
{
    setUp();

    ASSERT_EQ(svLoadLogRecordAdapter->getSvTNum(), SV_TNUM);

    tearDown();
}

TEST(SvLoadLogRecordAdapterTest, toString_shouldContainSamID)
{
    setUp();

    std::stringstream ss;
    ss << svLoadLogRecordAdapter;

    ASSERT_TRUE(StringUtils::contains(ss.str(), SAMID_STR));

    tearDown();
}
