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

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

/* Calypsonet Terminal Calypso */
#include "SvDebitLogRecordAdapter.h"

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

static std::shared_ptr<SvDebitLogRecordAdapter> svDebitLogRecordAdapter;

static const std::string HEADER = "79007013DE31A75F00001A";
static const std::string AMOUNT_STR = "FFFE";
static const std::string DATE_STR = "1234";
static const std::string TIME_STR = "5678";
static const std::string KVC_STR = "90";
static const std::string SAMID_STR = "AABBCCDD";

static const int AMOUNT = -2;
static const std::vector<uint8_t> DATE = HexUtil::toByteArray(DATE_STR);
static const std::vector<uint8_t> TIME = HexUtil::toByteArray(TIME_STR);
static const uint8_t KVC = (uint8_t) 0x90;
static const std::vector<uint8_t> SAMID = HexUtil::toByteArray(SAMID_STR);
static const int SAM_TNUM = 0x123456;
static const int BALANCE = 0x445566;
static const int SV_TNUM = 0x7890;

static const std::string BALANCE_STR = StringUtils::format("%06X", BALANCE);
static const std::string SAM_TNUM_STR = StringUtils::format("%06X", SAM_TNUM);
static const std::string SV_TNUM_STR = StringUtils::format("%04X", SV_TNUM);

static void setUp()
{
    const std::vector<uint8_t> svGetDebitData = HexUtil::toByteArray(HEADER +
                                                                     AMOUNT_STR +
                                                                     DATE_STR +
                                                                     TIME_STR +
                                                                     KVC_STR +
                                                                     SAMID_STR +
                                                                     SAM_TNUM_STR +
                                                                     BALANCE_STR +
                                                                     SV_TNUM_STR);

    svDebitLogRecordAdapter = std::make_shared<SvDebitLogRecordAdapter>(svGetDebitData,
                                                                        static_cast<int>(HEADER.size() / 2));
}

static void tearDown()
{
    svDebitLogRecordAdapter.reset();
}

TEST(SvDebitLogRecordTest, getAmount_shouldReturnAmount)
{
    setUp();

    ASSERT_EQ(svDebitLogRecordAdapter->getAmount(), AMOUNT);

    tearDown();
}

TEST(SvDebitLogRecordTest, getBalance_shouldReturnBalance)
{
    setUp();

    ASSERT_EQ(svDebitLogRecordAdapter->getBalance(), BALANCE);

    tearDown();
}

TEST(SvDebitLogRecordTest, getDebitDate_shouldReturnDebitDate)
{
    setUp();

    ASSERT_EQ(svDebitLogRecordAdapter->getDebitDate(), DATE);

    tearDown();
}

TEST(SvDebitLogRecordTest, getDebitTime_shouldReturnDebitTime)
{
    setUp();

    ASSERT_EQ(svDebitLogRecordAdapter->getDebitTime(), TIME);

    tearDown();
}

TEST(SvDebitLogRecordTest, getKvc_shouldReturnKvc)
{
    setUp();

    ASSERT_EQ(svDebitLogRecordAdapter->getKvc(), KVC);

    tearDown();
}

TEST(SvDebitLogRecordTest, getSamId_shouldReturnSamId)
{
    setUp();

    ASSERT_EQ(svDebitLogRecordAdapter->getSamId(), SAMID);

    tearDown();
}

TEST(SvDebitLogRecordTest, getSamTNum_shouldReturnSamTNum)
{
    setUp();

    ASSERT_EQ(svDebitLogRecordAdapter->getSamTNum(), SAM_TNUM);

    tearDown();
}

TEST(SvDebitLogRecordTest, getSvTNum_shouldReturnSvTNum)
{
    setUp();

    ASSERT_EQ(svDebitLogRecordAdapter->getSvTNum(), SV_TNUM);

    tearDown();
}

TEST(SvDebitLogRecordTest, toString_shouldContainSamID)
{
    setUp();

    std::stringstream ss;
    ss << svDebitLogRecordAdapter;

    std::cout << svDebitLogRecordAdapter << std::endl;
    std::cout << ss.str() << std::endl;

    ASSERT_TRUE(StringUtils::contains(ss.str(), SAMID_STR));

    tearDown();
}
