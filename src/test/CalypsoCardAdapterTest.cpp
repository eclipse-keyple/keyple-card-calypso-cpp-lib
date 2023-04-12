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

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"

/* Keyple Core Service */
#include "ApduResponseAdapter.h"
#include "CardSelectionResponseAdapter.h"

/* Keyple Core Util */
#include "HexUtil.h"
#include "IllegalArgumentException.h"
#include "IllegalStateException.h"
#include "StringUtils.h"
#include "System.h"

/* Mock */
#include "CardSelectionResponseAdapterMock.h"

using namespace testing;

using namespace keyple::card::calypso;
using namespace keyple::core::service;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp;
using namespace keyple::core::util::cpp::exception;

static std::shared_ptr<CalypsoCardAdapter> calypsoCardAdapter;

static const std::string CALYPSO_SERIAL_NUMBER = "0000000012345678";
static const std::string CALYPSO_SERIAL_NUMBER_HCE = "12340080FEDCBA98";
static const std::string POWER_ON_DATA = "3B8F8001805A0A0103200311" +
                                         CALYPSO_SERIAL_NUMBER.substr(8) +
                                         "829000F7";
static const std::string POWER_ON_DATA_BAD_LENGTH = "3B8F8001805A0A010320031124B77FE7829000F700";
static const std::string DF_NAME = "315449432E49434131";
static const std::string STARTUP_INFO_PRIME_REVISION_2 = "0A3C1005141001";
static const std::string STARTUP_INFO_PRIME_REVISION_3 = "0A3C2005141001";
static const std::string STARTUP_INFO_TOO_SHORT = "0A3C20051410";
static const std::string STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE = "0A3C2005141001FF";
static const std::string STARTUP_INFO_PRIME_REVISION_3_PIN = "0A3C2105141001";
static const std::string STARTUP_INFO_PRIME_REVISION_3_STORED_VALUE = "0A3C2205141001";
static const std::string STARTUP_INFO_PRIME_REVISION_3_RATIFICATION_ON_DESELECT ="0A3C2405141001";
static const std::string STARTUP_INFO_PRIME_REVISION_3_EXTENDED_MODE = "0A3C2805141001";
static const std::string STARTUP_INFO_PRIME_REVISION_3_PKI_MODE = "0A3C3005141001";
static const std::string STARTUP_INFO_SESSION_MODIFICATION_XX = "%02X3C2005141001";
static const std::string STARTUP_INFO_PLATFORM_XX = "0A%02X2005141001";
static const std::string STARTUP_INFO_APP_TYPE_XX = "0A3C%02X05141001";
static const std::string STARTUP_INFO_BASIC_APP_TYPE_XX = "043C%02X05141001";
static const std::string STARTUP_INFO_SUBTYPE_XX = "0A3C20%02X141001";
static const std::string STARTUP_INFO_SOFTWARE_ISSUER_XX = "0A3C2005%02X1001";
static const std::string STARTUP_INFO_SOFTWARE_VERSION_XX = "0A3C200514%02X01";
static const std::string STARTUP_INFO_SOFTWARE_REVISION_XX = "0A3C20051410%02X";
static const std::string STARTUP_INFO_APP_TYPE_00 = "0A3C0005141001";
static const std::string STARTUP_INFO_APP_TYPE_FF = "0A3CFF05141001";
static const int SW1SW2_OK = 0x9000;
static const int SW1SW2_INVALIDATED = 0x6283;
const std::string SELECT_APPLICATION_RESPONSE_DIFFERENT_TAGS_ORDER =
    "6F23A516BF0C1353070A3C2005141001C70800000000123456788409315449432E494341319000";

static void setUp()
{
}

static void tearDown()
{
    calypsoCardAdapter.reset();
}

static std::shared_ptr<CalypsoCardAdapter> buildCalypsoCard(const std::string& powerOnData)
{
    auto adapter = std::make_shared<CalypsoCardAdapter>();
    adapter->initialize(std::make_shared<CardSelectionResponseAdapterMock>(powerOnData));

    return adapter;
}

static std::shared_ptr<CalypsoCardAdapter> buildCalypsoCard(
    const std::shared_ptr<ApduResponseApi> apduResponse)
{
    auto adapter = std::make_shared<CalypsoCardAdapter>();
    adapter->initialize(std::make_shared<CardSelectionResponseAdapterMock>(apduResponse));

    return adapter;
}

/**
 * (private)<br>
 * Builds a simulated response to a Select Application command.
 *
 * @param dfNameAsHexString The DF Name.
 * @param serialNumberAsHexString The Calypso Serial Number.
 * @param startupInfoAsHexString The startup info data.
 * @param statusWord The status word.
 * @return The APDU response containing the FCI and the status word.
 */
static const std::shared_ptr<ApduResponseApi> buildSelectApplicationResponse(
    const std::string& dfNameAsHexString,
    const std::string& serialNumberAsHexString,
    const std::string& startupInfoAsHexString,
    const int statusWord)
{
    const std::vector<uint8_t> dfName = HexUtil::toByteArray(dfNameAsHexString);
    const std::vector<uint8_t> serialNumber = HexUtil::toByteArray(serialNumberAsHexString);
    const std::vector<uint8_t> startupInfo = HexUtil::toByteArray(startupInfoAsHexString);
    std::vector<uint8_t> selAppResponse(23 + dfName.size() + startupInfo.size());

    selAppResponse[0] = 0x6F;
    selAppResponse[1] = static_cast<uint8_t>(11 +
                                             dfName.size() +
                                             serialNumber.size() +
                                             startupInfo.size());
    selAppResponse[2] = 0x84;
    selAppResponse[3] = static_cast<uint8_t>(dfName.size());
    System::arraycopy(dfName, 0, selAppResponse, 4, dfName.size());
    selAppResponse[4 + dfName.size()] = 0xA5;
    selAppResponse[5 + dfName.size()] = static_cast<uint8_t>(7 +
                                                             serialNumber.size() +
                                                             startupInfo.size());
    selAppResponse[6 + dfName.size()] = 0xBF;
    selAppResponse[7 + dfName.size()] = 0x0C;
    selAppResponse[8 + dfName.size()] = static_cast<uint8_t>(4 +
                                                             serialNumber.size() +
                                                             startupInfo.size());
    selAppResponse[9 + dfName.size()] = 0xC7;
    selAppResponse[10 + dfName.size()] = static_cast<uint8_t>(serialNumber.size());
    System::arraycopy(serialNumber, 0, selAppResponse, 11 + dfName.size(), 8);
    selAppResponse[19 + dfName.size()] = 0x53;
    selAppResponse[20 + dfName.size()] = static_cast<uint8_t>(startupInfo.size());
    System::arraycopy(startupInfo, 0, selAppResponse, 21 + dfName.size(), startupInfo.size());
    selAppResponse[21 + dfName.size() + startupInfo.size()] = ((statusWord & 0xFF00) >> 8);
    selAppResponse[22 + dfName.size() + startupInfo.size()] = (statusWord & 0xFF);

    return std::make_shared<ApduResponseAdapter>(selAppResponse);
}

TEST(CalypsoCardAdapterTest, initializeWithPowerOnData_whenInconsistentData_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(buildCalypsoCard(POWER_ON_DATA_BAD_LENGTH), IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithPowerOnData_shouldInitPrimeRevision1ProductType)
{
    setUp();

    calypsoCardAdapter = buildCalypsoCard(POWER_ON_DATA);

    ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::PRIME_REVISION_1);
    ASSERT_FALSE(calypsoCardAdapter->isExtendedModeSupported());
    ASSERT_FALSE(calypsoCardAdapter->isSvFeatureAvailable());
    ASSERT_FALSE(calypsoCardAdapter->isPinFeatureAvailable());
    ASSERT_FALSE(calypsoCardAdapter->isPkiModeSupported());
    ASSERT_FALSE(calypsoCardAdapter->isDfInvalidated());
    ASSERT_TRUE(calypsoCardAdapter->isRatificationOnDeselectSupported());
    ASSERT_EQ(calypsoCardAdapter->getApplicationSerialNumber(),
              HexUtil::toByteArray(CALYPSO_SERIAL_NUMBER));

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenBadFci_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(
        buildCalypsoCard(std::make_shared<ApduResponseAdapter>(HexUtil::toByteArray("1122339000"))),
        IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_withEmptyFCI_shouldInitUnknownProductType)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(std::make_shared<ApduResponseAdapter>(HexUtil::toByteArray("9000")));

    ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::UNKNOWN);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenAppTypeIs_00_shouldThrowIAE)
{
    setUp();


    EXPECT_THROW(
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME, CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_APP_TYPE_00, SW1SW2_OK)),
        IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenAppTypeIs_FF_shouldInitUnknownProductType)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME, CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_APP_TYPE_FF, SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::UNKNOWN);

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_01_and_1F_shouldInitPrimeRevision2ProductType)
{
    setUp();

    for (int appType = 1; appType <= 0x1F; appType++) {

        calypsoCardAdapter =
            buildCalypsoCard(
                buildSelectApplicationResponse(
                    DF_NAME,
                    CALYPSO_SERIAL_NUMBER,
                    StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), appType),
                    SW1SW2_OK));

        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::PRIME_REVISION_2);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_20_and_89_shouldInitPrimeRevision3ProductType)
{
    setUp();

    for (int appType = 0x20; appType <= 0x89; appType++) {

        calypsoCardAdapter =
            buildCalypsoCard(
                buildSelectApplicationResponse(
                    DF_NAME,
                    CALYPSO_SERIAL_NUMBER,
                    StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), appType),
                    SW1SW2_OK));

        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::PRIME_REVISION_3);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_90_and_97_shouldInitLightProductType)
{
    setUp();

    for (int appType = 0x90; appType <= 0x97; appType++) {

        calypsoCardAdapter =
            buildCalypsoCard(
                buildSelectApplicationResponse(
                    DF_NAME,
                    CALYPSO_SERIAL_NUMBER,
                    StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), appType),
                    SW1SW2_OK));

        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::LIGHT);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_98_and_9F_shouldInitBasicProductType)
{
    setUp();

    for (int appType = 0x98; appType <= 0x9F; appType++) {

        calypsoCardAdapter =
            buildCalypsoCard(
                buildSelectApplicationResponse(
                    DF_NAME,
                    CALYPSO_SERIAL_NUMBER,
                    StringUtils::format(STARTUP_INFO_BASIC_APP_TYPE_XX.c_str(), appType),
                    SW1SW2_OK));

        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::BASIC);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_A0_and_FE_shouldInitPrimeRevision3ProductType)
{
    setUp();

    for (int appType = 0xA0; appType <= 0xFE; appType++) {

        calypsoCardAdapter =
            buildCalypsoCard(
                buildSelectApplicationResponse(
                    DF_NAME,
                    CALYPSO_SERIAL_NUMBER,
                    StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), appType),
                    SW1SW2_OK));

        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::PRIME_REVISION_3);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenStatusWord_9000_shouldInitNotInvalidated)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME, CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isDfInvalidated());

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenStatusWord_6283_shouldInitInvalidated)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_INVALIDATED));

    ASSERT_TRUE(calypsoCardAdapter->isDfInvalidated());

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenSerialNumberNotHce_shouldInitHceFalse)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME, CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isHce());

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenSerialNumberHce_shouldInitHceTrue)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER_HCE,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isHce());

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenSessionModificationByteIsOutOfRangeInf_shouldIAE)
{
    setUp();

    EXPECT_THROW(
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER_HCE,
                StringUtils::format(STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(), 0x05),
                SW1SW2_OK)),
        IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenSessionModificationByteIsOutOfRangeSup_shouldIAE)
{
    setUp();

    EXPECT_THROW(
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER_HCE,
                StringUtils::format(STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(), 0x38),
                SW1SW2_OK)),
        IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenStartupInfoIsShorter_shouldThrowParsingException)
{
    setUp();

    EXPECT_THROW(
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER_HCE,
                                           STARTUP_INFO_TOO_SHORT, SW1SW2_OK)),
        IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenStartupInfoIsLarger_shouldProvideWholeData)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER_HCE,
                                           STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE,
                                           SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getStartupInfoRawData(),
              HexUtil::toByteArray(STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE));

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenTagsAreInADifferentOrder_shouldProvideSameResult)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            std::make_shared<ApduResponseAdapter>(
                HexUtil::toByteArray(SELECT_APPLICATION_RESPONSE_DIFFERENT_TAGS_ORDER)));

    ASSERT_EQ(calypsoCardAdapter->getDfName(), HexUtil::toByteArray(DF_NAME));
    ASSERT_EQ(calypsoCardAdapter->getCalypsoSerialNumberFull(),
              HexUtil::toByteArray(CALYPSO_SERIAL_NUMBER));
    ASSERT_EQ(calypsoCardAdapter->getStartupInfoRawData(),
              HexUtil::toByteArray(STARTUP_INFO_PRIME_REVISION_3));

    tearDown();
}

TEST(CalypsoCardAdapterTest, getPowerOnData_whenNotSet_shouldReturnNull)
{
    setUp();

    calypsoCardAdapter = buildCalypsoCard("");

    ASSERT_EQ(calypsoCardAdapter->getPowerOnData(), "");

    tearDown();
}

TEST(CalypsoCardAdapterTest, getPowerOnData_shouldReturnPowerOnData)
{
    setUp();

    calypsoCardAdapter = buildCalypsoCard(POWER_ON_DATA);

    ASSERT_EQ(calypsoCardAdapter->getPowerOnData(), POWER_ON_DATA);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSelectApplicationResponse_whenNotSet_shouldReturnEmpty)
{
    setUp();

    calypsoCardAdapter = buildCalypsoCard((const std::shared_ptr<ApduResponseApi>)nullptr);

    ASSERT_EQ(calypsoCardAdapter->getSelectApplicationResponse().size(), 0);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSelectApplicationResponse_shouldSelectApplicationResponse)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter = buildCalypsoCard(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getSelectApplicationResponse(),
              selectApplicationResponse->getApdu());

    tearDown();
}

TEST(CalypsoCardAdapterTest, getDfName_shouldReturnDfNameFromFCI)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getDfName(), HexUtil::toByteArray(DF_NAME));

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationSerialNumber_shouldReturnApplicationSerialNumberFromFCI)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getApplicationSerialNumber(),
              HexUtil::toByteArray(CALYPSO_SERIAL_NUMBER));

    tearDown();
}

TEST(CalypsoCardAdapterTest, getStartupInfoRawData_shouldReturnFromFCI)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getStartupInfoRawData(),
              HexUtil::toByteArray(STARTUP_INFO_PRIME_REVISION_3));

    tearDown();
}

TEST(CalypsoCardAdapterTest, isPinFeatureAvailable_whenAppTypeBit0IsNotSet_shouldReturnFalse)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isPinFeatureAvailable());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isPinFeatureAvailable_whenAppTypeBit0IsSet_shouldReturnTrue)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3_PIN,
                                           SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isPinFeatureAvailable());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isSvFeatureAvailable_whenAppTypeBit1IsNotSet_shouldReturnFalse)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isSvFeatureAvailable());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isSvFeatureAvailable_whenAppTypeBit1IsSet_shouldReturnTrue)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3_STORED_VALUE,
                                           SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isSvFeatureAvailable());

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     isRatificationOnDeselectSupported_whenAppTypeBit2IsNotSet_shouldReturnTrue)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isRatificationOnDeselectSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     isRatificationOnDeselectSupported_whenAppTypeBit2IsSet_shouldReturnFalse)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                STARTUP_INFO_PRIME_REVISION_3_RATIFICATION_ON_DESELECT,
                SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isRatificationOnDeselectSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isExtendedModeSupported_whenAppTypeBit3IsNotSet_shouldReturnFalse)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isExtendedModeSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isExtendedModeSupported_whenAppTypeBit3IsSet_shouldReturnTrue)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3_EXTENDED_MODE,
                                           SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isExtendedModeSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isPkiModeSupported_whenAppTypeBit4IsNotSet_shouldReturnFalse)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3,
                                           SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isPkiModeSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isPkiModeSupported_whenAppTypeBit4IsSet_shouldReturnTrue)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           STARTUP_INFO_PRIME_REVISION_3_PKI_MODE,
                                           SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isPkiModeSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSessionModification_shouldReturnSessionModification)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(), 0x11),
                SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getSessionModification(), 0x11);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getPlatform_shouldReturnPlatformByte)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_PLATFORM_XX.c_str(), 0x22),
                SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getPlatform(), 0x22);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationType_shouldReturnApplicationType)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), 0x33),
                SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getApplicationType(), 0x33);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationSubType_whenValueIs00_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0x00),
                SW1SW2_OK)),
        IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationSubType_whenValueIsFF_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0xFF),
                SW1SW2_OK)),
        IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationSubType_shouldReturnApplicationSubType)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0x44),
                SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getApplicationSubtype(), 0x44);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSoftwareIssuer_shouldReturnSoftwareIssuer)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_SOFTWARE_ISSUER_XX.c_str(), 0x55),
                SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getSoftwareIssuer(), 0x55);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSoftwareVersion_shouldReturnSoftwareVersion)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_SOFTWARE_VERSION_XX.c_str(), 0x66),
                SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getSoftwareVersion(), 0x66);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSoftwareRevision_shouldReturnSoftwareRevision)
{
    setUp();

    calypsoCardAdapter =
        buildCalypsoCard(
            buildSelectApplicationResponse(
                DF_NAME,
                CALYPSO_SERIAL_NUMBER,
                StringUtils::format(STARTUP_INFO_SOFTWARE_REVISION_XX.c_str(), 0x77),
                SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getSoftwareRevision(), 0x77);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSvBalance_whenNotSet_shouldThrowISE)
{
    setUp();

    calypsoCardAdapter = buildCalypsoCard((const std::shared_ptr<ApduResponseApi>)nullptr);

    EXPECT_THROW(calypsoCardAdapter->getSvBalance(), IllegalStateException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, isDfRatified_whenNoSessionWasOpened_shouldThrowISE)
{
    setUp();

    calypsoCardAdapter = buildCalypsoCard((const std::shared_ptr<ApduResponseApi>)nullptr);

    EXPECT_THROW(calypsoCardAdapter->isDfRatified(), IllegalStateException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getTransactionCounter_whenNoSessionWasOpened_shouldThrowISE)
{
    setUp();

    calypsoCardAdapter = buildCalypsoCard((const std::shared_ptr<ApduResponseApi>)nullptr);

    EXPECT_THROW(calypsoCardAdapter->getTransactionCounter(), IllegalStateException);

    tearDown();
}
