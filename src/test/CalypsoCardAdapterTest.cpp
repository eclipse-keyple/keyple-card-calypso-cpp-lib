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

/* Keyple Card Calypso */
#include "CalypsoCardAdapter.h"

/* Keyple Core Service */
#include "ApduResponseAdapter.h"

/* Keyple Core Util */
#include "ByteArrayUtil.h"
#include "IllegalArgumentException.h"
#include "IllegalStateException.h"
#include "StringUtils.h"
#include "System.h"

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
    calypsoCardAdapter = std::make_shared<CalypsoCardAdapter>();
}

static void tearDown()
{
    calypsoCardAdapter.reset();
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
    const std::vector<uint8_t> dfName = ByteArrayUtil::fromHex(dfNameAsHexString);
    const std::vector<uint8_t> serialNumber = ByteArrayUtil::fromHex(serialNumberAsHexString);
    const std::vector<uint8_t> startupInfo = ByteArrayUtil::fromHex(startupInfoAsHexString);
    std::vector<uint8_t> selAppResponse(23 + dfName.size() + startupInfo.size());

    selAppResponse[0] = 0x6F;
    selAppResponse[1] = (11 + dfName.size() + serialNumber.size() + startupInfo.size());
    selAppResponse[2] = 0x84;
    selAppResponse[3] = (dfName.size());
    System::arraycopy(dfName, 0, selAppResponse, 4, dfName.size());
    selAppResponse[4 + dfName.size()] = 0xA5;
    selAppResponse[5 + dfName.size()] = (7 + serialNumber.size() + startupInfo.size());
    selAppResponse[6 + dfName.size()] = 0xBF;
    selAppResponse[7 + dfName.size()] = 0x0C;
    selAppResponse[8 + dfName.size()] = (4 + serialNumber.size() + startupInfo.size());
    selAppResponse[9 + dfName.size()] = 0xC7;
    selAppResponse[10 + dfName.size()] = (serialNumber.size());
    System::arraycopy(serialNumber, 0, selAppResponse, 11 + dfName.size(), 8);
    selAppResponse[19 + dfName.size()] = 0x53;
    selAppResponse[20 + dfName.size()] = (startupInfo.size());
    System::arraycopy(startupInfo, 0, selAppResponse, 21 + dfName.size(), startupInfo.size());
    selAppResponse[21 + dfName.size() + startupInfo.size()] = ((statusWord & 0xFF00) >> 8);
    selAppResponse[22 + dfName.size() + startupInfo.size()] = (statusWord & 0xFF);

    return std::make_shared<ApduResponseAdapter>(selAppResponse);
}

TEST(CalypsoCardAdapterTest, initializeWithPowerOnData_whenInconsistentData_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(calypsoCardAdapter->initializeWithPowerOnData(POWER_ON_DATA_BAD_LENGTH),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithPowerOnData_shouldInitPrimeRevision1ProductType)
{
    setUp();

    calypsoCardAdapter->initializeWithPowerOnData(POWER_ON_DATA);

    ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::PRIME_REVISION_1);
    ASSERT_FALSE(calypsoCardAdapter->isExtendedModeSupported());
    ASSERT_FALSE(calypsoCardAdapter->isSvFeatureAvailable());
    ASSERT_FALSE(calypsoCardAdapter->isPinFeatureAvailable());
    ASSERT_FALSE(calypsoCardAdapter->isPkiModeSupported());
    ASSERT_FALSE(calypsoCardAdapter->isDfInvalidated());
    ASSERT_TRUE(calypsoCardAdapter->isRatificationOnDeselectSupported());
    ASSERT_EQ(calypsoCardAdapter->getApplicationSerialNumber(),
              ByteArrayUtil::fromHex(CALYPSO_SERIAL_NUMBER));

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenBadFci_shouldThrowIAE)
{
    setUp();

    const auto selectApplicationResponse =
        std::make_shared<ApduResponseAdapter>(ByteArrayUtil::fromHex("1122339000"));

    EXPECT_THROW(calypsoCardAdapter->initializeWithFci(selectApplicationResponse),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_withEmptyFCI_shouldInitUnknownProductType)
{
    setUp();

    const auto selectApplicationResponse =
        std::make_shared<ApduResponseAdapter>(ByteArrayUtil::fromHex("9000"));

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::UNKNOWN);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenAppTypeIs_00_shouldThrowIAE)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_APP_TYPE_00,
                                       SW1SW2_OK);

    EXPECT_THROW(calypsoCardAdapter->initializeWithFci(selectApplicationResponse),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenAppTypeIs_FF_shouldInitUnknownProductType)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_APP_TYPE_FF,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::UNKNOWN);

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_01_and_1F_shouldInitPrimeRevision2ProductType)
{
    setUp();

    std::shared_ptr<ApduResponseApi> selectApplicationResponse;

    for (int appType = 1; appType <= 0x1F; appType++) {
        selectApplicationResponse =
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(),
                                                               appType),
                                           SW1SW2_OK);
        calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::PRIME_REVISION_2);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_20_and_89_shouldInitPrimeRevision3ProductType)
{
    setUp();

    std::shared_ptr<ApduResponseApi> selectApplicationResponse;

    for (int appType = 0x20; appType <= 0x89; appType++) {
        selectApplicationResponse =
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(),
                                                               appType),
                                           SW1SW2_OK);
        calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::PRIME_REVISION_3);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_90_and_97_shouldInitLightProductType)
{
    setUp();

    std::shared_ptr<ApduResponseApi> selectApplicationResponse;

    for (int appType = 0x90; appType <= 0x97; appType++) {
        selectApplicationResponse =
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(),
                                                               appType),
                                           SW1SW2_OK);
        calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::LIGHT);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_98_and_9F_shouldInitBasicProductType)
{
    setUp();

    std::shared_ptr<ApduResponseApi> selectApplicationResponse;

    for (int appType = 0x98; appType <= 0x9F; appType++) {
        selectApplicationResponse =
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           StringUtils::format(STARTUP_INFO_BASIC_APP_TYPE_XX.c_str(),
                                                               appType),
                                           SW1SW2_OK);
        calypsoCardAdapter->initializeWithFci(selectApplicationResponse);
        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::BASIC);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     initializeWithFci_whenAppTypeIsBetween_A0_and_FE_shouldInitPrimeRevision3ProductType)
{
    setUp();

    std::shared_ptr<ApduResponseApi> selectApplicationResponse;

    for (int appType = 0xA0; appType <= 0xFE; appType++) {
        selectApplicationResponse =
            buildSelectApplicationResponse(DF_NAME,
                                           CALYPSO_SERIAL_NUMBER,
                                           StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(),
                                                               appType),
                                           SW1SW2_OK);
        calypsoCardAdapter->initializeWithFci(selectApplicationResponse);
        ASSERT_EQ(calypsoCardAdapter->getProductType(), CalypsoCard::ProductType::PRIME_REVISION_3);
    }

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenStatusWord_9000_shouldInitNotInvalidated)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_FALSE(calypsoCardAdapter->isDfInvalidated());

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenStatusWord_6283_shouldInitInvalidated)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_INVALIDATED);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_TRUE(calypsoCardAdapter->isDfInvalidated());

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenSerialNumberNotHce_shouldInitHceFalse)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_FALSE(calypsoCardAdapter->isHce());

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenSerialNumberHce_shouldInitHceTrue)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER_HCE,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_TRUE(calypsoCardAdapter->isHce());

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenSessionModificationByteIsOutOfRangeInf_shouldIAE)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER_HCE,
                                       StringUtils::format(STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(),
                                                           0x05),
                                       SW1SW2_OK);

    EXPECT_THROW(calypsoCardAdapter->initializeWithFci(selectApplicationResponse),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenSessionModificationByteIsOutOfRangeSup_shouldIAE)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER_HCE,
                                       StringUtils::format(STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(),
                                                           0x38),
                                       SW1SW2_OK);

    EXPECT_THROW(calypsoCardAdapter->initializeWithFci(selectApplicationResponse),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenStartupInfoIsShorter_shouldThrowParsingException)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER_HCE,
                                       STARTUP_INFO_TOO_SHORT,
                                       SW1SW2_OK);

    EXPECT_THROW(calypsoCardAdapter->initializeWithFci(selectApplicationResponse),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenStartupInfoIsLarger_shouldProvideWholeData)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER_HCE,
                                       STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getStartupInfoRawData(),
              ByteArrayUtil::fromHex(STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE));

    tearDown();
}

TEST(CalypsoCardAdapterTest, initializeWithFci_whenTagsAreInADifferentOrder_shouldProvideSameResult)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        std::make_shared<ApduResponseAdapter>(
            ByteArrayUtil::fromHex(SELECT_APPLICATION_RESPONSE_DIFFERENT_TAGS_ORDER));

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getDfName(), ByteArrayUtil::fromHex(DF_NAME));
    ASSERT_EQ(calypsoCardAdapter->getCalypsoSerialNumberFull(),
              ByteArrayUtil::fromHex(CALYPSO_SERIAL_NUMBER));
    ASSERT_EQ(calypsoCardAdapter->getStartupInfoRawData(),
              ByteArrayUtil::fromHex(STARTUP_INFO_PRIME_REVISION_3));

    tearDown();
}

TEST(CalypsoCardAdapterTest, getPowerOnData_whenNotSet_shouldReturnNull)
{
    setUp();

    ASSERT_EQ(calypsoCardAdapter->getPowerOnData(), "");

    tearDown();
}

TEST(CalypsoCardAdapterTest, getPowerOnData_shouldReturnPowerOnData)
{
    setUp();

    calypsoCardAdapter->initializeWithPowerOnData(POWER_ON_DATA);

    ASSERT_EQ(calypsoCardAdapter->getPowerOnData(), POWER_ON_DATA);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSelectApplicationResponse_whenNotSet_shouldReturnEmpty)
{
    setUp();

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

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getSelectApplicationResponse(),
              selectApplicationResponse->getApdu());

    tearDown();
}

TEST(CalypsoCardAdapterTest, getDfName_shouldReturnDfNameFromFCI)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getDfName(), ByteArrayUtil::fromHex(DF_NAME));

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationSerialNumber_shouldReturnApplicationSerialNumberFromFCI)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getApplicationSerialNumber(),
              ByteArrayUtil::fromHex(CALYPSO_SERIAL_NUMBER));

    tearDown();
}

TEST(CalypsoCardAdapterTest, getStartupInfoRawData_shouldReturnFromFCI)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getStartupInfoRawData(),
              ByteArrayUtil::fromHex(STARTUP_INFO_PRIME_REVISION_3));

    tearDown();
}

TEST(CalypsoCardAdapterTest, isPinFeatureAvailable_whenAppTypeBit0IsNotSet_shouldReturnFalse)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_FALSE(calypsoCardAdapter->isPinFeatureAvailable());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isPinFeatureAvailable_whenAppTypeBit0IsSet_shouldReturnTrue)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3_PIN,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_TRUE(calypsoCardAdapter->isPinFeatureAvailable());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isSvFeatureAvailable_whenAppTypeBit1IsNotSet_shouldReturnFalse)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_FALSE(calypsoCardAdapter->isSvFeatureAvailable());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isSvFeatureAvailable_whenAppTypeBit1IsSet_shouldReturnTrue)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3_STORED_VALUE,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_TRUE(calypsoCardAdapter->isSvFeatureAvailable());

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     isRatificationOnDeselectSupported_whenAppTypeBit2IsNotSet_shouldReturnTrue)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_TRUE(calypsoCardAdapter->isRatificationOnDeselectSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest,
     isRatificationOnDeselectSupported_whenAppTypeBit2IsSet_shouldReturnFalse)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3_RATIFICATION_ON_DESELECT,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_FALSE(calypsoCardAdapter->isRatificationOnDeselectSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isExtendedModeSupported_whenAppTypeBit3IsNotSet_shouldReturnFalse)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_FALSE(calypsoCardAdapter->isExtendedModeSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isExtendedModeSupported_whenAppTypeBit3IsSet_shouldReturnTrue)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3_EXTENDED_MODE,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_TRUE(calypsoCardAdapter->isExtendedModeSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isPkiModeSupported_whenAppTypeBit4IsNotSet_shouldReturnFalse)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_FALSE(calypsoCardAdapter->isPkiModeSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, isPkiModeSupported_whenAppTypeBit4IsSet_shouldReturnTrue)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       STARTUP_INFO_PRIME_REVISION_3_PKI_MODE,
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_TRUE(calypsoCardAdapter->isPkiModeSupported());

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSessionModification_shouldReturnSessionModification)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(),
                                                           0x11),
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getSessionModification(), 0x11);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getPlatform_shouldReturnPlatformByte)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_PLATFORM_XX.c_str(), 0x22),
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getPlatform(), 0x22);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationType_shouldReturnApplicationType)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), 0x33),
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getApplicationType(), 0x33);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationSubType_whenValueIs00_shouldThrowIAE)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0x00),
                                       SW1SW2_OK);

    EXPECT_THROW(calypsoCardAdapter->initializeWithFci(selectApplicationResponse),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationSubType_whenValueIsFF_shouldThrowIAE)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0xFF),
                                       SW1SW2_OK);

    EXPECT_THROW(calypsoCardAdapter->initializeWithFci(selectApplicationResponse),
                 IllegalArgumentException);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getApplicationSubType_shouldReturnApplicationSubType)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0x44),
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getApplicationSubtype(), 0x44);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSoftwareIssuer_shouldReturnSoftwareIssuer)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_SOFTWARE_ISSUER_XX.c_str(),
                                                           0x55),
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getSoftwareIssuer(), 0x55);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSoftwareVersion_shouldReturnSoftwareVersion)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_SOFTWARE_VERSION_XX.c_str(),
                                                           0x66),
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getSoftwareVersion(), 0x66);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSoftwareRevision_shouldReturnSoftwareRevision)
{
    setUp();

    const std::shared_ptr<ApduResponseApi> selectApplicationResponse =
        buildSelectApplicationResponse(DF_NAME,
                                       CALYPSO_SERIAL_NUMBER,
                                       StringUtils::format(STARTUP_INFO_SOFTWARE_REVISION_XX.c_str(),
                                                           0x77),
                                       SW1SW2_OK);

    calypsoCardAdapter->initializeWithFci(selectApplicationResponse);

    ASSERT_EQ(calypsoCardAdapter->getSoftwareRevision(), 0x77);

    tearDown();
}

TEST(CalypsoCardAdapterTest, getSvBalance_whenNotSet_shouldThrowISE)
{
    setUp();

    EXPECT_THROW(calypsoCardAdapter->getSvBalance(), IllegalStateException);

    tearDown();
}
