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
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"
#include "keyple/core/util/cpp/StringUtils.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/card/CalypsoCard.hpp"

#include "mock/CardSelectionResponseAdapterMock.hpp"

using keyple::card::calypso::CalypsoCardAdapter;
using keyple::core::util::cpp::StringUtils;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::card::CalypsoCard;

const std::string CALYPSO_SERIAL_NUMBER = "0000000012345678";
const std::string CALYPSO_SERIAL_NUMBER_HCE = "12340080FEDCBA98";
const std::string POWER_ON_DATA
    = "3B8F8001805A0A0103200311" + CALYPSO_SERIAL_NUMBER.substr(8) + "829000F7";
const std::string POWER_ON_DATA_BAD_LENGTH
    = "3B8F8001805A0A010320031124B77FE7829000F700";
const std::string DF_NAME = "315449432E49434131";
const std::string STARTUP_INFO_PRIME_REVISION_2 = "0A3C1005141001";
const std::string STARTUP_INFO_PRIME_REVISION_3 = "0A3C2005141001";
const std::string STARTUP_INFO_TOO_SHORT = "0A3C20051410";
const std::string STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE = "0A3C2005141001FF";
const std::string STARTUP_INFO_PRIME_REVISION_3_PIN = "0A3C2105141001";
const std::string STARTUP_INFO_PRIME_REVISION_3_STORED_VALUE = "0A3C2205141001";
const std::string STARTUP_INFO_PRIME_REVISION_3_RATIFICATION_ON_DESELECT
    = "0A3C2405141001";
const std::string STARTUP_INFO_PRIME_REVISION_3_EXTENDED_MODE
    = "0A3C2805141001";
const std::string STARTUP_INFO_PRIME_REVISION_3_PKI_MODE = "0A3C3005141001";
const std::string STARTUP_INFO_SESSION_MODIFICATION_XX = "%02X3C2005141001";
const std::string STARTUP_INFO_PLATFORM_XX = "0A%02X2005141001";
const std::string STARTUP_INFO_APP_TYPE_XX = "0A3C%02X05141001";
const std::string STARTUP_INFO_BASIC_APP_TYPE_XX = "043C%02X05141001";
const std::string STARTUP_INFO_SUBTYPE_XX = "0A3C20%02X141001";
const std::string STARTUP_INFO_SOFTWARE_ISSUER_XX = "0A3C2005%02X1001";
const std::string STARTUP_INFO_SOFTWARE_VERSION_XX = "0A3C200514%02X01";
const std::string STARTUP_INFO_SOFTWARE_REVISION_XX = "0A3C20051410%02X";
const std::string STARTUP_INFO_APP_TYPE_00 = "0A3C0005141001";
const std::string STARTUP_INFO_APP_TYPE_FF = "0A3CFF05141001";
const int SW1SW2_OK = 0x9000;
const int SW1SW2_INVALIDATED = 0x6283;
const std::string SELECT_APPLICATION_RESPONSE_DIFFERENT_TAGS_ORDER
    = "6F23A516BF0C1353070A3C2005141001C70800000000123456788409315449432E494341"
      "319000";

class CalypsoCardAdapterTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
    }

    void
    TearDown() override
    {
        calypsoCardAdapter.reset();
    }

    std::shared_ptr<CalypsoCardAdapter> calypsoCardAdapter;
};

std::shared_ptr<CalypsoCardAdapter>
buildCalypsoCard(const std::string& powerOnData)
{
    auto adapter = std::make_shared<CalypsoCardAdapter>();
    adapter->initialize(
        std::make_shared<CardSelectionResponseAdapterMock>(powerOnData));

    return adapter;
}

std::shared_ptr<CalypsoCardAdapter>
buildCalypsoCard(const std::shared_ptr<ApduResponseApi> apduResponse)
{
    auto adapter = std::make_shared<CalypsoCardAdapter>();
    adapter->initialize(
        std::make_shared<CardSelectionResponseAdapterMock>(apduResponse));

    return adapter;
}

/**
 * Builds a simulated response to a Select Application command.
 *
 * @param dfNameAsHexString The DF Name.
 * @param serialNumberAsHexString The Calypso Serial Number.
 * @param startupInfoAsHexString The startup info data.
 * @param statusWord The status word.
 * @return The APDU response containing the FCI and the status word.
 */
const std::shared_ptr<ApduResponseApi>
buildSelectApplicationResponse(
    const std::string& dfNameAsHexString,
    const std::string& serialNumberAsHexString,
    const std::string& startupInfoAsHexString,
    const int statusWord)
{
    const std::vector<uint8_t> dfName = HexUtil::toByteArray(dfNameAsHexString);
    const std::vector<uint8_t> serialNumber
        = HexUtil::toByteArray(serialNumberAsHexString);
    const std::vector<uint8_t> startupInfo
        = HexUtil::toByteArray(startupInfoAsHexString);
    std::vector<uint8_t> selAppResponse(
        23 + dfName.size() + startupInfo.size());

    selAppResponse[0] = 0x6F;
    selAppResponse[1] = static_cast<uint8_t>(
        11 + dfName.size() + serialNumber.size() + startupInfo.size());
    selAppResponse[2] = 0x84;
    selAppResponse[3] = static_cast<uint8_t>(dfName.size());
    System::arraycopy(dfName, 0, selAppResponse, 4, dfName.size());
    selAppResponse[4 + dfName.size()] = 0xA5;
    selAppResponse[5 + dfName.size()]
        = static_cast<uint8_t>(7 + serialNumber.size() + startupInfo.size());
    selAppResponse[6 + dfName.size()] = 0xBF;
    selAppResponse[7 + dfName.size()] = 0x0C;
    selAppResponse[8 + dfName.size()]
        = static_cast<uint8_t>(4 + serialNumber.size() + startupInfo.size());
    selAppResponse[9 + dfName.size()] = 0xC7;
    selAppResponse[10 + dfName.size()]
        = static_cast<uint8_t>(serialNumber.size());
    System::arraycopy(serialNumber, 0, selAppResponse, 11 + dfName.size(), 8);
    selAppResponse[19 + dfName.size()] = 0x53;
    selAppResponse[20 + dfName.size()]
        = static_cast<uint8_t>(startupInfo.size());
    System::arraycopy(
        startupInfo, 0, selAppResponse, 21 + dfName.size(), startupInfo.size());
    selAppResponse[21 + dfName.size() + startupInfo.size()]
        = ((statusWord & 0xFF00) >> 8);
    selAppResponse[22 + dfName.size() + startupInfo.size()]
        = (statusWord & 0xFF);

    return std::make_shared<ApduResponseAdapter>(selAppResponse);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithPowerOnData_whenInconsistentData_shouldThrowIAE)
{
    EXPECT_THROW(
        buildCalypsoCard(POWER_ON_DATA_BAD_LENGTH), IllegalArgumentException);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithPowerOnData_shouldInitPrimeRevision1ProductType)
{
    calypsoCardAdapter = buildCalypsoCard(POWER_ON_DATA);

    ASSERT_EQ(
        calypsoCardAdapter->getProductType(),
        CalypsoCard::ProductType::PRIME_REVISION_1);
    ASSERT_FALSE(calypsoCardAdapter->isExtendedModeSupported());
    ASSERT_FALSE(calypsoCardAdapter->isSvFeatureAvailable());
    ASSERT_FALSE(calypsoCardAdapter->isPinFeatureAvailable());
    ASSERT_FALSE(calypsoCardAdapter->isPkiModeSupported());
    ASSERT_FALSE(calypsoCardAdapter->isDfInvalidated());
    ASSERT_TRUE(calypsoCardAdapter->isRatificationOnDeselectSupported());
    ASSERT_EQ(
        calypsoCardAdapter->getApplicationSerialNumber(),
        HexUtil::toByteArray(CALYPSO_SERIAL_NUMBER));
}

TEST_F(CalypsoCardAdapterTest, initializeWithFci_whenBadFci_shouldThrowIAE)
{
    EXPECT_THROW(
        buildCalypsoCard(
            std::make_shared<ApduResponseAdapter>(
                HexUtil::toByteArray("1122339000"))),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_withEmptyFCI_shouldInitUnknownProductType)
{
    calypsoCardAdapter = buildCalypsoCard(
        std::make_shared<ApduResponseAdapter>(HexUtil::toByteArray("9000")));

    ASSERT_EQ(
        calypsoCardAdapter->getProductType(),
        CalypsoCard::ProductType::UNKNOWN);
}

TEST_F(
    CalypsoCardAdapterTest, initializeWithFci_whenAppTypeIs_00_shouldThrowIAE)
{
    EXPECT_THROW(
        buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            STARTUP_INFO_APP_TYPE_00,
            SW1SW2_OK)),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenAppTypeIs_FF_shouldInitUnknownProductType)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME, CALYPSO_SERIAL_NUMBER, STARTUP_INFO_APP_TYPE_FF, SW1SW2_OK));

    ASSERT_EQ(
        calypsoCardAdapter->getProductType(),
        CalypsoCard::ProductType::UNKNOWN);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenAppTypeIsBetween_01_and_1F_shouldInitPrimeRevision2ProductType)  // NOLINT
{
    for (int appType = 1; appType <= 0x1F; appType++) {
        calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), appType),
            SW1SW2_OK));

        ASSERT_EQ(
            calypsoCardAdapter->getProductType(),
            CalypsoCard::ProductType::PRIME_REVISION_2);
    }
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenAppTypeIsBetween_20_and_89_shouldInitPrimeRevision3ProductType)  // NOLINT
{
    for (int appType = 0x20; appType <= 0x89; appType++) {
        calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), appType),
            SW1SW2_OK));

        ASSERT_EQ(
            calypsoCardAdapter->getProductType(),
            CalypsoCard::ProductType::PRIME_REVISION_3);
    }
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenAppTypeIsBetween_90_and_97_shouldInitLightProductType)
{
    for (int appType = 0x90; appType <= 0x97; appType++) {
        calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), appType),
            SW1SW2_OK));

        ASSERT_EQ(
            calypsoCardAdapter->getProductType(),
            CalypsoCard::ProductType::LIGHT);
    }
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenAppTypeIsBetween_98_and_9F_shouldInitBasicProductType)
{
    for (int appType = 0x98; appType <= 0x9F; appType++) {
        calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            StringUtils::format(
                STARTUP_INFO_BASIC_APP_TYPE_XX.c_str(), appType),
            SW1SW2_OK));

        ASSERT_EQ(
            calypsoCardAdapter->getProductType(),
            CalypsoCard::ProductType::BASIC);
    }
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenAppTypeIsBetween_A0_and_FE_shouldInitPrimeRevision3ProductType)  // NOLINT
{
    for (int appType = 0xA0; appType <= 0xFE; appType++) {
        calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), appType),
            SW1SW2_OK));

        ASSERT_EQ(
            calypsoCardAdapter->getProductType(),
            CalypsoCard::ProductType::PRIME_REVISION_3);
    }
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenStatusWord_9000_shouldInitNotInvalidated)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isDfInvalidated());
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenStatusWord_6283_shouldInitInvalidated)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_INVALIDATED));

    ASSERT_TRUE(calypsoCardAdapter->isDfInvalidated());
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenSerialNumberNotHce_shouldInitHceFalse)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isHce());
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenSerialNumberHce_shouldInitHceTrue)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER_HCE,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isHce());
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenSessionModificationByteIsOutOfRangeInf_shouldIAE)
{
    EXPECT_THROW(
        buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER_HCE,
            StringUtils::format(
                STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(), 0x05),
            SW1SW2_OK)),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenSessionModificationByteIsOutOfRangeSup_shouldIAE)
{
    EXPECT_THROW(
        buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER_HCE,
            StringUtils::format(
                STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(), 0x38),
            SW1SW2_OK)),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenStartupInfoIsShorter_shouldThrowParsingException)
{
    EXPECT_THROW(
        buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER_HCE,
            STARTUP_INFO_TOO_SHORT,
            SW1SW2_OK)),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenStartupInfoIsLarger_shouldProvideWholeData)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER_HCE,
        STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE,
        SW1SW2_OK));

    ASSERT_EQ(
        calypsoCardAdapter->getStartupInfoRawData(),
        HexUtil::toByteArray(STARTUP_INFO_PRIME_REVISION_3_EXTRA_BYTE));
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenTagsAreInADifferentOrder_shouldProvideSameResult)
{
    calypsoCardAdapter = buildCalypsoCard(
        std::make_shared<ApduResponseAdapter>(HexUtil::toByteArray(
            SELECT_APPLICATION_RESPONSE_DIFFERENT_TAGS_ORDER)));

    ASSERT_EQ(calypsoCardAdapter->getDfName(), HexUtil::toByteArray(DF_NAME));
    ASSERT_EQ(
        calypsoCardAdapter->getCalypsoSerialNumberFull(),
        HexUtil::toByteArray(CALYPSO_SERIAL_NUMBER));
    ASSERT_EQ(
        calypsoCardAdapter->getStartupInfoRawData(),
        HexUtil::toByteArray(STARTUP_INFO_PRIME_REVISION_3));
}

TEST_F(CalypsoCardAdapterTest, getPowerOnData_whenNotSet_shouldReturnNull)
{
    calypsoCardAdapter = buildCalypsoCard("");

    ASSERT_EQ(calypsoCardAdapter->getPowerOnData(), "");
}

TEST_F(CalypsoCardAdapterTest, getPowerOnData_shouldReturnPowerOnData)
{
    calypsoCardAdapter = buildCalypsoCard(POWER_ON_DATA);

    ASSERT_EQ(calypsoCardAdapter->getPowerOnData(), POWER_ON_DATA);
}

TEST_F(
    CalypsoCardAdapterTest,
    getSelectApplicationResponse_whenNotSet_shouldReturnEmpty)
{
    calypsoCardAdapter
        = buildCalypsoCard((const std::shared_ptr<ApduResponseApi>)nullptr);

    ASSERT_EQ(calypsoCardAdapter->getSelectApplicationResponse().size(), 0);
}

TEST_F(
    CalypsoCardAdapterTest,
    getSelectApplicationResponse_shouldSelectApplicationResponse)
{
    const std::shared_ptr<ApduResponseApi> selectApplicationResponse
        = buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            STARTUP_INFO_PRIME_REVISION_3,
            SW1SW2_OK);

    calypsoCardAdapter = buildCalypsoCard(selectApplicationResponse);

    ASSERT_EQ(
        calypsoCardAdapter->getSelectApplicationResponse(),
        selectApplicationResponse->getApdu());
}

TEST_F(CalypsoCardAdapterTest, getDfName_shouldReturnDfNameFromFCI)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getDfName(), HexUtil::toByteArray(DF_NAME));
}

TEST_F(
    CalypsoCardAdapterTest,
    getApplicationSerialNumber_shouldReturnApplicationSerialNumberFromFCI)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_EQ(
        calypsoCardAdapter->getApplicationSerialNumber(),
        HexUtil::toByteArray(CALYPSO_SERIAL_NUMBER));
}

TEST_F(CalypsoCardAdapterTest, getStartupInfoRawData_shouldReturnFromFCI)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_EQ(
        calypsoCardAdapter->getStartupInfoRawData(),
        HexUtil::toByteArray(STARTUP_INFO_PRIME_REVISION_3));
}

TEST_F(
    CalypsoCardAdapterTest,
    isPinFeatureAvailable_whenAppTypeBit0IsNotSet_shouldReturnFalse)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isPinFeatureAvailable());
}

TEST_F(
    CalypsoCardAdapterTest,
    isPinFeatureAvailable_whenAppTypeBit0IsSet_shouldReturnTrue)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3_PIN,
        SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isPinFeatureAvailable());
}

TEST_F(
    CalypsoCardAdapterTest,
    isSvFeatureAvailable_whenAppTypeBit1IsNotSet_shouldReturnFalse)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isSvFeatureAvailable());
}

TEST_F(
    CalypsoCardAdapterTest,
    isSvFeatureAvailable_whenAppTypeBit1IsSet_shouldReturnTrue)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3_STORED_VALUE,
        SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isSvFeatureAvailable());
}

TEST_F(
    CalypsoCardAdapterTest,
    isRatificationOnDeselectSupported_whenAppTypeBit2IsNotSet_shouldReturnTrue)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isRatificationOnDeselectSupported());
}

TEST_F(
    CalypsoCardAdapterTest,
    isRatificationOnDeselectSupported_whenAppTypeBit2IsSet_shouldReturnFalse)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3_RATIFICATION_ON_DESELECT,
        SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isRatificationOnDeselectSupported());
}

TEST_F(
    CalypsoCardAdapterTest,
    isExtendedModeSupported_whenAppTypeBit3IsNotSet_shouldReturnFalse)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isExtendedModeSupported());
}

TEST_F(
    CalypsoCardAdapterTest,
    isExtendedModeSupported_whenAppTypeBit3IsSet_shouldReturnTrue)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3_EXTENDED_MODE,
        SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isExtendedModeSupported());
}

TEST_F(
    CalypsoCardAdapterTest,
    isPkiModeSupported_whenAppTypeBit4IsNotSet_shouldReturnFalse)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));

    ASSERT_FALSE(calypsoCardAdapter->isPkiModeSupported());
}

TEST_F(
    CalypsoCardAdapterTest,
    isPkiModeSupported_whenAppTypeBit4IsSet_shouldReturnTrue)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3_PKI_MODE,
        SW1SW2_OK));

    ASSERT_TRUE(calypsoCardAdapter->isPkiModeSupported());
}

TEST_F(
    CalypsoCardAdapterTest,
    getSessionModification_shouldReturnSessionModification)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        StringUtils::format(STARTUP_INFO_SESSION_MODIFICATION_XX.c_str(), 0x11),
        SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getSessionModification(), 0x11);
}

TEST_F(CalypsoCardAdapterTest, getPlatform_shouldReturnPlatformByte)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        StringUtils::format(STARTUP_INFO_PLATFORM_XX.c_str(), 0x22),
        SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getPlatform(), 0x22);
}

TEST_F(CalypsoCardAdapterTest, getApplicationType_shouldReturnApplicationType)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        StringUtils::format(STARTUP_INFO_APP_TYPE_XX.c_str(), 0x33),
        SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getApplicationType(), 0x33);
}

TEST_F(
    CalypsoCardAdapterTest, getApplicationSubType_whenValueIs00_shouldThrowIAE)
{
    EXPECT_THROW(
        buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0x00),
            SW1SW2_OK)),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardAdapterTest, getApplicationSubType_whenValueIsFF_shouldThrowIAE)
{
    EXPECT_THROW(
        buildCalypsoCard(buildSelectApplicationResponse(
            DF_NAME,
            CALYPSO_SERIAL_NUMBER,
            StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0xFF),
            SW1SW2_OK)),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardAdapterTest,
    getApplicationSubType_shouldReturnApplicationSubType)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        StringUtils::format(STARTUP_INFO_SUBTYPE_XX.c_str(), 0x44),
        SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getApplicationSubtype(), 0x44);
}

TEST_F(CalypsoCardAdapterTest, getSoftwareIssuer_shouldReturnSoftwareIssuer)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        StringUtils::format(STARTUP_INFO_SOFTWARE_ISSUER_XX.c_str(), 0x55),
        SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getSoftwareIssuer(), 0x55);
}

TEST_F(CalypsoCardAdapterTest, getSoftwareVersion_shouldReturnSoftwareVersion)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        StringUtils::format(STARTUP_INFO_SOFTWARE_VERSION_XX.c_str(), 0x66),
        SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getSoftwareVersion(), 0x66);
}

TEST_F(CalypsoCardAdapterTest, getSoftwareRevision_shouldReturnSoftwareRevision)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        StringUtils::format(STARTUP_INFO_SOFTWARE_REVISION_XX.c_str(), 0x77),
        SW1SW2_OK));

    ASSERT_EQ(calypsoCardAdapter->getSoftwareRevision(), 0x77);
}

TEST_F(CalypsoCardAdapterTest, getSvBalance_whenNotSet_shouldThrowISE)
{
    calypsoCardAdapter
        = buildCalypsoCard((const std::shared_ptr<ApduResponseApi>)nullptr);

    EXPECT_THROW(calypsoCardAdapter->getSvBalance(), IllegalStateException);
}

TEST_F(
    CalypsoCardAdapterTest, isDfRatified_whenNoSessionWasOpened_shouldThrowISE)
{
    calypsoCardAdapter
        = buildCalypsoCard((const std::shared_ptr<ApduResponseApi>)nullptr);

    EXPECT_THROW(calypsoCardAdapter->isDfRatified(), IllegalStateException);
}

TEST_F(
    CalypsoCardAdapterTest,
    getTransactionCounter_whenNoSessionWasOpened_shouldThrowISE)
{
    calypsoCardAdapter
        = buildCalypsoCard((const std::shared_ptr<ApduResponseApi>)nullptr);

    EXPECT_THROW(
        calypsoCardAdapter->getTransactionCounter(), IllegalStateException);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenPrimeRevision3_shouldInitCounterValuePostponedToFalse)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_3,
        SW1SW2_OK));
    ASSERT_FALSE(*(calypsoCardAdapter->getIsCounterValuePostponed()));
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithFci_whenPrimeRevision2_shouldKeepCounterValuePostponedNull)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_2,
        SW1SW2_OK));
    ASSERT_EQ(calypsoCardAdapter->getIsCounterValuePostponed(), nullptr);
}

TEST_F(
    CalypsoCardAdapterTest,
    initializeWithPowerOnData_whenPrimeRevision1_shouldKeepCounterValuePostponedNull)  // NOLINT
{
    calypsoCardAdapter = buildCalypsoCard(POWER_ON_DATA);
    ASSERT_EQ(calypsoCardAdapter->getIsCounterValuePostponed(), nullptr);
}

TEST_F(
    CalypsoCardAdapterTest,
    setIsCounterValuePostponed_shouldUpdateValueCorrectly)
{
    calypsoCardAdapter = buildCalypsoCard(buildSelectApplicationResponse(
        DF_NAME,
        CALYPSO_SERIAL_NUMBER,
        STARTUP_INFO_PRIME_REVISION_2,
        SW1SW2_OK));
    ASSERT_EQ(calypsoCardAdapter->getIsCounterValuePostponed(), nullptr);

    calypsoCardAdapter->setIsCounterValuePostponed(true);
    ASSERT_TRUE(*(calypsoCardAdapter->getIsCounterValuePostponed()));

    calypsoCardAdapter->setIsCounterValuePostponed(false);
    ASSERT_FALSE(*(calypsoCardAdapter->getIsCounterValuePostponed()));
}
