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
#include "CalypsoExtensionService.h"
#include "CalypsoSam.h"
#include "samTransactionManager->h"

/* Keyple Card Calypso */
#include "CalypsoSamAdapter.h"

/* Keyple Core Util */
#include "HexUtil.h"

/* Mocks */
#include "CardSelectionResponseApiMock.h"
#include "ReaderMock.h"

using namespace testing;

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::sam;
using namespace keyple::card::calypso;
using namespace keyple::core::util;

static const std::string SAM_SERIAL_NUMBER = "11223344";
static const std::string PSO_MESSAGE = "A1A2A3A4A5A6A7A8A9AA";
static const std::string PSO_MESSAGE_SAM_TRACEABILITY = "B1B2B3B4B5B6B7B8B9BA";
static const std::string PSO_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
static const std::string SPECIFIC_KEY_DIVERSIFIER = "AABBCCDD";

static const std::string R_9000 = "9000";
static const std::string R_INCORRECT_SIGNATURE = "6988";

static const std::string SAM_C1_POWER_ON_DATA =
    "3B3F9600805A4880C1205017" + SAM_SERIAL_NUMBER + "82" + R_9000;

static const std::string C_SELECT_DIVERSIFIER = "8014000004" + SAM_SERIAL_NUMBER;
static const std::string C_SELECT_DIVERSIFIER_SPECIFIC =
    "8014000004" + SPECIFIC_KEY_DIVERSIFIER;

static const std::string C_PSO_COMPUTE_SIGNATURE_DEFAULT = "802A9E9A0EFF010288" + PSO_MESSAGE;
static const std::string R_PSO_COMPUTE_SIGNATURE_DEFAULT = PSO_MESSAGE_SIGNATURE + R_9000;

static const std::string C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
    "802A9E9A10FF0102480001" + PSO_MESSAGE;
static const std::string R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
    PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE + R_9000;

static const std::string C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL =
    "802A9E9A10FF0102680001" + PSO_MESSAGE;
static const std::string R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL =
    PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE + R_9000;

static const std::string C_PSO_VERIFY_SIGNATURE_DEFAULT =
    "802A00A816FF010288" + PSO_MESSAGE + PSO_MESSAGE_SIGNATURE;
static const std::string C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_PARTIAL =
    "802A00A818FF0102480001" + PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE;
static const std::string C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_FULL =
    "802A00A818FF0102680001" + PSO_MESSAGE_SAM_TRACEABILITY + PSO_MESSAGE_SIGNATURE;

static std::shared_ptr<SamTransactionManager> samTransactionManager;
static std::shared_ptr<ReaderMock> samReader;
static std::shared_ptr<CalypsoSam> sam;
static std::shared_ptr<SamSecuritySetting> samSecuritySetting;

static void setUp()
{
    samReader = std::make_shared<ReaderMock>();

    auto samCardSelectionResponse = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*samCardSelectionResponse, getPowerOnData())
        .WillRepeatedly(ReturnRef(SAM_C1_POWER_ON_DATA));
    sam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);

    auto controlSamReader = std::make_shared<ReaderMock>();
    auto controlSam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);
    samSecuritySetting = CalypsoExtensionService::getInstance()->createSamSecuritySetting()
    samSecuritySetting->setControlSamResource(controlSamReader, controlSam);

    samSecuritySetting = CalypsoExtensionService::getInstance()
                                ->createSamTransaction(samReader, sam, samSecuritySetting);
}

static void tearDown()
{
    samReader.reset();
    sam.reset();
    samSecuritySetting.reset();
    samSecuritySetting.reset();
}

static std::shared_ptr<CardRequestSpi> createCardRequest(
    const std::vector<std::string>& apduCommands)
{
    std::vector<std::shared_ptr<ApduRequestSpi>> apduRequests;

    for (const auto& apduCommand : apduCommands) {
        apduRequests.push_back(
            std::make_shared<ApduRequestAdapter>(HexUtil::toByteArray(apduCommand)));
    }

    return std::make_shared<CardRequestAdapter>(apduRequests, false);
}

static std::shared_ptr<CardResponseApi> createCardResponse(
    const std::vector<std::string>& apduCommandResponses)
{
    std::vector<std::shared_ptr<ApduResponseApi>> apduResponses;

    for (const auto& apduResponse : apduCommandResponses) {
        apduResponses.push_back(
            std::make_shared<ApduResponseAdapter>(HexUtil::toByteArray(apduResponse)));
    }

    return std::make_shared<CardResponseAdapter>(apduResponses, true);
}

static bool CardRequestMatcher_matches(const std::shared_ptr<CardRequestSpi> right,
                                       const std::shared_ptr<CardRequestSpi> left)
{
    if (right == nullptr || left == nullptr) {
        return false;
    }

    const auto& rightApduRequests = right->getApduRequests();
    const auto& leftApduRequests = left->getApduRequests();
    if (leftApduRequests.size() != rightApduRequests.size()) {
        return false;
    }

    for (int i = 0; i < rightApduRequests.size(); i++) {
        const auto &rightApdu = rightApduRequests[i]->getApdu();
        const auto &leftApdu = leftApduRequests[i]->getApdu();
        if (rightApdu != leftapdu) {
            return false;
        }
    }

    return true;
}

TEST(SamTransactionManagerAdapterTest, getSamReader_shouldReturnSamReader)
{
    setUp();

    ASSER_EQ(samTransactionManager->getCalypsoSam(), samReader);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, getCalypsoSam_shouldReturnCalypsoSam)
{
    setUp();

    ASSER_EQ(samTransactionManager->getCalypsoSam(), sam);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, getSecuritySetting_shouldReturnSecuritySetting)
{
    setUp();

    ASSER_EQ(samTransactionManager->getSecuritySetting(), samSecuritySetting);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareComputeSignature_whenDataIsNull_shouldThrowIAE)
{
    setUp();

    EXPECT_THROw(samTransactionManager->prepareComputeSignature(nullptr), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenDataIsNotInstanceOfSignatureComputationDataAdapter_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationData>();

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareComputeSignature_whenMessageIsNull_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException;

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareComputeSignature_whenMessageIsEmpty_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(0), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException;

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(207), 1, 2).withSamTraceabilityMode(0, true);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(1), 1,2);
    samTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(208), 1,2);
    samTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(206), 1,2).withSamTraceabilityMode(0, true);
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    setUp();

    auto data = std::make-shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setSignatureSize(0);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>()
    data->setData(std::vector<uint8_t>(10), 1, 2).setSignatureSize(9);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>()
    data->setData(std::vector<uint8_t>(10), 1, 2).setSignatureSize(1);
    samTransactionManager->prepareComputeSignature(data);

    data->setSignatureSize(8);
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareComputeSignature_whenTraceabilityOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>()
    data->setData(std::vector<uint8_t>(10), 1, 2).withSamTraceabilityMode(-1, true);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).withSamTraceabilityMode(3 * 8 + 1, true);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).withSamTraceabilityMode(2 * 8 + 1, false);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data =std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).withSamTraceabilityMode(0, true);
    samTransactionManager->prepareComputeSignature(data);

    data->withSamTraceabilityMode(3 * 8, true);
    samTransactionManager->prepareComputeSignature(data);

    data->withSamTraceabilityMode(2 * 8, false);
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenKeyDiversifierSizeIs0_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setKeyDiversifier(std::vector<uint8_t>(0));

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setKeyDiversifier(std::vector<uint8_t>(9));

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setKeyDiversifier(std::vector<uint8_t>(1));
    samTransactionManager->prepareComputeSignature(data);

    data->setKeyDiversifier(std::vector<uint8_t>(8));
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenTryToGetSignatureButNotProcessed_shouldThrowISE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    EXPECT_THROW(data->getSignature(), IllegalStateException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenTryToGetSignedDataButNotProcessed_shouldThrowISE)
{
    setUp();

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    EXPECT_THROW(data->getSignedData(), IllegalStateException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier)
{

    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data = std::make_shared<SignatureComputationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data).processCommands();

    ASSERT_EQ(data->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<SignatureComputationDataAdapter>();
    data1.setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    auto data2 = std::make_shared<SignatureComputationDataAdapter>();
    data2.setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);

    samTransactionManager->prepareComputeSignature(data1)
                          .prepareComputeSignature(data2)
                          .processCommands();

    ASSERT_EQ(data1->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data1->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));
    ASSERT_EQ(data2->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data2->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                          C_SELECT_DIVERSIFIER,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                          C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                            R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                            R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<SignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<SignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    auto data3 = std::make_shared<SignatureComputationDataAdapter>();
    data3->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));

    samTransactionManager->prepareComputeSignature(data1)
                          .prepareComputeSignature(data2)
                          .prepareComputeSignature(data3)
                          .processCommands();

    ASSERT_EQ(data1->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data1->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));
    ASSERT_EQ(data2->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data2->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));
    ASSERT_EQ(data3->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data3->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice()
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<SignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<SignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));

    samTransactionManager->prepareComputeSignature(data1)
                          .prepareComputeSignature(data2)
                          .processCommands();

    ASSERT_EQ(data1->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data1->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));
    ASSERT_EQ(data2->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data2->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER,
                                          C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
                                          C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL});
    auto cardResponse = createCardResponse({R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
                                            R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<SignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .withSamTraceabilityMode(1, true)
          .withoutBusyMode();
    auto data2 = std::make_shared<SignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .withSamTraceabilityMode(1, false)
          .withoutBusyMode();

    samTransactionManager->prepareComputeSignature(data1)
                          .prepareComputeSignature(data2)
                          .processCommands();

    ASSERT_EQ(data1->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data1->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY));
    ASSERT_EQ(data2->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data2->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareVerifySignature_whenDataIsNull_shouldThrowIAE)
{
    setUp();

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(nullptr), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenDataIsNotInstanceOfSignatureVerificationDataAdapter_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationData>();

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareVerifySignature_whenMessageIsNull_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException;

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareVerifySignature_whenMessageIsEmpty_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::make_shared<uint8_t>(0), std::make_shared<uint8_t>(8), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(207), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(0, true, false);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

@Test(expected = IllegalArgumentException.class)
TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(1), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(208), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(206), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(0, true, false);
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSignatureIsNull_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), null, 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(0), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(9), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(1), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenTraceabilityOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(-1, true, false);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(3 * 8 + 1, true, false);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(2 * 8 + 1, false, false);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(0, true, false);
    samTransactionManager->prepareVerifySignature(data);

    data->withSamTraceabilityMode(3 * 8, true, false);
    samTransactionManager->prepareVerifySignature(data);

    data->withSamTraceabilityMode(2 * 8, false, false);
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenKeyDiversifierSizeIs0_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(0));

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(9));

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(1));
    samTransactionManager->prepareVerifySignature(data);

    data->setKeyDiversifier(std::vector<uint8_t>(8));
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    EXPECT_THROW(data->isSignatureValid(), IllegalStateException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenCheckSamRevocationStatusButNoServiceAvailable_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(0, true, true);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenCheckSamRevocationStatusOK_shouldBeSuccessful)
{
    setUp();

    auto samRevocationServiceSpi = std::make_shared<SamRevocationServiceSpi>();
    EXPECT_CALL(*samRevocationServiceSpi, isSamRevoked(HexUtil::toByteArray("B2B3B4"), 0xC5C6C7))
        .WillRepeatedly(Return(false));

    samSecuritySetting->setSamRevocationService(samRevocationServiceSpi);

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(8, true, true);

    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenCheckSamRevocationStatusKOPartial_shouldThrow)
{
    setUp();

    auto samRevocationServiceSpi = std::make_shared<SamRevocationServiceSpi>();
    EXPECT_CALL(*samRevocationServiceSpi, isSamRevoked(HexUtil::toByteArray("B2B3B4"), 0xB5B6B7))
        .WillRepeatedly(Return(true));

    samSecuritySetting->setSamRevocationService(samRevocationServiceSpi);

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(8, true, true);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), SamRevokedException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenCheckSamRevocationStatusKOFull_shouldThrow)
{
    setUp();

    auto samRevocationServiceSpi = std::make_shared<(SamRevocationServiceSpi>();
    EXPECT_CALL(*samRevocationServiceSpi, isSamRevoked(HexUtil::toByteArray("B2B3B4B5"), 0xB6B7B8))
        .WillRepeatedly(Return(true));

    samSecuritySetting->setSamRevocationService(samRevocationServiceSpi);

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(8, false, true);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), SamRevokedException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData({HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                  1,
                  2);

    samTransactionManager->prepareVerifySignature(data).processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice()
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<SignatureVerificationDataAdapter>();
    data1->setData({HexUtil::toByteArray(PSO_MESSAGE),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2);
    auto data2 = std::make_shared<SignatureVerificationDataAdapter>();
    data2->setData({HexUtil::toByteArray(PSO_MESSAGE),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2);

    samTransactionManager->prepareVerifySignature(data1)
                          .prepareVerifySignature(data2)
                          .processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT,
                                          C_SELECT_DIVERSIFIER,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT,
                                          C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000, R_9000, R_9000, R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<SignatureVerificationDataAdapter>();
    data1->setData({HexUtil::toByteArray(PSO_MESSAGE),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<SignatureVerificationDataAdapter>();
    data2->setData({HexUtil::toByteArray(PSO_MESSAGE),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2);
    auto data3 = std::make_shared<SignatureVerificationDataAdapter>();
    data3->setData({HexUtil::toByteArray(PSO_MESSAGE),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2)
         .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));

    samTransactionManager->prepareVerifySignature(data1)
                          .prepareVerifySignature(data2)
                          .prepareVerifySignature(data3)
                          .processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<SignatureVerificationDataAdapter>();
    data1->setData({HexUtil::toByteArray(PSO_MESSAGE),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<SignatureVerificationDataAdapter>();
    data2->setData({HexUtil::toByteArray(PSO_MESSAGE),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));

    samTransactionManager->prepareVerifySignature(data1)
                          .prepareVerifySignature(data2)
                          .processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER,
                                          C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
                                          C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_FULL});
    auto cardResponse = createCardResponse({R_9000, R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<SignatureVerificationDataAdapter>();
    data1->setData({HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2)
          .withSamTraceabilityMode(1, true, false)
          .withoutBusyMode();
    auto data2 = std::make_shared<SignatureVerificationDataAdapter>();
    data2->setData({HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                    HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                   1,
                   2)
          .withSamTraceabilityMode(1, false, false)
          .withoutBusyMode();

    samTransactionManager->prepareVerifySignature(data1)
                          .prepareVerifySignature(data2)
                          .processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSignatureIsValid_shouldUpdateOutputDatad)
{
    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData({HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                  1,
                  2);

    samTransactionManager->prepareVerifySignature(data).processCommands();

    ASSERT_TRUE(data->isSignatureValid());

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_INCORRECT_SIGNATURE});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse));

    auto data = std::make_shared<SignatureVerificationDataAdapter>();
    data->setData({HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE)},
                  1,
                  2);


    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data).processCommands(),
                 UnexpectedCommandStatusException);

    ASSERT_FALSE(data->isSignatureValid());

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, processCommands_whenNoError_shouldClearCommandList)
{
    setUp();

    auto cardRequest1 = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse1 = createCardResponse({R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    auto cardRequest2 = createCardRequest(C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    auto cardResponse2 = createCardResponse(R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse1));
    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse2));

    auto data1 = std::make_shared<SignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data1).processCommands();

    auto data2 = std::make_shared<SignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data2).processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, processCommands_whenError_shouldClearCommandList)
{
    setUp();

    auto cardRequest1 = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse1 = createCardResponse({R_9000, R_INCORRECT_SIGNATURE});

    auto cardRequest2 = createCardRequest(C_PSO_COMPUTE_SIGNATURE_DEFAULT);
    auto cardResponse2 = createCardResponse(R_PSO_COMPUTE_SIGNATURE_DEFAULT);

    EXPECT_CALL(*samReader, transmitCardRequest(_, _).WillOnce(Return(cardResponse1));
    EXPECT_CALL(*samReader, transmitCardRequest(_, _)WillOnce(Return(cardResponse2));

    auto data1 = std::make_shared<SignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data1).processCommands();
                 UnexpectedCommandStatusException);

    auto data2 = std::make_shared<SignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data2).processCommands();

    tearDown();
}
