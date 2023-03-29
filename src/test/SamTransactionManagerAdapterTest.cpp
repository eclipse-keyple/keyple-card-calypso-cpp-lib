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

/* Calypsonet Terminal Calypso */
#include "CalypsoExtensionService.h"
#include "CalypsoSam.h"
#include "SamTransactionManager.h"

/* Keyple Card Calypso */
#include "BasicSignatureComputationDataAdapter.h"
#include "CalypsoSamAdapter.h"
#include "SamTransactionManager.h"
#include "SamTransactionManagerAdapter.h"
#include "TraceableSignatureComputationDataAdapter.h"

/* Keyple Core Service */
#include "ApduResponseAdapter.h"
#include "CardResponseAdapter.h"

/* Keyple Core Util */
#include "HexUtil.h"
#include "IllegalArgumentException.h"

/* Mocks */
#include "CardSelectionResponseApiMock.h"
#include "CardProxyReaderMock.h"
#include "ReaderMock.h"
#include "SamRevocationServiceSpiMock.h"
#include "TraceableSignatureComputationDataMock.h"
#include "TraceableSignatureVerificationDataMock.h"

using namespace testing;

using namespace calypsonet::terminal::calypso;
using namespace calypsonet::terminal::calypso::sam;
using namespace keyple::card::calypso;
using namespace keyple::core::service;
using namespace keyple::core::util;
using namespace keyple::core::util::cpp::exception;

static const std::string SAM_SERIAL_NUMBER = "11223344";
static const std::string CIPHER_MESSAGE = "A1A2A3A4A5A6A7A8";
static const std::string CIPHER_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
static const std::string CIPHER_MESSAGE_INCORRECT_SIGNATURE = "C1C2C3C4C5C6C7C9";
static const std::string CIPHER_MESSAGE_SIGNATURE_3_BYTES = "C1C2C3";
static const std::string PSO_MESSAGE = "A1A2A3A4A5A6A7A8A9AA";
static const std::string PSO_MESSAGE_SAM_TRACEABILITY = "B1B2B3B4B5B6B7B8B9BA";
static const std::string PSO_MESSAGE_SIGNATURE = "C1C2C3C4C5C6C7C8";
static const std::string SPECIFIC_KEY_DIVERSIFIER = "AABBCCDD";

static const std::string R_9000 = "9000";
static const std::string R_INCORRECT_SIGNATURE = "6988";

static const std::string C_DATA_CIPHER_DEFAULT = "801C40000A0102" + CIPHER_MESSAGE;
static const std::string R_DATA_CIPHER_DEFAULT = CIPHER_MESSAGE_SIGNATURE + R_9000;


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
static std::shared_ptr<CardProxyReaderMock> samReader;
static std::shared_ptr<CalypsoSam> _sam;
static std::shared_ptr<SamSecuritySetting> samSecuritySetting;

static void setUp()
{
    samReader = std::make_shared<CardProxyReaderMock>();

    auto samCardSelectionResponse = std::make_shared<CardSelectionResponseApiMock>();
    EXPECT_CALL(*samCardSelectionResponse, getPowerOnData())
        .WillRepeatedly(ReturnRef(SAM_C1_POWER_ON_DATA));
    _sam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);

    auto controlSamReader = std::make_shared<CardProxyReaderMock>();
    auto controlSam = std::make_shared<CalypsoSamAdapter>(samCardSelectionResponse);
    samSecuritySetting = CalypsoExtensionService::getInstance()->createSamSecuritySetting();
    samSecuritySetting->setControlSamResource(controlSamReader, controlSam);

    samTransactionManager = CalypsoExtensionService::getInstance()
                                ->createSamTransaction(samReader, _sam, samSecuritySetting);
}

static void tearDown()
{
    samReader.reset();
    _sam.reset();
    samSecuritySetting.reset();
    samTransactionManager.reset();
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

// static bool CardRequestMatcher_matches(const std::shared_ptr<CardRequestSpi> right,
//                                        const std::shared_ptr<CardRequestSpi> left)
// {
//     if (right == nullptr || left == nullptr) {
//         return false;
//     }

//     const auto& rightApduRequests = right->getApduRequests();
//     const auto& leftApduRequests = left->getApduRequests();
//     if (leftApduRequests.size() != rightApduRequests.size()) {
//         return false;
//     }

//     for (int i = 0; i < static_cast<int>(rightApduRequests.size()); i++) {
//         const auto &rightApdu = rightApduRequests[i]->getApdu();
//         const auto &leftApdu = leftApduRequests[i]->getApdu();
//         if (rightApdu != leftApdu) {
//             return false;
//         }
//     }

//     return true;
// }

TEST(SamTransactionManagerAdapterTest, getSamReader_shouldReturnSamReader)
{
    setUp();

    ASSERT_EQ(samTransactionManager->getSamReader(), samReader);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, getCalypsoSam_shouldReturnCalypsoSam)
{
    setUp();

    ASSERT_EQ(samTransactionManager->getCalypsoSam(), _sam);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, getSecuritySetting_shouldReturnSecuritySetting)
{
    setUp();

    ASSERT_EQ(samTransactionManager->getSecuritySetting(), samSecuritySetting);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareComputeSignature_whenDataIsNull_shouldThrowIAE)
{
    setUp();

    /* C++: random type cast... */
    const std::shared_ptr<CommonSignatureComputationData<TraceableSignatureComputationData>>
        data = nullptr;

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenDataIsNotInstanceOfBasicSignatureComputationDataAdapterOrTraceableSignatureComputationDataAdapter_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataMock>();

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenMessageIsNull_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareComputeSignature_PSO_whenMessageIsNull_shouldThrowIAE)
{
    setUp();

    const auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenMessageIsEmpty_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(0), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenMessageIsEmpty_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(0), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenMessageLengthIsGreaterThan208_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(207), 1, 2).withSamTraceabilityMode(0, true);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), 1, 2);


    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenMessageLengthIsNotMultipleOf8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(15), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(208), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(16), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(1), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(208), 1,2);
    samTransactionManager->prepareComputeSignature(data);

    data->setData(std::vector<uint8_t>(206), 1,2).withSamTraceabilityMode(0, true);
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setSignatureSize(0);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setSignatureSize(0);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setSignatureSize(9);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setSignatureSize(9);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), 1, 2).setSignatureSize(1);
    samTransactionManager->prepareComputeSignature(data);

    data->setSignatureSize(8);
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setSignatureSize(1);
    samTransactionManager->prepareComputeSignature(data);
    data->setSignatureSize(8);
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenTraceabilityOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).withSamTraceabilityMode(-1, true);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).withSamTraceabilityMode(3 * 8 + 1, true);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).withSamTraceabilityMode(2 * 8 + 1, false);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data =std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).withSamTraceabilityMode(0, true);
    samTransactionManager->prepareComputeSignature(data);

    data->withSamTraceabilityMode(3 * 8, true);
    samTransactionManager->prepareComputeSignature(data);

    data->withSamTraceabilityMode(2 * 8, false);
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenKeyDiversifierSizeIs0_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setKeyDiversifier(std::vector<uint8_t>(0));

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenKeyDiversifierSizeIs0_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setKeyDiversifier(std::vector<uint8_t>(0));

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setKeyDiversifier(std::vector<uint8_t>(9));

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setKeyDiversifier(std::vector<uint8_t>(9));

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
      prepareComputeSignature_Basic_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), 1, 2).setKeyDiversifier(std::vector<uint8_t>(1));
    samTransactionManager->prepareComputeSignature(data);

    data->setKeyDiversifier(std::vector<uint8_t>(8));
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2).setKeyDiversifier(std::vector<uint8_t>(1));
    samTransactionManager->prepareComputeSignature(data);
    data->setKeyDiversifier(std::vector<uint8_t>(8));
    samTransactionManager->prepareComputeSignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenTryToGetSignatureButNotProcessed_shouldThrowISE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    EXPECT_THROW(data->getSignature(), IllegalStateException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenTryToGetSignatureButNotProcessed_shouldThrowISE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    EXPECT_THROW(data->getSignature(), IllegalStateException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenTryToGetSignedDataButNotProcessed_shouldThrowISE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), 1, 2);
    samTransactionManager->prepareComputeSignature(data);

    EXPECT_THROW(data->getSignedData(), IllegalStateException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data).processCommands();

    ASSERT_EQ(data->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
      prepareComputeSignature_PSO_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier)
{
    setUp();

    const auto cardRequest =
        createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data).processCommands();


    ASSERT_EQ(data->getSignature(), HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE));
    ASSERT_EQ(data->getSignedData(), HexUtil::toByteArray(PSO_MESSAGE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_Basic_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    const auto cardRequest =
        createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse =
        createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    const auto data1 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    const auto data2 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data1)
                          .prepareComputeSignature(data2)
                          .processCommands();

    ASSERT_EQ(data1->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
    ASSERT_EQ(data2->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);

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
     prepareComputeSignature_Basic_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                                C_DATA_CIPHER_DEFAULT,
                                                C_SELECT_DIVERSIFIER,
                                                C_DATA_CIPHER_DEFAULT,
                                                C_SELECT_DIVERSIFIER_SPECIFIC,
                                                C_DATA_CIPHER_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000,
                                                  R_DATA_CIPHER_DEFAULT,
                                                  R_9000,
                                                  R_DATA_CIPHER_DEFAULT,
                                                  R_9000,
                                                  R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    const auto data1 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    const auto data2 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2);
    const auto data3 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data3->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager->prepareComputeSignature(data1)
                          .prepareComputeSignature(data2)
                          .prepareComputeSignature(data3)
                          .processCommands();

    ASSERT_EQ(data1->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
    ASSERT_EQ(data2->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
    ASSERT_EQ(data3->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier)
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

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    auto data3 = std::make_shared<TraceableSignatureComputationDataAdapter>();
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
     prepareComputeSignature_Basic_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                                C_DATA_CIPHER_DEFAULT,
                                                C_DATA_CIPHER_DEFAULT});
    const auto cardResponse =
        createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    const auto data1 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    const auto data2 = std::make_shared<BasicSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager->prepareComputeSignature(data1)
                          .prepareComputeSignature(data2)
                          .processCommands();

    ASSERT_EQ(data1->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));
    ASSERT_EQ(data2->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                          C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT,
                                            R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
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
     prepareComputeSignature_Basic_whenSignatureSizeIsLessThan8_shouldBeSuccessful)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureComputationDataAdapter>();
    data->setData(HexUtil::toByteArray(CIPHER_MESSAGE), 1, 2)
         .setSignatureSize(3); /* Signature size = 3 */
    samTransactionManager->prepareComputeSignature(data).processCommands();

    ASSERT_EQ(data->getSignature(), HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE_3_BYTES));

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareComputeSignature_PSO_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER,
                                          C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
                                          C_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL});
    auto cardResponse = createCardResponse({R_9000,
                                            R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
                                            R_PSO_COMPUTE_SIGNATURE_SAM_TRACEABILITY_FULL});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2)
          .withSamTraceabilityMode(1, true)
          .withoutBusyMode();
    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
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

    const std::shared_ptr<CommonSignatureVerificationData<TraceableSignatureVerificationData>>
        data = nullptr;

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_whenDataIsNotInstanceOfBasicSignatureVerificationDataAdapterOrTraceableSignatureVerificationDataAdapter_shouldThrowIAE)
{
    setUp();

    const auto data = std::make_shared<TraceableSignatureVerificationDataMock>();

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareVerifySignature_Basic_whenMessageIsNull_shouldThrowIAE)
{
    setUp();

    const auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareVerifySignature_PSO_whenMessageIsNull_shouldThrowIAE)
{
    setUp();

    const auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenMessageIsEmpty_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(0), std::vector<uint8_t>(8), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareVerifySignature_PSO_whenMessageIsEmpty_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(0), std::vector<uint8_t>(8), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenMessageLengthIsGreaterThan208_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), std::vector<uint8_t>(8), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenTraceabilityModeAndMessageLengthIsGreaterThan206_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(207), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(0, true, false);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenNotTraceabilityModeAndMessageLengthIsGreaterThan208_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), std::vector<uint8_t>(8), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenMessageLengthIsNotMultipleOf8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(209), std::vector<uint8_t>(15), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(208), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(16), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenMessageLengthIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
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
     prepareVerifySignature_Basic_whenSignatureIsNull_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(0), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, prepareVerifySignature_PSO_whenSignatureIsNull_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(0), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(0), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenSignatureSizeIsLessThan1_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(0), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(9), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenSignatureSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(9), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(1), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenSignatureSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(1), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenTraceabilityOffsetIsNegative_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(-1, true, false);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenPartialSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(3 * 8 + 1, true, false);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenFullSamSerialNumberAndTraceabilityOffsetIsToHigh_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(2 * 8 + 1, false, false);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenTraceabilityOffsetIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
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
     prepareVerifySignature_Basic_whenKeyDiversifierSizeIs0_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(0));

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenKeyDiversifierSizeIs0_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(0));

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(9));

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenKeyDiversifierSizeIsGreaterThan8_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(9));

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(1));
    samTransactionManager->prepareVerifySignature(data);

    data->setKeyDiversifier(std::vector<uint8_t>(8));
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenKeyDiversifierSizeIsInCorrectRange_shouldBeSuccessful)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .setKeyDiversifier(std::vector<uint8_t>(1));
    samTransactionManager->prepareVerifySignature(data);

    data->setKeyDiversifier(std::vector<uint8_t>(8));
    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE)
{
    setUp();

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(8), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    EXPECT_THROW(data->isSignatureValid(), IllegalStateException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenTryToCheckIfSignatureIsValidButNotAlreadyProcessed_shouldThrowISE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2);
    samTransactionManager->prepareVerifySignature(data);

    EXPECT_THROW(data->isSignatureValid(), IllegalStateException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenCheckSamRevocationStatusButNoServiceAvailable_shouldThrowIAE)
{
    setUp();

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(std::vector<uint8_t>(10), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(0, true, true);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), IllegalArgumentException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenCheckSamRevocationStatusOK_shouldBeSuccessful)
{
    setUp();

    auto samRevocationServiceSpi = std::make_shared<SamRevocationServiceSpiMock>();
    EXPECT_CALL(*samRevocationServiceSpi, isSamRevoked(_, _)).WillRepeatedly(Return(false));

    samSecuritySetting->setSamRevocationService(samRevocationServiceSpi);

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(8, true, true);

    samTransactionManager->prepareVerifySignature(data);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenCheckSamRevocationStatusKOPartial_shouldThrowSRE)
{
    setUp();

    auto samRevocationServiceSpi = std::make_shared<SamRevocationServiceSpiMock>();
    EXPECT_CALL(*samRevocationServiceSpi, isSamRevoked(_, _)).WillRepeatedly(Return(true));

    samSecuritySetting->setSamRevocationService(samRevocationServiceSpi);

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(8, true, true);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), SamRevokedException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenCheckSamRevocationStatusKOFull_shouldThrowSRE)
{
    setUp();

    auto samRevocationServiceSpi = std::make_shared<SamRevocationServiceSpiMock>();
    EXPECT_CALL(*samRevocationServiceSpi, isSamRevoked(_, _)).WillRepeatedly(Return(true));

    samSecuritySetting->setSamRevocationService(samRevocationServiceSpi);

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY), std::vector<uint8_t>(8), 1, 2)
         .withSamTraceabilityMode(8, false, true);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data), SamRevokedException);

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                  HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
                  1,
                  2);
    samTransactionManager->prepareVerifySignature(data).processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenDefaultDiversifierAndNotAlreadySelected_shouldSelectDefaultDiversifier)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE),
                  HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                  1,
                  2);

    samTransactionManager->prepareVerifySignature(data).processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    const auto cardRequest =
        createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse =
        createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data1->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                   HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
                   1,
                   2);
    auto data2 = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data2->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                   HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
                   1,
                   2);
    samTransactionManager->prepareVerifySignature(data1)
                          .prepareVerifySignature(data2)
                          .processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
      prepareVerifySignature_PSO_whenDefaultDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                   1,
                   2);
    auto data2 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                   1,
                   2);

    samTransactionManager->prepareVerifySignature(data1)
                          .prepareVerifySignature(data2)
                          .processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                                C_DATA_CIPHER_DEFAULT,
                                                C_SELECT_DIVERSIFIER,
                                                C_DATA_CIPHER_DEFAULT,
                                                C_SELECT_DIVERSIFIER_SPECIFIC,
                                                C_DATA_CIPHER_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000,
                                                  R_DATA_CIPHER_DEFAULT,
                                                  R_9000,
                                                  R_DATA_CIPHER_DEFAULT,
                                                  R_9000,
                                                  R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data1->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                   HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data2->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                   HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
                   1,
                   2);
    auto data3 = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data3->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                   HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
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
     prepareVerifySignature_PSO_whenSpecificDiversifierAndNotAlreadySelected_shouldSelectSpecificDiversifier)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT,
                                          C_SELECT_DIVERSIFIER,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT,
                                          C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000, R_9000, R_9000, R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                   1,
                   2);
    auto data3 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data3->setData(HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
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
     prepareVerifySignature_Basic_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    const auto cardRequest = createCardRequest(
        {C_SELECT_DIVERSIFIER_SPECIFIC, C_DATA_CIPHER_DEFAULT, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse =
        createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data1->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                   HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data2->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                   HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    samTransactionManager->prepareVerifySignature(data1)
                          .prepareVerifySignature(data2)
                          .processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenSpecificDiversifierAndAlreadySelected_shouldNotSelectTwice)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER_SPECIFIC,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT,
                                          C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));
    auto data2 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                   1,
                   2)
          .setKeyDiversifier(HexUtil::toByteArray(SPECIFIC_KEY_DIVERSIFIER));

    samTransactionManager->prepareVerifySignature(data1)
                          .prepareVerifySignature(data2)
                          .processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenSamTraceabilityModePartialAndNotBusy_shouldBeSuccessful)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER,
                                          C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_PARTIAL,
                                          C_PSO_VERIFY_SIGNATURE_SAM_TRACEABILITY_FULL});
    auto cardResponse = createCardResponse({R_9000, R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data1 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                   1,
                   2)
          .withSamTraceabilityMode(1, true, false)
          .withoutBusyMode();
    auto data2 = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE_SAM_TRACEABILITY),
                   HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
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
     prepareVerifySignature_Basic_whenSignatureIsValid_shouldUpdateOutputData)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                  HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE),
                  1,
                  2);
    samTransactionManager->prepareVerifySignature(data).processCommands();

    ASSERT_TRUE(data->isSignatureValid());

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
      prepareVerifySignature_Basic_whenSignatureIsValidWithSizeLessThan8_shouldUpdateOutputData)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                  HexUtil::toByteArray(CIPHER_MESSAGE_SIGNATURE_3_BYTES),
                  1,
                  2);
    samTransactionManager->prepareVerifySignature(data).processCommands();

    ASSERT_TRUE(data->isSignatureValid());

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenSignatureIsValid_shouldUpdateOutputData)
{
    setUp();

    const auto cardRequest =
        createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000, R_9000});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE),
                  HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                  1,
                  2);

    samTransactionManager->prepareVerifySignature(data).processCommands();

    ASSERT_TRUE(data->isSignatureValid());

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_Basic_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData)
{
    setUp();

    const auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_DATA_CIPHER_DEFAULT});
    const auto cardResponse = createCardResponse({R_9000, R_DATA_CIPHER_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<BasicSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(CIPHER_MESSAGE),
                  HexUtil::toByteArray(CIPHER_MESSAGE_INCORRECT_SIGNATURE),
                  1,
                  2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data).processCommands(),
                 InvalidSignatureException);
    ASSERT_FALSE(data->isSignatureValid());

    tearDown();
}

TEST(SamTransactionManagerAdapterTest,
     prepareVerifySignature_PSO_whenSignatureIsInvalid_shouldThrowISEAndUpdateOutputData)
{
    setUp();

    auto cardRequest = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_VERIFY_SIGNATURE_DEFAULT});
    auto cardResponse = createCardResponse({R_9000, R_INCORRECT_SIGNATURE});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _)).WillOnce(Return(cardResponse));

    auto data = std::make_shared<TraceableSignatureVerificationDataAdapter>();
    data->setData(HexUtil::toByteArray(PSO_MESSAGE),
                  HexUtil::toByteArray(PSO_MESSAGE_SIGNATURE),
                  1,
                  2);

    EXPECT_THROW(samTransactionManager->prepareVerifySignature(data).processCommands(),
                 InvalidSignatureException);

    ASSERT_FALSE(data->isSignatureValid());

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, processCommands_whenNoError_shouldClearCommandList)
{
    setUp();

    const auto cardRequest1 =
        createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    const auto cardResponse1 = createCardResponse({R_9000, R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    const auto cardRequest2 = createCardRequest({C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    const auto cardResponse2 = createCardResponse({R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _))
        .WillOnce(Return(cardResponse1))
        .WillOnce(Return(cardResponse2));

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data1).processCommands();

    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data2).processCommands();

    tearDown();
}

TEST(SamTransactionManagerAdapterTest, processCommands_whenError_shouldClearCommandList)
{
    setUp();

    auto cardRequest1 = createCardRequest({C_SELECT_DIVERSIFIER, C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse1 = createCardResponse({R_9000, R_INCORRECT_SIGNATURE});

    auto cardRequest2 = createCardRequest({C_PSO_COMPUTE_SIGNATURE_DEFAULT});
    auto cardResponse2 = createCardResponse({R_PSO_COMPUTE_SIGNATURE_DEFAULT});

    EXPECT_CALL(*samReader, transmitCardRequest(_, _))
        .WillOnce(Return(cardResponse1))
        .WillOnce(Return(cardResponse2));

    auto data1 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data1->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);

    EXPECT_THROW(samTransactionManager->prepareComputeSignature(data1).processCommands(),
                 UnexpectedCommandStatusException);

    auto data2 = std::make_shared<TraceableSignatureComputationDataAdapter>();
    data2->setData(HexUtil::toByteArray(PSO_MESSAGE), 1, 2);
    samTransactionManager->prepareComputeSignature(data2).processCommands();

    tearDown();
}
