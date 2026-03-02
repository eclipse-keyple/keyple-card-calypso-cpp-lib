/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keyple/card/calypso/CalypsoExtensionService.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/card/CalypsoCard.hpp"
#include "keypop/calypso/card/card/ElementaryFile.hpp"
#include "keypop/calypso/card/card/FileHeader.hpp"
#include "keypop/calypso/card/transaction/FreeTransactionManager.hpp"

#include "AbstractTransactionManagerTest.hpp"
#include "FreeTransactionManagerMock.hpp"

using keyple::card::calypso::CalypsoExtensionService;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::card::CalypsoCard;
using keypop::calypso::card::card::ElementaryFile;
using keypop::calypso::card::card::FileHeader;
using keypop::calypso::card::transaction::FreeTransactionManager;

using testing::ReturnRef;

class SecureRegularModeTransactionManagerAdapterTest
: public ::testing::Test,
  public AbstractTransactionManagerTest {
protected:
    void
    SetUp() override
    {
        cardReader = std::make_shared<ReaderMock>();
        initCalypsoCardAndTransactionManager(
            SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);

        // EXPECT_CALL(*cardTransactionManager, prepareSelectFile(_))
        //     .WillRepeatedly(Return);
    }

    void
    TearDown() override
    {
        cardReader.reset();
        cardTransactionManager.reset();
    }

    void
    initTransactionManager() override
    {
        cardTransactionManager
            = CalypsoExtensionService::getInstance()
                  ->getCalypsoCardApiFactory()
                  ->createFreeTransactionManager(cardReader, calypsoCard);
    }

    std::unique_ptr<FreeTransactionManager> cardTransactionManager;
};

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSelectFile_whenLidIs1234AndCardIsPrimeRevision3_shouldPrepareSelectFileApduWith1234)  // NOLINT
{
    const std::uint16_t lid = 0x1234;

    std::vector<std::string> apdus
        = {CARD_SELECT_FILE_1234_CMD, CARD_SELECT_FILE_1234_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareSelectFile(lid);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSelectFile_whenLidIs1234AndCardIsPrimeRevision2_shouldPrepareSelectFileApduWith1234)  // NOLINT
{
    const std::uint16_t lid = 0x1234;

    std::vector<std::string> apdus
        = {CARD_SELECT_FILE_1234_CMD_PRIME_REV2,
           CARD_SELECT_FILE_1234_RSP_PRIME_REV2};

    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareSelectFile(lid);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSelectFile_whenSelectFileControlIsFirstEF_shouldPrepareSelectFileApduWithP2_02_P1_00)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_SELECT_FILE_FIRST_CMD, CARD_SELECT_FILE_1234_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareSelectFile(SelectFileControl::FIRST_EF);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSelectFile_whenSelectFileControlIsNextEF_shouldPrepareSelectFileApduWithP2_02_P1_02)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_SELECT_FILE_NEXT_CMD, CARD_SELECT_FILE_1234_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareSelectFile(SelectFileControl::NEXT_EF);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSelectFile_whenSelectFileControlIsCurrentEF_shouldPrepareSelectFileApduWithP2_09_P1_00)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_SELECT_FILE_CURRENT_CMD, CARD_SELECT_FILE_1234_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareSelectFile(SelectFileControl::CURRENT_DF);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

// Does not apply to C++
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareGetData_whenGetDataTagIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareGetData(nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareGetData_whenGetDataTagIsFCP_shouldPrepareSelectFileApduWithTagFCP)
{
    std::vector<std::string> apdus
        = {CARD_GET_DATA_FCP_CMD, CARD_GET_DATA_FCP_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareGetData(GetDataTag::FCP_FOR_CURRENT_FILE);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareGetData_whenGetDataTagIsEF_LIST_shouldPopulateCalypsoCard)
{
    // EF LIST
    // C028
    // C106 2001 07 02 1D 01
    // C106 20FF 09 01 1D 04
    // C106 F123 10 04 F3 F4
    // C106 F124 11 08 F3 F4
    // C106 F125 1F 09 F3 F4
    std::vector<std::string> apdus
        = {CARD_GET_DATA_EF_LIST_CMD, CARD_GET_DATA_EF_LIST_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    ASSERT_TRUE(calypsoCard->getFiles().empty());

    cardTransactionManager->prepareGetData(GetDataTag::EF_LIST);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(calypsoCard->getFiles().size(), 5);

    std::shared_ptr<FileHeader> fileHeader07(
        calypsoCard->getFileBySfi(0x07)->getHeader());
    ASSERT_EQ(fileHeader07->getLid(), 0x2001);
    ASSERT_EQ(fileHeader07->getEfType(), ElementaryFile::Type::LINEAR);
    ASSERT_EQ(fileHeader07->getRecordSize(), 0x1D);
    ASSERT_EQ(fileHeader07->getRecordsNumber(), 0x01);

    std::shared_ptr<FileHeader> fileHeader09(
        calypsoCard->getFileBySfi(0x09)->getHeader());
    ASSERT_EQ(fileHeader09->getLid(), 0x20FF);
    ASSERT_EQ(fileHeader09->getEfType(), ElementaryFile::Type::BINARY);
    ASSERT_EQ(fileHeader09->getRecordSize(), 0x1D);
    ASSERT_EQ(fileHeader09->getRecordsNumber(), 0x04);

    std::shared_ptr<FileHeader> fileHeader10(
        calypsoCard->getFileBySfi(0x10)->getHeader());
    ASSERT_EQ(fileHeader10->getLid(), 0xF123);
    ASSERT_EQ(fileHeader10->getEfType(), ElementaryFile::Type::CYCLIC);
    ASSERT_EQ(fileHeader10->getRecordSize(), 0xF3);
    ASSERT_EQ(fileHeader10->getRecordsNumber(), 0xF4);

    std::shared_ptr<FileHeader> fileHeader11(
        calypsoCard->getFileBySfi(0x11)->getHeader());
    ASSERT_EQ(fileHeader11->getLid(), 0xF124);
    ASSERT_EQ(
        fileHeader11->getEfType(), ElementaryFile::Type::SIMULATED_COUNTERS);
    ASSERT_EQ(fileHeader11->getRecordSize(), 0xF3);
    ASSERT_EQ(fileHeader11->getRecordsNumber(), 0xF4);

    std::shared_ptr<FileHeader> fileHeader1F(
        calypsoCard->getFileBySfi(0x1F)->getHeader());
    ASSERT_EQ(fileHeader1F->getLid(), 0xF125);
    ASSERT_EQ(fileHeader1F->getEfType(), ElementaryFile::Type::COUNTERS);
    ASSERT_EQ(fileHeader1F->getRecordSize(), 0xF3);
    ASSERT_EQ(fileHeader1F->getRecordsNumber(), 0xF4);

    ASSERT_EQ(
        calypsoCard->getFileByLid(0x20FF), calypsoCard->getFileBySfi(0x09));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareGetData_whenGetDataTagIsTRACEABILITY_INFORMATION_shouldPopulateCalypsoCard)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_GET_DATA_TRACEABILITY_INFORMATION_CMD,
           CARD_GET_DATA_TRACEABILITY_INFORMATION_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareGetData(
        GetDataTag::TRACEABILITY_INFORMATION);

    ASSERT_TRUE(calypsoCard->getTraceabilityInformation().empty());

    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getTraceabilityInformation(),
        HexUtil::toByteArray("00112233445566778899"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareGetData_whenGetDataTagIsFCI_shouldPrepareSelectFileApduWithTagFCI)
{
    std::vector<std::string> apdus
        = {CARD_GET_DATA_FCI_CMD, CARD_GET_DATA_FCI_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareGetData(GetDataTag::FCI_FOR_CURRENT_DF);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecord(31, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecord_whenRecordNumberIsLessThan0_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecord(FILE7, -1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecord_whenRecordNumberIsMoreThan250_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecord(FILE7, 251),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecord_whenSfi07RecNumber1_shouldPrepareReadRecordApduWithSfi07RecNumber1)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_REC_SFI7_REC1_CMD, CARD_READ_REC_SFI7_REC1_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareReadRecord(FILE7, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecords_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(31, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecords_whenFromRecordNumberIs0_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(FILE7, 0, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecords_whenFromRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(FILE7, 251, 251, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecords_whenToRecordNumberIsLessThanFromRecordNumber_shouldThrowIAE)  // NOLINT
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(FILE7, 2, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecords_whenToRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(FILE7, 1, 251, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecords_whenNbRecordsToReadMultipliedByRecSize2IsLessThanPayLoad_shouldPrepareOneCommand)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_RECORDS_FROM1_TO2_CMD, CARD_READ_RECORDS_FROM1_TO2_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(7));

    initTransactionManager();

    cardTransactionManager->prepareReadRecords(1, 1, 2, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(1),
        HexUtil::toByteArray("11"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(2),
        HexUtil::toByteArray("22"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecords_whenNbRecordsToReadMultipliedByRecSize2IsGreaterThanPayLoad_shouldPrepareMultipleCommands)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_RECORDS_FROM1_TO2_CMD,
           CARD_READ_RECORDS_FROM1_TO2_RSP,
           CARD_READ_RECORDS_FROM3_TO4_CMD,
           CARD_READ_RECORDS_FROM3_TO4_RSP,
           CARD_READ_RECORDS_FROM5_TO5_CMD,
           CARD_READ_RECORDS_FROM5_TO5_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(7));

    initTransactionManager();

    cardTransactionManager->prepareReadRecords(1, 1, 5, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(1),
        HexUtil::toByteArray("11"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(2),
        HexUtil::toByteArray("22"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(3),
        HexUtil::toByteArray("33"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(4),
        HexUtil::toByteArray("44"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(5),
        HexUtil::toByteArray("55"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenProductTypeIsNotPrimeRev3OrLight_shouldThrowUOE)  // NOLINT
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);

    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 1, 1),
        UnsupportedOperationException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(-1, 1, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(31, 1, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenFromRecordNumberIsZero_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 0, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenFromRecordNumberGreaterThan250_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 251, 251, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenToRecordNumberLessThanFromRecordNumber_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 2, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenToRecordNumberGreaterThan250MinusFromRecordNumber_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 251, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, -1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenOffsetGreaterThan249_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 250, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenNbBytesToReadIsZero_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 1, 0),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenNbBytesToReadIsGreaterThan250MinusOffset_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 3, 248),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenNbRecordsToReadMultipliedByNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NB_BYTE1_CMD,
           CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NB_BYTE1_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(3));

    initTransactionManager();

    cardTransactionManager->prepareReadRecordsPartially(1, 1, 2, 3, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(1),
        HexUtil::toByteArray("00000011"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(2),
        HexUtil::toByteArray("00000022"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenNbRecordsToReadMultipliedByNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NB_BYTE1_CMD,
           CARD_READ_RECORD_MULTIPLE_REC1_OFFSET3_NB_BYTE1_RSP,
           CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NB_BYTE1_CMD,
           CARD_READ_RECORD_MULTIPLE_REC3_OFFSET3_NB_BYTE1_RSP,
           CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NB_BYTE1_CMD,
           CARD_READ_RECORD_MULTIPLE_REC5_OFFSET3_NB_BYTE1_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    initTransactionManager();

    cardTransactionManager->prepareReadRecordsPartially(1, 1, 5, 3, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(1),
        HexUtil::toByteArray("00000011"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(2),
        HexUtil::toByteArray("00000022"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(3),
        HexUtil::toByteArray("00000033"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(4),
        HexUtil::toByteArray("00000044"));
    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(5),
        HexUtil::toByteArray("00000055"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadBinary_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(-1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(31, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(1, -1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(1, 32768, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadBinary_whenNbBytesToReadIsLessThan1_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(1, 1, 0),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD,
           CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP,
           CARD_READ_BINARY_SFI0_OFFSET256_1B_CMD,
           CARD_READ_BINARY_SFI0_OFFSET256_1B_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareReadBinary(1, 256, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    const std::vector<std::uint8_t> content(
        calypsoCard->getFileBySfi(1)->getData()->getContent());

    ASSERT_TRUE(Arrays::startsWith(content, HexUtil::toByteArray("1100")));
    ASSERT_TRUE(Arrays::endsWith(content, HexUtil::toByteArray("0066")));
    ASSERT_EQ(content.size(), 257);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadBinary_whenNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD,
           CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    initTransactionManager();

    cardTransactionManager->prepareReadBinary(1, 0, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(),
        HexUtil::toByteArray("11"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadBinary_whenNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD,
           CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    initTransactionManager();

    cardTransactionManager->prepareReadBinary(1, 0, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(),
        HexUtil::toByteArray("11"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareReadCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadCounter(31, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenProductTypeIsNotPrimeRev3_shouldThrowUOE)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(nullptr),
        UnsupportedOperationException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenDataIsNull_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(nullptr),
        IllegalArgumentException);
}

// C++: does not apply
// @Test(expected = IllegalArgumentException.class)
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareSearchRecords_whenDataIsNotInstanceOfInternalAdapter_shouldThrowIAE)
// {
//
//     cardTransactionManager.prepareSearchRecords(
//         new SearchCommandData() {
//           @Override
//           public SearchCommandData setSfi(byte sfi) {
//             return null;
//           }
//
//           @Override
//           public SearchCommandData startAtRecord(int recordNumber) {
//             return null;
//           }
//
//           @Override
//           public SearchCommandData setOffset(int offset) {
//             return null;
//           }
//
//           @Override
//           public SearchCommandData enableRepeatedOffset() {
//             return null;
//           }
//
//           @Override
//           public SearchCommandData setSearchData(byte[] data) {
//             return null;
//           }
//
//           @Override
//           public SearchCommandData setMask(byte[] mask) {
//             return null;
//           }
//
//           @Override
//           public SearchCommandData fetchFirstMatchingResult() {
//             return null;
//           }
//
//           @Override
//           public List<Integer> getMatchingRecordNumbers() {
//             return null;
//           }
//         });
//   }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenSfiIsNegative_shouldThrowIAE)
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->setSfi(-1).setSearchData({0});

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenSfiGreaterThanSfiMax_shouldThrowIAE)
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->setSfi(31).setSearchData({0});

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenRecordNumberIs0_shouldThrowIAE)
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->startAtRecord(0).setSearchData({0});

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->startAtRecord(251).setSearchData({0});

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenOffsetIsNegative_shouldThrowIAE)
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->setOffset(-1).setSearchData({0});

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenOffsetIsGreaterThan249_shouldThrowIAE)
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->setOffset(250).setSearchData({0});
    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenSearchDataIsNotSet_shouldThrowIAE)
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

// C++: does not apply
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareSearchRecords_whenSearchDataIsNull_shouldThrowIAE)
// {
//     std::shared_ptr<SearchCommandData> data =
//         CalypsoExtensionService::getInstance()
//             ->getCalypsoCardApiFactory()
//             ->createSearchCommandData();
//
//     data->setSearchData(nullptr);
//
//     EXPECT_THROW(
//         cardTransactionManager->prepareSearchRecords(data),
//         IllegalArgumentException);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenSearchDataIsEmpty_shouldThrowIAE)
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->setSearchData({});

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenSearchDataLengthIsGreaterThan250MinusOffset0_shouldThrowIAE)  // NOLINT
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->setSearchData(std::vector<std::uint8_t>(251));

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenSearchDataLengthIsGreaterThan249MinusOffset1_shouldThrowIAE)  // NOLINT
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->setOffset(1).setSearchData(std::vector<std::uint8_t>(250));

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenMaskLengthIsGreaterThanSearchDataLength_shouldThrowIAE)  // NOLINT
{
    std::shared_ptr<SearchCommandData> data
        = CalypsoExtensionService::getInstance()
              ->getCalypsoCardApiFactory()
              ->createSearchCommandData();

    data->setSearchData({0}).setMask({0, 0});

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(data),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenUsingDefaultParameters_shouldPrepareDefaultCommand)
{
    std::vector<std::string> apdus = {
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_FFFF_CMD,
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_FFFF_RSP};  // NOLINT

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::shared_ptr<SearchCommandData> data(
        CalypsoExtensionService::getInstance()
            ->getCalypsoCardApiFactory()
            ->createSearchCommandData());

    data->setSearchData({0x12, 0x34});

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    const std::vector<int> expected {4, 6};
    ASSERT_EQ(data->getMatchingRecordNumbers(), expected);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenSetAllParameters_shouldPrepareCustomCommand)
{
    std::vector<std::string> apdus = {
        CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_CMD,
        CARD_SEARCH_RECORD_MULTIPLE_SFI4_REC2_OFFSET3_FROM_FETCH_1234_FFFF_RSP};  // NOLINT

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::shared_ptr<SearchCommandData> data(
        CalypsoExtensionService::getInstance()
            ->getCalypsoCardApiFactory()
            ->createSearchCommandData());

    data->setSfi(4)
        .startAtRecord(2)
        .setOffset(3)
        .enableRepeatedOffset()
        .setSearchData({0x12, 0x34})
        .fetchFirstMatchingResult();

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    const std::vector<int> expected {4, 6};
    ASSERT_EQ(data->getMatchingRecordNumbers(), expected);
    ASSERT_EQ(
        calypsoCard->getFileBySfi(4)->getData()->getContent(4),
        HexUtil::toByteArray("112233123456"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenNoMask_shouldFillMaskWithFFh)
{
    std::vector<std::string> apdus = {
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_FFFF_CMD,
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_FFFF_RSP};  // NOLINT

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::shared_ptr<SearchCommandData> data(
        CalypsoExtensionService::getInstance()
            ->getCalypsoCardApiFactory()
            ->createSearchCommandData());

    data->setSearchData({0x12, 0x34});

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    const std::vector<int> expected {4, 6};
    ASSERT_EQ(data->getMatchingRecordNumbers(), expected);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenPartialMask_shouldRightPadMaskWithFFh)
{
    std::vector<std::string> apdus = {
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_56FF_CMD,
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_56FF_RSP};  // NOLINT

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::shared_ptr<SearchCommandData> data(
        CalypsoExtensionService::getInstance()
            ->getCalypsoCardApiFactory()
            ->createSearchCommandData());

    data->setSearchData({0x12, 0x34}).setMask({0x56});

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    const std::vector<int> expected {4, 6};
    ASSERT_EQ(data->getMatchingRecordNumbers(), expected);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenFullMask_shouldUseCompleteMask)
{
    std::vector<std::string> apdus = {
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_5677_CMD,
        CARD_SEARCH_RECORD_MULTIPLE_SFI1_REC1_OFFSET0_AT_NO_FETCH_1234_5677_RSP};  // NOLINT

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::shared_ptr<SearchCommandData> data(
        CalypsoExtensionService::getInstance()
            ->getCalypsoCardApiFactory()
            ->createSearchCommandData());

    data->setSearchData({0x12, 0x34}).setMask({0x56, 0x77});

    cardTransactionManager->prepareSearchRecords(data);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    const std::vector<int> expected {4, 6};
    ASSERT_EQ(data->getMatchingRecordNumbers(), expected);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareCheckPinStatus_whenPinFeatureIsNotAvailable_shouldThrowISE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareCheckPinStatus(),
        UnsupportedOperationException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareCheckPinStatus_whenPinFeatureIsAvailable_shouldPrepareCheckPinStatusApdu)  // NOLINT
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    std::vector<std::string> apdus = {CARD_CHECK_PIN_CMD, SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareCheckPinStatus();
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareAppendRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareAppendRecord(
            31, std::vector<std::uint8_t>(3)),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareAppendRecord_whenRecordDataIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareAppendRecord(FILE7, nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateRecord(
            31, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateRecord_whenRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateRecord(
            FILE7, 251, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareUpdateRecord_whenRecordDataIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareUpdateRecord(FILE7, 1, nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteRecord(
            31, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteRecord_whenRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteRecord(
            FILE7, 251, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE)
{
    initCalypsoCardAndTransactionManager(SELECT_APPLICATION_RESPONSE_LIGHT);

    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            1, 1, std::vector<std::uint8_t>(1)),
        UnsupportedOperationException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            -1, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            31, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            1, -1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            1, 32768, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareUpdateBinary_whenDataIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareUpdateBinary(1, 1, nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenDataIsEmpty_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            1, 1, std::vector<std::uint8_t>(0)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD,
           CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP,
           CARD_UPDATE_BINARY_SFI0_OFFSET256_1B_CMD,
           SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareUpdateBinary(
        1, 256, HexUtil::toByteArray("66"));
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenDataLengthIsLessThanPayLoad_shouldPrepareOneCommand)
{
    std::vector<std::string> apdus
        = {CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD, SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    initTransactionManager();

    cardTransactionManager->prepareUpdateBinary(
        1, 4, HexUtil::toByteArray("55"));
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(),
        HexUtil::toByteArray("0000000055"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_UPDATE_BINARY_SFI1_OFFSET0_2B_CMD,
           SW_9000,
           CARD_UPDATE_BINARY_SFI1_OFFSET2_2B_CMD,
           SW_9000,
           CARD_UPDATE_BINARY_SFI1_OFFSET4_1B_CMD,
           SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    initTransactionManager();

    cardTransactionManager->prepareUpdateBinary(
        1, 0, HexUtil::toByteArray("1122334455"));
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(),
        HexUtil::toByteArray("1122334455"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE)
{
    initCalypsoCardAndTransactionManager(SELECT_APPLICATION_RESPONSE_LIGHT);

    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            1, 1, std::vector<std::uint8_t>(1)),
        UnsupportedOperationException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            -1, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            31, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            1, -1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            1, 32768, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareWriteBinary_whenDataIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareWriteBinary(1, 1, nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenDataIsEmpty_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            1, 1, std::vector<std::uint8_t>(0)),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_BINARY_SFI1_OFFSET0_1B_CMD,
           CARD_READ_BINARY_SFI1_OFFSET0_1B_RSP,
           CARD_WRITE_BINARY_SFI0_OFFSET256_1B_CMD,
           SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareWriteBinary(
        1, 256, HexUtil::toByteArray("66"));
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenDataLengthIsLessThanPayLoad_shouldPrepareOneCommand)
{
    std::vector<std::string> apdus
        = {CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD, SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    initTransactionManager();

    cardTransactionManager->prepareWriteBinary(
        1, 4, HexUtil::toByteArray("55"));
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(),
        HexUtil::toByteArray("0000000055"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_WRITE_BINARY_SFI1_OFFSET0_2B_CMD,
           SW_9000,
           CARD_WRITE_BINARY_SFI1_OFFSET2_2B_CMD,
           SW_9000,
           CARD_WRITE_BINARY_SFI1_OFFSET4_1B_CMD,
           SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(2));

    initTransactionManager();

    cardTransactionManager->prepareWriteBinary(
        1, 0, HexUtil::toByteArray("1122334455"));
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(
        calypsoCard->getFileBySfi(1)->getData()->getContent(),
        HexUtil::toByteArray("1122334455"));
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(31, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenValueIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(FILE7, 1, -1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(FILE7, 1, 16777216),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(FILE7, 84, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenParametersAreCorrect_shouldAddDecreaseCommand)
{
    std::vector<std::string> apdus = {
        CARD_INCREASE_SFI11_CNT1_100U_CMD, CARD_INCREASE_SFI11_CNT1_8821U_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareIncreaseCounter(1, 1, 100);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::shared_ptr<int> counterValue(
        calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1));

    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 8821);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenCounterNumberIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(FILE7, -1, 1),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareIncreaseCounter_whenCounterNumberIs0_shouldNotThrowException)
// {
//     FreeTransactionManager& tm(
//         cardTransactionManager->prepareIncreaseCounter(FILE7, 0, 1));
//
//     ASSERT_NE(tm, nullptr);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounters_whenCardIsLowerThanPrime3__shouldAddMultipleIncreaseCommands)  // NOLINT
{
    const CalypsoCard::ProductType& productType(
        CalypsoCard::ProductType::BASIC);

    EXPECT_CALL(*calypsoCard, getProductType())
        .WillRepeatedly(ReturnRef(productType));

    std::vector<std::string> apdus = {
        CARD_INCREASE_SFI11_CNT1_100U_CMD, CARD_INCREASE_SFI11_CNT1_8821U_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::map<int, int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, 100});

    cardTransactionManager->prepareIncreaseCounters(
        1, counterNumberToIncValueMap);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::shared_ptr<int> counterValue(
        calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1));

    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 8821);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounters_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    std::map<int, int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, 1});

    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounters(
            31, counterNumberToIncValueMap),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounters_whenValueIsLessThan0_shouldThrowIAE)
{
    std::map<int, int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, -1});

    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounters(
            FILE7, counterNumberToIncValueMap),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounters_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    std::map<int, int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({84, 1});

    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounters(
            FILE7, counterNumberToIncValueMap),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounters_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    std::map<int, int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, 16777216});

    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounters(
            FILE7, counterNumberToIncValueMap),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounters_whenParametersAreCorrect_shouldAddIncreaseMultipleCommand)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_C3_3_CMD,
           CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_C3_33_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::map<int, int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({3, 3});
    counterNumberToIncValueMap.insert({1, 1});
    counterNumberToIncValueMap.insert({2, 2});

    cardTransactionManager->prepareIncreaseCounters(
        1, counterNumberToIncValueMap);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::shared_ptr<int> counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x11);

    counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(2);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x22);

    counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(3);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x33);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareIncreaseCounters_whenDataLengthIsGreaterThanPayLoad_shouldPrepareMultipleCommands)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_INCREASE_MULTIPLE_SFI1_C1_1_C2_2_CMD,
           CARD_INCREASE_MULTIPLE_SFI1_C1_11_C2_22_RSP,
           CARD_INCREASE_MULTIPLE_SFI1_C3_3_CMD,
           CARD_INCREASE_MULTIPLE_SFI1_C3_33_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(*calypsoCard, getPayloadCapacity()).WillRepeatedly(Return(9));

    initTransactionManager();

    std::map<int, int> counterNumberToIncValueMap;
    counterNumberToIncValueMap.insert({1, 1});
    counterNumberToIncValueMap.insert({2, 2});
    counterNumberToIncValueMap.insert({3, 3});

    cardTransactionManager->prepareIncreaseCounters(
        1, counterNumberToIncValueMap);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::shared_ptr<int> counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x11);

    counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(2);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x22);

    counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(3);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x33);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(31, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenValueIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(FILE7, 1, -1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(FILE7, 1, 16777216),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(FILE7, 84, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenCounterNumberIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(FILE7, -1, 1),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareDecreaseCounter_whenCounterNumberIs0_shouldNotThrowException)
// {
//     FreeTransactionManager& tm(
//         cardTransactionManager->prepareDecreaseCounter(FILE7, 0, 1));
//
//         ASSERT_NE(tm, nullptr);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenParametersAreCorrect_shouldAddDecreaseMultipleCommand)  // NOLINT
{
    std::vector<std::string> apdus = {
        CARD_DECREASE_SFI10_CNT1_100U_CMD, CARD_DECREASE_SFI10_CNT1_4286U_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareDecreaseCounter(1, 1, 100);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::shared_ptr<int> counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 4286);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounters_whenCardIsLowerThanPrime3_shouldThrowUOE)
{
    const CalypsoCard::ProductType productType(CalypsoCard::ProductType::BASIC);
    EXPECT_CALL(*calypsoCard, getProductType())
        .WillRepeatedly(ReturnRef(productType));

    std::vector<std::string> apdus = {
        CARD_DECREASE_SFI10_CNT1_100U_CMD, CARD_DECREASE_SFI10_CNT1_4286U_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::map<int, int> counterNumberToDecValueMap;
    counterNumberToDecValueMap.insert({1, 100});

    cardTransactionManager->prepareDecreaseCounters(
        1, counterNumberToDecValueMap);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::shared_ptr<int> counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 4286);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounters_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    std::map<int, int> counterNumberToDecValueMap;
    counterNumberToDecValueMap.insert({1, 1});

    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounters(
            31, counterNumberToDecValueMap),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounters_whenValueIsLessThan0_shouldThrowIAE)
{
    std::map<int, int> counterNumberToDecValueMap;
    counterNumberToDecValueMap.insert({1, -1});

    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounters(
            FILE7, counterNumberToDecValueMap),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounters_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    std::map<int, int> counterNumberToDecValueMap;
    counterNumberToDecValueMap.insert({84, 1});

    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounters(
            FILE7, counterNumberToDecValueMap),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounters_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    std::map<int, int> counterNumberToDecValueMap;
    counterNumberToDecValueMap.insert({1, 16777216});

    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounters(
            FILE7, counterNumberToDecValueMap),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareDecreaseCounters_whenParametersAreCorrect_shouldAddDecreaseMultipleCommand)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_DECREASE_MULTIPLE_SFI1_C1_11_C2_22_C8_88_CMD,
           CARD_DECREASE_MULTIPLE_SFI1_C1_111_C2_222_C8_888_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    std::map<int, int> counterNumberToDecValueMap;
    counterNumberToDecValueMap.insert({2, 0x22});
    counterNumberToDecValueMap.insert({8, 0x88});
    counterNumberToDecValueMap.insert({1, 0x11});

    cardTransactionManager->prepareDecreaseCounters(
        1, counterNumberToDecValueMap);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::shared_ptr<int> counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(1);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x111);

    counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(2);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x222);

    counterValue
        = calypsoCard->getFileBySfi(1)->getData()->getContentAsCounterValue(8);
    ASSERT_NE(counterValue, nullptr);
    ASSERT_EQ(*counterValue, 0x888);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSetCounter_whenCounterNotPreviouslyRead_shouldThrowISE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareSetCounter(FILE7, 1, 1),
        IllegalStateException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSvReadAllLogs_whenPinFeatureIsNotAvailable_shouldThrowISE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareSvReadAllLogs(),
        UnsupportedOperationException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareSvReadAllLogs_whenNotAnSVApplication_shouldThrowISE)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    EXPECT_THROW(
        cardTransactionManager->prepareSvReadAllLogs(),
        UnsupportedOperationException);
}

// C++: does not apply
// TEST_F(
//     SecureRegularModeTransactionManagerAdapterTest,
//     prepareVerifyPin_whenPINIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager
//             ->prepareVerifyPin(nullptr)
//             .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
//         IllegalArgumentException);
// }

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareVerifyPin_whenPINIsNot4Digits_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareVerifyPin(PIN_5_DIGITS_BYTES)
            .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
        IllegalArgumentException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareVerifyPin_whenPINNotAvailable_shouldThrowUOE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareVerifyPin(PIN_OK_BYTES)
            .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
        UnsupportedOperationException);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareVerifyPin_whenPINTransmittedInPlainText_shouldSendApduVerifyPIN)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    std::vector<std::string> apdus = {CARD_VERIFY_PIN_PLAIN_OK_CMD, SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareVerifyPin(PIN_OK_BYTES)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    // verifyNoMoreInteractions(cardReader);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    prepareChangePin_whenTransmissionIsPlain_shouldSendApdusToTheCardAndTheSAM)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    calypsoCard->setPinAttemptRemaining(3);

    std::vector<std::string> apdus
        = {CARD_CHANGE_PIN_PLAIN_CMD, CARD_CHANGE_PIN_PLAIN_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareChangePin(NEW_PIN_BYTES)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    // verifyNoMoreInteractions(cardReader);
}

TEST_F(
    SecureRegularModeTransactionManagerAdapterTest,
    processCommands_whenOutOfSession_shouldExchangeApduWithCardOnly)
{
    std::vector<std::string> apdus
        = {CARD_READ_REC_SFI7_REC1_L29_CMD,
           CARD_READ_REC_SFI7_REC1_RSP,
           CARD_READ_REC_SFI8_REC1_L29_CMD,
           CARD_READ_REC_SFI8_REC1_RSP,
           CARD_READ_REC_SFI10_REC1_CMD,
           CARD_READ_REC_SFI10_REC1_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareReadRecords(FILE7, 1, 1, RECORD_SIZE);
    cardTransactionManager->prepareReadRecords(FILE8, 1, 1, RECORD_SIZE);
    cardTransactionManager->prepareReadRecords(FILE10, 1, 1, 34);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}
