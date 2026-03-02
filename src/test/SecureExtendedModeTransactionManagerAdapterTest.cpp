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
#include "keyple/card/calypso/SecureExtendedModeTransactionManagerAdapter.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/calypso/card/GetDataTag.hpp"
#include "keypop/calypso/card/SelectFileControl.hpp"
#include "keypop/calypso/card/WriteAccessLevel.hpp"
#include "keypop/calypso/card/card/CalypsoCard.hpp"
#include "keypop/calypso/card/card/ElementaryFile.hpp"
#include "keypop/calypso/card/card/FileHeader.hpp"
#include "keypop/calypso/card/card/SvDebitLogRecord.hpp"
#include "keypop/calypso/card/card/SvLoadLogRecord.hpp"
#include "keypop/calypso/card/cpp/SecureExtendedModeTransactionManagerBase.hpp"
#include "keypop/calypso/card/transaction/FreeTransactionManager.hpp"
#include "keypop/calypso/card/transaction/InvalidCardSignatureException.hpp"
#include "keypop/calypso/card/transaction/SearchCommandData.hpp"
#include "keypop/calypso/card/transaction/SvAction.hpp"
#include "keypop/calypso/card/transaction/SvOperation.hpp"
#include "keypop/calypso/card/transaction/SymmetricCryptoSecuritySetting.hpp"
#include "keypop/calypso/card/transaction/UnauthorizedKeyException.hpp"
#include "keypop/reader/selection/InvalidCardResponseException.hpp"

#include "AbstractTransactionManagerTest.hpp"
#include "mock/SymmetricCryptoCardTransactionManagerFactoryMock.hpp"
#include "mock/SymmetricCryptoCardTransactionManagerMock.hpp"

using keyple::card::calypso::CalypsoExtensionService;
using keyple::card::calypso::SecureExtendedModeTransactionManagerAdapter;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::calypso::card::GetDataTag;
using keypop::calypso::card::SelectFileControl;
using keypop::calypso::card::WriteAccessLevel;
using keypop::calypso::card::card::CalypsoCard;
using keypop::calypso::card::card::ElementaryFile;
using keypop::calypso::card::card::FileHeader;
using keypop::calypso::card::card::SvDebitLogRecord;
using keypop::calypso::card::card::SvLoadLogRecord;
using keypop::calypso::card::cpp::SecureExtendedModeTransactionManagerBase;
using keypop::calypso::card::transaction::FreeTransactionManager;
using keypop::calypso::card::transaction::InvalidCardSignatureException;
using keypop::calypso::card::transaction::SearchCommandData;
using keypop::calypso::card::transaction::SvAction;
using keypop::calypso::card::transaction::SvOperation;
using keypop::calypso::card::transaction::SymmetricCryptoSecuritySetting;
using keypop::calypso::card::transaction::UnauthorizedKeyException;
using keypop::reader::selection::InvalidCardResponseException;

using testing::InSequence;
using testing::InvokeWithoutArgs;
using testing::ReturnRef;
using testing::Truly;

using SecureExtendedModeTransactionManager
    = keypop::calypso::card::cpp::SecureExtendedModeTransactionManagerBase;

class SecureExtendedModeTransactionManagerAdapterTest
: public ::testing::Test,
  public AbstractTransactionManagerTest {
protected:
    void
    SetUp() override
    {
        /* Mock reader */
        cardReader = std::make_shared<ReaderMock>();

        /* Mock crypto manager */
        const std::vector<std::uint8_t> samChallenge(
            HexUtil::toByteArray(SAM_CHALLENGE));
        const std::vector<std::uint8_t> samSignature(
            HexUtil::toByteArray(SAM_SIGNATURE));
        const std::vector<std::uint8_t> cardSignature(
            HexUtil::toByteArray(CARD_SIGNATURE));

        symmetricCryptoCardTransactionManager
            = std::make_shared<SymmetricCryptoCardTransactionManagerMock>();
        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .WillRepeatedly(Return(samChallenge));
        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            finalizeTerminalSessionMac())
            .WillRepeatedly(Return(samSignature));
        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            isCardSessionMacValid(cardSignature))
            .WillRepeatedly(Return(true));

        /* Mock crypto factory */
        symmetricCryptoCardTransactionManagerFactory = std::make_shared<
            SymmetricCryptoCardTransactionManagerFactoryMock>();
        EXPECT_CALL(
            *symmetricCryptoCardTransactionManagerFactory,
            getMaxCardApduLengthSupported())
            .WillRepeatedly(Return(250));
        EXPECT_CALL(
            *symmetricCryptoCardTransactionManagerFactory,
            isExtendedModeSupported())
            .WillRepeatedly(Return(true));
        EXPECT_CALL(
            *symmetricCryptoCardTransactionManagerFactory,
            createCardTransactionManager(
                HexUtil::toByteArray(CARD_SERIAL_NUMBER), _, _))
            .WillRepeatedly(Return(symmetricCryptoCardTransactionManager));

        /* Mock security setting */
        cardSecuritySetting
            = CalypsoExtensionService::getInstance()
                  ->getCalypsoCardApiFactory()
                  ->createSymmetricCryptoSecuritySetting(
                      symmetricCryptoCardTransactionManagerFactory);

        initCalypsoCardAndTransactionManager(
            SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);
    }

    void
    TearDown() override
    {
        cardReader.reset();
        cardTransactionManager.reset();
        symmetricCryptoCardTransactionManager.reset();
        symmetricCryptoCardTransactionManagerFactory.reset();
        cardSecuritySetting.reset();
    }

    void
    initTransactionManager() override
    {
        cardTransactionManager
            = CalypsoExtensionService::getInstance()
                  ->getCalypsoCardApiFactory()
                  ->createSecureExtendedModeTransactionManager(
                      cardReader, calypsoCard, cardSecuritySetting);
    }

    std::unique_ptr<SecureExtendedModeTransactionManager>
        cardTransactionManager;
    std::shared_ptr<SymmetricCryptoSecuritySetting> cardSecuritySetting;
    std::shared_ptr<SymmetricCryptoCardTransactionManagerFactoryMock>
        symmetricCryptoCardTransactionManagerFactory;
    std::shared_ptr<SymmetricCryptoCardTransactionManagerMock>
        symmetricCryptoCardTransactionManager;
};

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSelectFile_whenSelectFileControlIsFirstEF_shouldPrepareSelectFileApduWithP2_02_P1_00)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_SELECT_FILE_FIRST_CMD, CARD_SELECT_FILE_1234_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareSelectFile(SelectFileControl::FIRST_EF);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSelectFile_whenSelectFileControlIsNextEF_shouldPrepareSelectFileApduWithP2_02_P1_02)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_SELECT_FILE_NEXT_CMD, CARD_SELECT_FILE_1234_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareSelectFile(SelectFileControl::NEXT_EF);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
//     SecureExtendedModeTransactionManagerAdapterTest,
//     prepareGetData_whenGetDataTagIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareGetData(nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareGetData_whenGetDataTagIsFCP_shouldPrepareSelectFileApduWithTagFCP)
{
    std::vector<std::string> apdus
        = {CARD_GET_DATA_FCP_CMD, CARD_GET_DATA_FCP_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareGetData(GetDataTag::FCP_FOR_CURRENT_FILE);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareGetData_whenGetDataTagIsFCI_shouldPrepareSelectFileApduWithTagFCI)
{
    std::vector<std::string> apdus
        = {CARD_GET_DATA_FCI_CMD, CARD_GET_DATA_FCI_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareGetData(GetDataTag::FCI_FOR_CURRENT_DF);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecord(31, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecord_whenRecordNumberIsLessThan0_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecord(FILE7, -1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecord_whenRecordNumberIsMoreThan250_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecord(FILE7, 251),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecord_whenSfi07RecNumber1_shouldPrepareReadRecordApduWithSfi07RecNumber1)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_READ_REC_SFI7_REC1_CMD, CARD_READ_REC_SFI7_REC1_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareReadRecord(FILE7, 1);
    cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecords_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(31, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecords_whenFromRecordNumberIs0_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(FILE7, 0, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecords_whenFromRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(FILE7, 251, 251, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecords_whenToRecordNumberIsLessThanFromRecordNumber_shouldThrowIAE)  // NOLINT
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(FILE7, 2, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecords_whenToRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    ASSERT_THROW(
        cardTransactionManager->prepareReadRecords(FILE7, 1, 251, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenProductTypeIsNotPrimeRev3OrLight_shouldThrowUOE)  // NOLINT
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);

    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 1, 1),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(-1, 1, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(31, 1, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenFromRecordNumberIsZero_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 0, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenFromRecordNumberGreaterThan250_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 251, 251, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenToRecordNumberLessThanFromRecordNumber_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 2, 1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenToRecordNumberGreaterThan250MinusFromRecordNumber_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 251, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, -1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenOffsetGreaterThan249_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 250, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenNbBytesToReadIsZero_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 1, 0),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadRecordsPartially_whenNbBytesToReadIsGreaterThan250MinusOffset_shouldThrowIAE)  // NOLINT
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadRecordsPartially(1, 1, 1, 3, 248),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadBinary_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(-1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(31, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(1, -1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(1, 32768, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadBinary_whenNbBytesToReadIsLessThan1_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadBinary(1, 1, 0),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareReadCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareReadCounter(31, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenProductTypeIsNotPrimeRev3_shouldThrowUOE)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2);

    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(nullptr),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSearchRecords_whenDataIsNull_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareSearchRecords(nullptr),
        IllegalArgumentException);
}

// C++: does not apply
// @Test(expected = IllegalArgumentException.class)
// TEST_F(
//     SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
//     SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareCheckPinStatus_whenPinFeatureIsNotAvailable_shouldThrowISE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareCheckPinStatus(),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareAppendRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareAppendRecord(
            31, std::vector<std::uint8_t>(3)),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureExtendedModeTransactionManagerAdapterTest,
//     prepareAppendRecord_whenRecordDataIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareAppendRecord(FILE7, nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareUpdateRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateRecord(
            31, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareUpdateRecord_whenRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateRecord(
            FILE7, 251, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureExtendedModeTransactionManagerAdapterTest,
//     prepareUpdateRecord_whenRecordDataIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareUpdateRecord(FILE7, 1, nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareWriteRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteRecord(
            31, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareWriteRecord_whenRecordNumberIsGreaterThan250_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteRecord(
            FILE7, 251, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE)
{
    initCalypsoCardAndTransactionManager(SELECT_APPLICATION_RESPONSE_LIGHT);

    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            1, 1, std::vector<std::uint8_t>(1)),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            -1, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            31, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            1, -1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            1, 32768, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureExtendedModeTransactionManagerAdapterTest,
//     prepareUpdateBinary_whenDataIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareUpdateBinary(1, 1, nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareUpdateBinary_whenDataIsEmpty_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareUpdateBinary(
            1, 1, std::vector<std::uint8_t>(0)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenProductTypeIsNotPrimeRev2OrRev3_shouldThrowUOE)
{
    initCalypsoCardAndTransactionManager(SELECT_APPLICATION_RESPONSE_LIGHT);

    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            1, 1, std::vector<std::uint8_t>(1)),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            -1, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            31, 1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            1, -1, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            1, 32768, std::vector<std::uint8_t>(1)),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureExtendedModeTransactionManagerAdapterTest,
//     prepareWriteBinary_whenDataIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager->prepareWriteBinary(1, 1, nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareWriteBinary_whenDataIsEmpty_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareWriteBinary(
            1, 1, std::vector<std::uint8_t>(0)),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(31, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenValueIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(FILE7, 1, -1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(FILE7, 1, 16777216),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(FILE7, 84, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareIncreaseCounter_whenCounterNumberIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareIncreaseCounter(FILE7, -1, 1),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureExtendedModeTransactionManagerAdapterTest,
//     prepareIncreaseCounter_whenCounterNumberIs0_shouldNotThrowException)
// {
//     SecureExtendedModeTransactionManager& tm(
//         cardTransactionManager->prepareIncreaseCounter(FILE7, 0, 1));
//
//     ASSERT_NE(tm, nullptr);
// }

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(31, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenValueIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(FILE7, 1, -1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenValueIsGreaterThan16777215_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(FILE7, 1, 16777216),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenCounterNumberIsGreaterThan83_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(FILE7, 84, 1),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareDecreaseCounter_whenCounterNumberIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareDecreaseCounter(FILE7, -1, 1),
        IllegalArgumentException);
}

// C++: not applicable
// TEST_F(
//     SecureExtendedModeTransactionManagerAdapterTest,
//     prepareDecreaseCounter_whenCounterNumberIs0_shouldNotThrowException)
// {
//     SecureExtendedModeTransactionManager& tm(
//         cardTransactionManager->prepareDecreaseCounter(FILE7, 0, 1));
//
//         ASSERT_NE(tm, nullptr);
// }

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
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
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSetCounter_whenCounterNotPreviouslyRead_shouldThrowISE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareSetCounter(FILE7, 1, 1),
        IllegalStateException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvReadAllLogs_whenPinFeatureIsNotAvailable_shouldThrowISE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareSvReadAllLogs(),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
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
//     SecureExtendedModeTransactionManagerAdapterTest,
//     prepareVerifyPin_whenPINIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardTransactionManager
//             ->prepareVerifyPin(nullptr)
//             .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
//         IllegalArgumentException);
// }

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareVerifyPin_whenPINIsNot4Digits_shouldThrowIAE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareVerifyPin(PIN_5_DIGITS_BYTES)
            .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
        IllegalArgumentException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareVerifyPin_whenPINNotAvailable_shouldThrowUOE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareVerifyPin(PIN_OK_BYTES)
            .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareVerifyPin_whenPINTransmittedInPlainText_shouldSendApduVerifyPIN)
{
    cardSecuritySetting->enablePinPlainTransmission();

    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    std::vector<std::string> apdus = {CARD_VERIFY_PIN_PLAIN_OK_CMD, SW_9000};

    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    cardTransactionManager->prepareVerifyPin(PIN_OK_BYTES)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    // verifyNoMoreInteractions(cardReader);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareChangePin_whenTransmissionIsPlain_shouldSendApdusToTheCardAndTheSAM)
{
    cardSecuritySetting->enablePinPlainTransmission();

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
    SecureExtendedModeTransactionManagerAdapterTest,
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

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    CryptoExtension_shouldReturnANonNullReference)
{
    std::shared_ptr<SymmetricCryptoCardTransactionManagerMock> cryptoExtension(
        std::dynamic_pointer_cast<SymmetricCryptoCardTransactionManagerMock>(
            cardTransactionManager->getCryptoExtension()));

    ASSERT_NE(cryptoExtension, nullptr);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareCloseSecureSession_whenNoSessionIsOpen_shouldThrowISE)
{
    EXPECT_THROW(
        cardTransactionManager->prepareCloseSecureSession().processCommands(
            CHANNEL_CONTROL_KEEP_OPEN),
        IllegalStateException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareCloseSecureSession_whenASessionIsOpen_shouldInteractWithCardAndCryptoManager)  // NOLINT
{
    std::vector<std::string> apdusCardRequest
        = {CARD_OPEN_SECURE_SESSION_CMD, CARD_OPEN_SECURE_SESSION_RSP};

    std::shared_ptr<CardRequestSpi> cardRequest(
        mockTransmitCardRequest(apdusCardRequest));

    std::vector<std::string> apdusCardRequestRead
        = {CARD_READ_REC_SFI7_REC1_L29_CMD, CARD_READ_REC_SFI7_REC1_RSP};

    std::shared_ptr<CardRequestSpi> cardRequestRead(
        mockTransmitCardRequest(apdusCardRequestRead));

    std::vector<std::string> apdusCardRequestClose
        = {CARD_CLOSE_SECURE_SESSION_CMD, CARD_CLOSE_SECURE_SESSION_RSP};

    std::shared_ptr<CardRequestSpi> cardRequestClose(
        mockTransmitCardRequest(apdusCardRequestClose));

    /*
     * GMock has no post-hoc equivalent of Mockito's InOrder.verify(): ordering
     * constraints have to be registered as expectations before the calls they
     * cover, via testing::InSequence, which chains every EXPECT_CALL created
     * while it's alive into a single sequence -- across different mock
     * objects too. Each expectation below takes precedence (GMock resolves
     * overlapping expectations in reverse registration order) over the
     * mockTransmitCardRequest()/SetUp() catch-all WillRepeatedly()
     * expectations for exactly the one call it matches, then falls back to
     * them for anything unexpected.
     *
     * The transmitCardRequest() expectations still delegate to the shared
     * FIFO (popNextQueuedCardResponse()) instead of hand-supplying a
     * response, so the returned card data stays whatever
     * mockTransmitCardRequest() queued above; only the argument content
     * (matched via CardRequestMatcher, mirroring Java's
     * argThat(new CardRequestMatcher(...))) and the call order are being
     * verified here.
     */
    {
        InSequence seq;

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly([cardRequestRead](
                          const std::shared_ptr<CardRequestSpi>& req) {
                    return CardRequestMatcher(cardRequestRead).matches(req);
                }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_L29_CMD)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_RSP)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            finalizeTerminalSessionMac())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_SIGNATURE)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly([cardRequestClose](
                          const std::shared_ptr<CardRequestSpi>& req) {
                    return CardRequestMatcher(cardRequestClose).matches(req);
                }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            isCardSessionMacValid(HexUtil::toByteArray(CARD_SIGNATURE)))
            .Times(1)
            .WillOnce(Return(true));

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    /*
     * Not part of the InOrder chain above (the original Java test verifies
     * it separately too): it happens even before the "Open Secure Session"
     * APDU is built, since the SAM challenge is embedded in it.
     */
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager,
        initTerminalSecureSessionContext())
        .Times(1)
        .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE)));

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    cardTransactionManager->prepareReadRecords(FILE7, 1, 1, 29)
        .prepareCloseSecureSession()
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareCloseSecureSession_whenCloseSessionFails_shouldThrowUCSE)  // NOLINT
{
    std::vector<std::string> apdusOpen
        = {CARD_OPEN_SECURE_SESSION_CMD, CARD_OPEN_SECURE_SESSION_RSP};
    mockTransmitCardRequest(apdusOpen);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::vector<std::string> apdusClose
        = {CARD_CLOSE_SECURE_SESSION_CMD, SW_INCORRECT_SIGNATURE};
    mockTransmitCardRequest(apdusClose);

    EXPECT_THROW(
        cardTransactionManager->prepareCloseSecureSession().processCommands(
            CHANNEL_CONTROL_KEEP_OPEN),
        InvalidCardResponseException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareCloseSecureSession_whenCardAuthenticationFails_shouldThrowICME)  // NOLINT
{
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager,
        isCardSessionMacValid(HexUtil::toByteArray(CARD_SIGNATURE)))
        .WillRepeatedly(Return(false));

    std::vector<std::string> apdusOpen
        = {CARD_OPEN_SECURE_SESSION_CMD, CARD_OPEN_SECURE_SESSION_RSP};
    mockTransmitCardRequest(apdusOpen);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::vector<std::string> apdusClose
        = {CARD_CLOSE_SECURE_SESSION_CMD, CARD_CLOSE_SECURE_SESSION_RSP};
    mockTransmitCardRequest(apdusClose);

    EXPECT_THROW(
        cardTransactionManager->prepareCloseSecureSession().processCommands(
            CHANNEL_CONTROL_KEEP_OPEN),
        InvalidCardSignatureException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareCancelSecureSession_whenNoSessionIsOpen_shouldDoBestEffortMode)  // NOLINT
{
    std::vector<std::string> apdus = {CARD_ABORT_SECURE_SESSION_CMD, SW_9000};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(
        *cardReader,
        transmitCardRequest(
            Truly([cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                return CardRequestMatcher(cardRequest).matches(req);
            }),
            _))
        .Times(1)
        .WillOnce(InvokeWithoutArgs(
            [this]() { return popNextQueuedCardResponse(); }));

    cardTransactionManager->prepareCancelSecureSession().processCommands(
        CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareCancelSecureSession_whenASessionIsOpen_shouldSendCancelApduToCard)  // NOLINT
{
    std::vector<std::string> apdusOpen
        = {CARD_OPEN_SECURE_SESSION_CMD, CARD_OPEN_SECURE_SESSION_RSP};
    std::shared_ptr<CardRequestSpi> cardRequestOpen(
        mockTransmitCardRequest(apdusOpen));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly([cardRequestOpen](
                          const std::shared_ptr<CardRequestSpi>& req) {
                    return CardRequestMatcher(cardRequestOpen).matches(req);
                }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    std::vector<std::string> apdusCancel
        = {CARD_ABORT_SECURE_SESSION_CMD, SW_9000};
    std::shared_ptr<CardRequestSpi> cardRequestCancel(
        mockTransmitCardRequest(apdusCancel));

    {
        InSequence seq;

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly([cardRequestCancel](
                          const std::shared_ptr<CardRequestSpi>& req) {
                    return CardRequestMatcher(cardRequestCancel).matches(req);
                }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    cardTransactionManager->prepareCancelSecureSession().processCommands(
        CHANNEL_CONTROL_KEEP_OPEN);
}
//
TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenNoCommandsArePrepared_shouldInteractWithCardAndCryptoManager)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_CMD, CARD_OPEN_SECURE_SESSION_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenSuccessful_shouldUpdateTransactionCounterAndRatificationStatus)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_CMD, CARD_OPEN_SECURE_SESSION_RSP};
    mockTransmitCardRequest(apdus);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_TRUE(calypsoCard->isDfRatified());
    ASSERT_EQ(calypsoCard->getTransactionCounter(), 0x030490);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenOneReadRecordIsPrepared_shouldInteractWithCardAndCryptoManager)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD,
           CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(
                    CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenTwoReadRecordArePreparedAndNoRestrictions_shouldMergeFirstReadRecord)  // NOLINT
{
    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD,
           CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP,
           CARD_READ_REC_SFI8_REC1_L29_CMD,
           CARD_READ_REC_SFI8_REC1_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(
                    CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI8_REC1_L29_CMD)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI8_REC1_RSP)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .prepareReadRecords(FILE8, 1, 1, RECORD_SIZE)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenTwoReadRecordArePreparedAndReadOnSessionOpeningIsDisabled_shouldNotMergeFirstReadRecord)  // NOLINT
{
    cardSecuritySetting->disableReadOnSessionOpening();

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_CMD,
           CARD_OPEN_SECURE_SESSION_RSP,
           CARD_READ_REC_SFI7_REC1_L29_CMD,
           CARD_READ_REC_SFI7_REC1_RSP,
           CARD_READ_REC_SFI8_REC1_L29_CMD,
           CARD_READ_REC_SFI8_REC1_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_L29_CMD)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_RSP)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI8_REC1_L29_CMD)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI8_REC1_RSP)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .prepareReadRecords(FILE8, 1, 1, RECORD_SIZE)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}
//
TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenTwoReadRecordArePreparedAndPreOpenVariant_shouldNotMergeFirstReadRecord)  // NOLINT
{
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    calypsoCard->setPreOpenWriteAccessLevel(WriteAccessLevel::DEBIT);
    calypsoCard->setPreOpenDataOut(
        HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP));
    initTransactionManager();

    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager, finalizeTerminalSessionMac())
        .WillRepeatedly(Return(HexUtil::toByteArray(SAM_SIGNATURE_EXTENDED)));
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager,
        isCardSessionMacValid(HexUtil::toByteArray(CARD_SIGNATURE_EXTENDED)))
        .WillRepeatedly(Return(true));

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
           CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
           CARD_READ_REC_SFI7_REC1_L29_CMD,
           CARD_READ_REC_SFI7_REC1_RSP,
           CARD_READ_REC_SFI8_REC1_L29_CMD,
           CARD_READ_REC_SFI8_REC1_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE_EXTENDED)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(
                    CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_L29_CMD)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_RSP)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI8_REC1_L29_CMD)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI8_REC1_RSP)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .prepareReadRecords(FILE8, 1, 1, RECORD_SIZE)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenPreOpenVariantWithDifferentWriteAccessLevel_shouldIgnoreThePreopenMode)  // NOLINT
{
    calypsoCard->setPreOpenWriteAccessLevel(WriteAccessLevel::LOAD);
    calypsoCard->setPreOpenDataOut(
        HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP));

    initTransactionManager();

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD,
           CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(
                    CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenPreOpenVariantButNotAtomicSession_shouldNotAnticipateDataOut)  // NOLINT
{
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    calypsoCard->setPreOpenWriteAccessLevel(WriteAccessLevel::DEBIT);
    calypsoCard->setPreOpenDataOut(
        HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_RSP));
    initTransactionManager();

    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager, finalizeTerminalSessionMac())
        .WillRepeatedly(Return(HexUtil::toByteArray(SAM_SIGNATURE_EXTENDED)));
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager,
        isCardSessionMacValid(HexUtil::toByteArray(CARD_SIGNATURE_EXTENDED)))
        .WillRepeatedly(Return(true));

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
           CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
           CARD_READ_REC_SFI7_REC1_L29_CMD,
           CARD_READ_REC_SFI7_REC1_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE_EXTENDED)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(
                    CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_L29_CMD)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_RSP)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenPreOpenVariantButExtendedModeNotSupportedByCryptoModule_shouldProcessInRegularMode)  // NOLINT
{
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManagerFactory,
        isExtendedModeSupported())
        .WillRepeatedly(Return(false));

    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    calypsoCard->setPreOpenWriteAccessLevel(WriteAccessLevel::DEBIT);
    calypsoCard->setPreOpenDataOut(
        HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_RSP));
    initTransactionManager();

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_SFI7_REC1_CMD,
           CARD_OPEN_SECURE_SESSION_SFI7_REC1_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(
                    CARD_OPEN_SECURE_SESSION_SFI7_REC1_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .prepareReadRecords(FILE7, 1, 1, RECORD_SIZE)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenPreOpenVariantAndExtendedModeSupportedByCryptoModule_shouldBeSuccessful)  // NOLINT
{
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    calypsoCard->setPreOpenWriteAccessLevel(WriteAccessLevel::DEBIT);
    calypsoCard->setPreOpenDataOut(
        HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT));
    initTransactionManager();

    calypsoCard->setContent(FILE7, 1, HexUtil::toByteArray(FILE7_REC1_29B));

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
           CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
           CARD_READ_REC_SFI7_REC1_L29_CMD,
           CARD_READ_REC_SFI7_REC1_RSP,
           CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD,
           CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    {
        InSequence seq;

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSecureSessionContext())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_CHALLENGE_EXTENDED)));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            initTerminalSessionMac(
                HexUtil::toByteArray(
                    CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT),
                HexUtil::toByte(KIF),
                HexUtil::toByte(KVC)))
            .Times(1);

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_L29_CMD)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            updateTerminalSessionMac(
                HexUtil::toByteArray(CARD_READ_REC_SFI7_REC1_RSP)))
            .Times(1)
            .WillOnce(Return(std::vector<std::uint8_t> {}));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            finalizeTerminalSessionMac())
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(SAM_SIGNATURE_EXTENDED)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly(
                    [cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                        return CardRequestMatcher(cardRequest).matches(req);
                    }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            isCardSessionMacValid(
                HexUtil::toByteArray(CARD_SIGNATURE_EXTENDED)))
            .Times(1)
            .WillOnce(Return(true));

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
        .prepareReadRecords(FILE7, 1, 1, 29)
        .prepareCloseSecureSession()
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenPreOpenVariantWithDifferentDataOut_shouldThrowUCSE)  // NOLINT
{
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    calypsoCard->setPreOpenWriteAccessLevel(WriteAccessLevel::DEBIT);
    calypsoCard->setPreOpenDataOut(
        HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT_2));
    calypsoCard->setContent(FILE7, 1, HexUtil::toByteArray(FILE7_REC1_29B));
    initTransactionManager();

    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager,
        initTerminalSecureSessionContext())
        .WillRepeatedly(Return(HexUtil::toByteArray(SAM_CHALLENGE_EXTENDED)));
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager, finalizeTerminalSessionMac())
        .WillRepeatedly(Return(HexUtil::toByteArray(SAM_SIGNATURE_EXTENDED)));
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager,
        isCardSessionMacValid(HexUtil::toByteArray(CARD_SIGNATURE_EXTENDED)))
        .WillRepeatedly(Return(true));

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
           CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
           CARD_READ_REC_SFI7_REC1_L29_CMD,
           CARD_READ_REC_SFI7_REC1_RSP,
           CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD,
           CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP};
    mockTransmitCardRequest(apdus);

    EXPECT_THROW(
        dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
            cardTransactionManager.get())
            ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
            .prepareReadRecords(FILE7, 1, 1, 29)
            .prepareCloseSecureSession()
            .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
        InvalidCardResponseException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenPreOpenVariantWithDifferentRecordContent_shouldThrowUCSE)  // NOLINT
{
    initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
    calypsoCard->setPreOpenWriteAccessLevel(WriteAccessLevel::DEBIT);
    calypsoCard->setPreOpenDataOut(
        HexUtil::toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT_2));
    calypsoCard->setContent(FILE7, 1, HexUtil::toByteArray(FILE7_REC2_29B));
    initTransactionManager();

    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager,
        initTerminalSecureSessionContext())
        .WillRepeatedly(Return(HexUtil::toByteArray(SAM_CHALLENGE_EXTENDED)));
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager, finalizeTerminalSessionMac())
        .WillRepeatedly(Return(HexUtil::toByteArray(SAM_SIGNATURE_EXTENDED)));
    EXPECT_CALL(
        *symmetricCryptoCardTransactionManager,
        isCardSessionMacValid(HexUtil::toByteArray(CARD_SIGNATURE_EXTENDED)))
        .WillRepeatedly(Return(true));

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
           CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
           CARD_READ_REC_SFI7_REC1_L29_CMD,
           CARD_READ_REC_SFI7_REC1_RSP,
           CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD,
           CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP};
    mockTransmitCardRequest(apdus);

    EXPECT_THROW(
        dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
            cardTransactionManager.get())
            ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
            .prepareReadRecords(FILE7, 1, 1, 29)
            .prepareCloseSecureSession()
            .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
        InvalidCardResponseException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareOpenSecureSession_whenKeyNotAuthorized_shouldThrowUnauthorizedKeyException)  // NOLINT
{
    /* Force the checking of the session key to fail. */
    cardSecuritySetting->addAuthorizedSessionKey(
        static_cast<std::uint8_t>(0x00), static_cast<std::uint8_t>(0x00));

    std::vector<std::string> apdus
        = {CARD_OPEN_SECURE_SESSION_CMD, CARD_OPEN_SECURE_SESSION_RSP};
    mockTransmitCardRequest(apdus);

    EXPECT_THROW(
        dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
            cardTransactionManager.get())
            ->prepareOpenSecureSession(WriteAccessLevel::DEBIT)
            .processCommands(CHANNEL_CONTROL_KEEP_OPEN),
        UnauthorizedKeyException);
}
//
/*
 * Note: the Java prepareSvGet_whenSvOperationNull_shouldThrowIAE and
 * prepareSvGet_whenSvActionNull_shouldThrowIAE tests are not portable: they
 * exercise a null check on a Java enum reference, but SvOperation/SvAction
 * are plain C++ enum class values with no null state, so there is nothing
 * analogous to convert.
 */

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvGet_whenSvOperationNotAvailable_shouldThrowUOE)  // NOLINT
{
    EXPECT_THROW(
        dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
            cardTransactionManager.get())
            ->prepareSvGet(SvOperation::DEBIT, SvAction::DO),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvGet_whenSvOperationDebit_shouldPrepareSvGetDebitApdu)  // NOLINT
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    std::vector<std::string> apdus
        = {CARD_SV_GET_DEBIT_CMD, CARD_SV_GET_DEBIT_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(
        *cardReader,
        transmitCardRequest(
            Truly([cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                return CardRequestMatcher(cardRequest).matches(req);
            }),
            _))
        .Times(1)
        .WillOnce(InvokeWithoutArgs(
            [this]() { return popNextQueuedCardResponse(); }));

    EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize()).Times(1);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareSvGet(SvOperation::DEBIT, SvAction::DO)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvGet_whenSvOperationReload_shouldPrepareSvGetReloadApdu)  // NOLINT
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    std::vector<std::string> apdus
        = {CARD_SV_GET_RELOAD_CMD, CARD_SV_GET_RELOAD_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(
        *cardReader,
        transmitCardRequest(
            Truly([cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                return CardRequestMatcher(cardRequest).matches(req);
            }),
            _))
        .Times(1)
        .WillOnce(InvokeWithoutArgs(
            [this]() { return popNextQueuedCardResponse(); }));

    EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize()).Times(1);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareSvGet(SvOperation::RELOAD, SvAction::DO)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvGet_whenSvOperationReloadWithPrimeRev2_shouldPrepareSvGetReloadApdu)  // NOLINT
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_2_WITH_STORED_VALUE);

    std::vector<std::string> apdus
        = {CARD_PRIME_REV2_SV_GET_RELOAD_CMD, CARD_SV_GET_RELOAD_RSP};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(
        *cardReader,
        transmitCardRequest(
            Truly([cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                return CardRequestMatcher(cardRequest).matches(req);
            }),
            _))
        .Times(1)
        .WillOnce(InvokeWithoutArgs(
            [this]() { return popNextQueuedCardResponse(); }));

    EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize()).Times(1);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareSvGet(SvOperation::RELOAD, SvAction::DO)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}
//
TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvReload_whenNoSvGetPreviouslyExecuted_shouldThrowISE)  // NOLINT
{
    EXPECT_THROW(
        dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
            cardTransactionManager.get())
            ->prepareSvReload(1),
        IllegalStateException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvReload_whenOutOfSession_InRegularMode_shouldUpdateReloadLog)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    std::vector<std::string> apdus
        = {CARD_SV_GET_RELOAD_CMD, CARD_SV_GET_RELOAD_RSP};
    mockTransmitCardRequest(apdus);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareSvGet(SvOperation::RELOAD, SvAction::DO)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(calypsoCard->getSvBalance(), HexUtil::toInt(SV_R_BALANCE));
    ASSERT_EQ(calypsoCard->getSvLastTNum(), HexUtil::toShort(SV_R_TNUM));
    std::shared_ptr<SvLoadLogRecord> loadLog1(
        calypsoCard->getSvLoadLogRecord());
    ASSERT_EQ(loadLog1->getLoadDate(), HexUtil::toByteArray(SV_R_LOG_DATE));
    ASSERT_EQ(loadLog1->getLoadTime(), HexUtil::toByteArray(SV_R_LOG_TIME));
    ASSERT_EQ(loadLog1->getBalance(), HexUtil::toInt(SV_R_LOG_BALANCE));
    ASSERT_EQ(loadLog1->getAmount(), HexUtil::toInt(SV_R_LOG_AMOUNT));
    ASSERT_EQ(
        loadLog1->getFreeData(),
        HexUtil::toByteArray(SV_R_LOG_FREE1 + SV_R_LOG_FREE2));
    ASSERT_EQ(loadLog1->getKvc(), HexUtil::toByte(SV_R_LOG_KVC));
    ASSERT_EQ(loadLog1->getSamId(), HexUtil::toByteArray(SV_R_LOG_SAM_ID));
    ASSERT_EQ(loadLog1->getSamTNum(), HexUtil::toInt(SV_R_LOG_SAM_TNUM));
    ASSERT_EQ(loadLog1->getSvTNum(), HexUtil::toInt(SV_R_LOG_SV_TNUM));
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvReload_whenOutOfSession_InExtendedMode_shouldUpdateReloadLog)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED_WITH_STORED_VALUE);  // NOLINT

    std::vector<std::string> apdus
        = {CARD_SV_GET_RELOAD_EXT_CMD, CARD_SV_GET_RELOAD_EXT_RSP};
    mockTransmitCardRequest(apdus);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareSvGet(SvOperation::RELOAD, SvAction::DO)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(calypsoCard->getSvBalance(), HexUtil::toInt(SV_R_BALANCE));
    ASSERT_EQ(calypsoCard->getSvLastTNum(), HexUtil::toShort(SV_R_TNUM));
    std::shared_ptr<SvLoadLogRecord> loadLog1(
        calypsoCard->getSvLoadLogRecord());
    ASSERT_EQ(loadLog1->getLoadDate(), HexUtil::toByteArray(SV_R_LOG_DATE));
    ASSERT_EQ(loadLog1->getLoadTime(), HexUtil::toByteArray(SV_R_LOG_TIME));
    ASSERT_EQ(loadLog1->getBalance(), HexUtil::toInt(SV_R_LOG_BALANCE));
    ASSERT_EQ(loadLog1->getAmount(), HexUtil::toInt(SV_R_LOG_AMOUNT));
    ASSERT_EQ(
        loadLog1->getFreeData(),
        HexUtil::toByteArray(SV_R_LOG_FREE1 + SV_R_LOG_FREE2));
    ASSERT_EQ(loadLog1->getKvc(), HexUtil::toByte(SV_R_LOG_KVC));
    ASSERT_EQ(loadLog1->getSamId(), HexUtil::toByteArray(SV_R_LOG_SAM_ID));
    ASSERT_EQ(loadLog1->getSamTNum(), HexUtil::toInt(SV_R_LOG_SAM_TNUM));
    ASSERT_EQ(loadLog1->getSvTNum(), HexUtil::toInt(SV_R_LOG_SV_TNUM));
    std::shared_ptr<SvDebitLogRecord> debitLog1(
        calypsoCard->getSvDebitLogLastRecord());
    ASSERT_EQ(debitLog1->getDebitDate(), HexUtil::toByteArray(SV_D_LOG_DATE));
    ASSERT_EQ(debitLog1->getDebitTime(), HexUtil::toByteArray(SV_D_LOG_TIME));
    ASSERT_EQ(debitLog1->getBalance(), HexUtil::toInt(SV_D_LOG_BALANCE));
    ASSERT_EQ(debitLog1->getAmount(), HexUtil::toInt(SV_D_LOG_AMOUNT));
    ASSERT_EQ(debitLog1->getKvc(), HexUtil::toByte(SV_D_LOG_KVC));
    ASSERT_EQ(debitLog1->getSamId(), HexUtil::toByteArray(SV_D_LOG_SAM_ID));
    ASSERT_EQ(debitLog1->getSamTNum(), HexUtil::toInt(SV_D_LOG_SAM_TNUM));
    ASSERT_EQ(debitLog1->getSvTNum(), HexUtil::toInt(SV_D_LOG_SV_TNUM));
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvDebit_whenNoSvGetPreviouslyExecuted_shouldThrowISE)
{
    EXPECT_THROW(
        dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
            cardTransactionManager.get())
            ->prepareSvDebit(1),
        IllegalStateException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvDebit_whenOutOfSession_InRegularMode_shouldUpdateReloadLog)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_STORED_VALUE);

    std::vector<std::string> apdus
        = {CARD_SV_GET_DEBIT_CMD, CARD_SV_GET_DEBIT_RSP};
    mockTransmitCardRequest(apdus);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareSvGet(SvOperation::DEBIT, SvAction::DO)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(calypsoCard->getSvBalance(), HexUtil::toInt(SV_D_BALANCE));
    ASSERT_EQ(calypsoCard->getSvLastTNum(), HexUtil::toShort(SV_D_TNUM));
    std::shared_ptr<SvDebitLogRecord> debitLog1(
        calypsoCard->getSvDebitLogLastRecord());
    ASSERT_EQ(debitLog1->getDebitDate(), HexUtil::toByteArray(SV_D_LOG_DATE));
    ASSERT_EQ(debitLog1->getDebitTime(), HexUtil::toByteArray(SV_D_LOG_TIME));
    ASSERT_EQ(debitLog1->getBalance(), HexUtil::toInt(SV_D_LOG_BALANCE));
    ASSERT_EQ(debitLog1->getAmount(), HexUtil::toInt(SV_D_LOG_AMOUNT));
    ASSERT_EQ(debitLog1->getKvc(), HexUtil::toByte(SV_D_LOG_KVC));
    ASSERT_EQ(debitLog1->getSamId(), HexUtil::toByteArray(SV_D_LOG_SAM_ID));
    ASSERT_EQ(debitLog1->getSamTNum(), HexUtil::toInt(SV_D_LOG_SAM_TNUM));
    ASSERT_EQ(debitLog1->getSvTNum(), HexUtil::toInt(SV_D_LOG_SV_TNUM));
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareSvDebit_whenOutOfSession_InExtendedMode_shouldUpdateReloadLog)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED_WITH_STORED_VALUE);  // NOLINT

    std::vector<std::string> apdus
        = {CARD_SV_GET_DEBIT_EXT_CMD, CARD_SV_GET_DEBIT_EXT_RSP};
    mockTransmitCardRequest(apdus);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareSvGet(SvOperation::DEBIT, SvAction::DO)
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);

    ASSERT_EQ(calypsoCard->getSvBalance(), HexUtil::toInt(SV_D_BALANCE));
    ASSERT_EQ(calypsoCard->getSvLastTNum(), HexUtil::toShort(SV_D_TNUM));
    std::shared_ptr<SvDebitLogRecord> debitLog1(
        calypsoCard->getSvDebitLogLastRecord());
    ASSERT_EQ(debitLog1->getDebitDate(), HexUtil::toByteArray(SV_D_LOG_DATE));
    ASSERT_EQ(debitLog1->getDebitTime(), HexUtil::toByteArray(SV_D_LOG_TIME));
    ASSERT_EQ(debitLog1->getBalance(), HexUtil::toInt(SV_D_LOG_BALANCE));
    ASSERT_EQ(debitLog1->getAmount(), HexUtil::toInt(SV_D_LOG_AMOUNT));
    ASSERT_EQ(debitLog1->getKvc(), HexUtil::toByte(SV_D_LOG_KVC));
    ASSERT_EQ(debitLog1->getSamId(), HexUtil::toByteArray(SV_D_LOG_SAM_ID));
    ASSERT_EQ(debitLog1->getSamTNum(), HexUtil::toInt(SV_D_LOG_SAM_TNUM));
    ASSERT_EQ(debitLog1->getSvTNum(), HexUtil::toInt(SV_D_LOG_SV_TNUM));
}
//
TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareInvalidate_whenCardIsInvalidated_shouldThrowISE)  // NOLINT
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED);

    EXPECT_THROW(
        dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
            cardTransactionManager.get())
            ->prepareInvalidate(),
        IllegalStateException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareInvalidate_whenCardIsNotInvalidated_prepareInvalidateApdu)
{
    std::vector<std::string> apdus = {CARD_INVALIDATE_CMD, SW_9000};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(
        *cardReader,
        transmitCardRequest(
            Truly([cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                return CardRequestMatcher(cardRequest).matches(req);
            }),
            _))
        .Times(1)
        .WillOnce(InvokeWithoutArgs(
            [this]() { return popNextQueuedCardResponse(); }));

    EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize()).Times(1);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareInvalidate()
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareRehabilitate_whenCardIsNotInvalidated_shouldThrowISE)
{
    EXPECT_THROW(
        dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
            cardTransactionManager.get())
            ->prepareRehabilitate(),
        IllegalStateException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareRehabilitate_whenCardIsInvalidated_prepareInvalidateApdu)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_INVALIDATED);

    std::vector<std::string> apdus = {CARD_REHABILITATE_CMD, SW_9000};
    std::shared_ptr<CardRequestSpi> cardRequest(mockTransmitCardRequest(apdus));

    EXPECT_CALL(
        *cardReader,
        transmitCardRequest(
            Truly([cardRequest](const std::shared_ptr<CardRequestSpi>& req) {
                return CardRequestMatcher(cardRequest).matches(req);
            }),
            _))
        .Times(1)
        .WillOnce(InvokeWithoutArgs(
            [this]() { return popNextQueuedCardResponse(); }));

    EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize()).Times(1);

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareRehabilitate()
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareChangeKey_shouldSendApdusToTheCardAndTheSAM)  // NOLINT
{
    cardSecuritySetting->enablePinPlainTransmission();

    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_WITH_PIN);

    std::vector<std::string> apdusGetChallenge
        = {CARD_GET_CHALLENGE_CMD, CARD_GET_CHALLENGE_RSP};
    std::shared_ptr<CardRequestSpi> cardGetChallengeCardRequest(
        mockTransmitCardRequest(apdusGetChallenge));

    std::vector<std::string> apdusChangeKey = {CARD_CHANGE_KEY_CMD, SW_9000};
    std::shared_ptr<CardRequestSpi> cardChangeKeyCardRequest(
        mockTransmitCardRequest(apdusChangeKey));

    {
        InSequence seq;

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly([cardGetChallengeCardRequest](
                          const std::shared_ptr<CardRequestSpi>& req) {
                    return CardRequestMatcher(cardGetChallengeCardRequest)
                        .matches(req);
                }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(
            *symmetricCryptoCardTransactionManager,
            generateCipheredCardKey(
                HexUtil::toByteArray(CARD_CHALLENGE),
                static_cast<std::uint8_t>(4),
                static_cast<std::uint8_t>(5),
                static_cast<std::uint8_t>(2),
                static_cast<std::uint8_t>(3)))
            .Times(1)
            .WillOnce(Return(HexUtil::toByteArray(CIPHERED_KEY)));

        EXPECT_CALL(
            *cardReader,
            transmitCardRequest(
                Truly([cardChangeKeyCardRequest](
                          const std::shared_ptr<CardRequestSpi>& req) {
                    return CardRequestMatcher(cardChangeKeyCardRequest)
                        .matches(req);
                }),
                _))
            .Times(1)
            .WillOnce(InvokeWithoutArgs(
                [this]() { return popNextQueuedCardResponse(); }));

        EXPECT_CALL(*symmetricCryptoCardTransactionManager, synchronize())
            .Times(1);
    }

    dynamic_cast<SecureExtendedModeTransactionManagerAdapter*>(
        cardTransactionManager.get())
        ->prepareChangeKey(
            1,
            static_cast<std::uint8_t>(2),
            static_cast<std::uint8_t>(3),
            static_cast<std::uint8_t>(4),
            static_cast<std::uint8_t>(5))
        .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
}
//
TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareEarlyMutualAuthentication_whenExtendedModeIsNotSupported_shouldThrowUOE)  // NOLINT
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);

    EXPECT_THROW(
        cardTransactionManager->prepareEarlyMutualAuthentication(),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareEarlyMutualAuthentication_whenProcessedOutsideSession_shouldThrowISE)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    EXPECT_THROW(
        {
            cardTransactionManager->prepareEarlyMutualAuthentication();
            cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
        },
        IllegalStateException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareActivateEncryption_whenExtendedModeIsNotSupported_shouldThrowUOE)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);

    EXPECT_THROW(
        cardTransactionManager->prepareActivateEncryption(),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareActivateEncryption_whenProcessedOutsideSession_shouldThrowISE)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    EXPECT_THROW(
        {
            cardTransactionManager->prepareActivateEncryption();
            cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
        },
        IllegalStateException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareDeactivateEncryption_whenExtendedModeIsNotSupported_shouldThrowUOE)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3);

    EXPECT_THROW(
        cardTransactionManager->prepareDeactivateEncryption(),
        UnsupportedOperationException);
}

TEST_F(
    SecureExtendedModeTransactionManagerAdapterTest,
    prepareDeactivateEncryption_whenProcessedOutsideSession_shouldThrowISE)
{
    initCalypsoCardAndTransactionManager(
        SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);

    EXPECT_THROW(
        {
            cardTransactionManager->prepareDeactivateEncryption();
            cardTransactionManager->processCommands(CHANNEL_CONTROL_KEEP_OPEN);
        },
        IllegalStateException);
}
//
//   @Test
//   public void
//       prepareEarlyMutualAuthenticationAndEncryption_whenExtendedModeIsNotSupportedAfterOpening_shouldThrowUOE()
//           throws Exception {
//
//     initCalypsoCardAndTransactionManager(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
//
//     // Mock
//     when(symmetricCryptoCardTransactionManager.initTerminalSecureSessionContext())
//         .thenReturn(HexUtil.toByteArray(SAM_CHALLENGE_EXTENDED));
//     when(symmetricCryptoCardTransactionManager.generateTerminalSessionMac())
//         .thenReturn(HexUtil.toByteArray(SAM_SIGNATURE_EXTENDED));
//     when(symmetricCryptoCardTransactionManager.isCardSessionMacValid(
//             HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED)))
//         .thenReturn(true);
//
//     mockTransmitCardRequest(
//         CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
//         CARD_OPEN_SECURE_SESSION_EXTENDED_NOT_SUPPORTED_RSP);
//
//     mockTransmitCardRequest(CARD_MSS_AUTHENTICATION_CMD, SW_6985);
//
//     // Scenario
//     assertThat(calypsoCard.isExtendedModeSupported()).isTrue();
//
//     cardTransactionManager
//         .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
//         .prepareEarlyMutualAuthentication()
//         .prepareActivateEncryption()
//         .prepareDeactivateEncryption();
//     try {
//       cardTransactionManager.processCommands(CHANNEL_CONTROL_KEEP_OPEN);
//       shouldHaveThrown(UnsupportedOperationException.class);
//     } catch (UnsupportedOperationException ignored) {
//     }
//
//     assertThat(calypsoCard.isExtendedModeSupported()).isFalse();
//
//     cardTransactionManager.prepareOpenSecureSession(WriteAccessLevel.DEBIT);
//     try {
//       cardTransactionManager.prepareEarlyMutualAuthentication();
//       shouldHaveThrown(UnsupportedOperationException.class);
//     } catch (UnsupportedOperationException ignored) {
//     }
//     try {
//       cardTransactionManager.prepareActivateEncryption();
//       shouldHaveThrown(UnsupportedOperationException.class);
//     } catch (UnsupportedOperationException ignored) {
//     }
//     try {
//       cardTransactionManager.prepareDeactivateEncryption();
//       shouldHaveThrown(UnsupportedOperationException.class);
//     } catch (UnsupportedOperationException ignored) {
//     }
//   }
//
//   @Test
//   public void
//       prepareEarlyMutualAuthenticationAndEncryption_whenExtendedAndSession_shouldBeSuccessful()
//           throws Exception {
//
//     cardSecuritySetting.enableMultipleSession();
//
//     initCalypsoCard(SELECT_APPLICATION_RESPONSE_PRIME_REVISION_3_EXTENDED);
//     when(calypsoCard.getModificationsCounter()).thenReturn(7);
//     initTransactionManager();
//
//     /* Process opening */
//     CardRequestSpi cardOssReq =
//         mockTransmitCardRequest(
//             CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
//             CARD_OPEN_SECURE_SESSION_EXTENDED_RSP);
//
//     // Digest Init + Mutual Authentication with encryption activation
//     CardRequestSpi cardMssAuthEncryptReq =
//         mockTransmitCardRequest(
//             CARD_MSS_AUTHENTICATION_ENCRYPTION_CMD,
//             CARD_MSS_AUTHENTICATION_ENCRYPTION_RSP);
//
//     // Encrypted read record
//     CardRequestSpi cardEncryptReq1 =
//         mockTransmitCardRequest(
//             CARD_READ_REC_ENCRYPTED_SFI1_REC1_CMD,
//             CARD_READ_REC_ENCRYPTED_SFI1_REC1_RSP);
//
//     // Mutual Authentication with encryption deactivation
//     mockTransmitCardRequest(CARD_MSS_AUTHENTICATION_CMD,
//     CARD_MSS_AUTHENTICATION_RSP);
//
//     // Plain read + encryption activation
//     CardRequestSpi cardMssAuthReqAndReadRec2AndMssEncryptReq =
//         mockTransmitCardRequest(
//             CARD_MSS_AUTHENTICATION_CMD,
//             CARD_MSS_AUTHENTICATION_RSP,
//             CARD_READ_REC_SFI1_REC2_CMD,
//             CARD_READ_REC_SFI1_REC2_RSP,
//             CARD_MSS_ENCRYPTION_CMD,
//             SW_9000);
//
//     /* Process commands */
//
//     // Mutual Authentication with encryption activation
//     // Encrypted read record
//     CardRequestSpi cardEncryptReq2 =
//         mockTransmitCardRequest(
//             CARD_READ_REC_ENCRYPTED_SFI1_REC3_CMD,
//             CARD_READ_REC_ENCRYPTED_SFI1_REC3_RSP);
//
//     // Encrypted update record
//     CardRequestSpi cardEncryptReq3 =
//         mockTransmitCardRequest(
//             CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_CMD,
//             CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_RSP);
//
//     // Atomic closing
//     CardRequestSpi cardCssReq =
//         mockTransmitCardRequest(
//             CARD_CLOSE_SECURE_SESSION_EXTENDED_CMD,
//             CARD_CLOSE_SECURE_SESSION_EXTENDED_RSP);
//
//     // Atomic opening
//     CardRequestSpi cardOssAndMssEncryptReq =
//         mockTransmitCardRequest(
//             CARD_OPEN_SECURE_SESSION_EXTENDED_CMD,
//             CARD_OPEN_SECURE_SESSION_EXTENDED_RSP,
//             CARD_MSS_ENCRYPTION_CMD,
//             SW_9000);
//
//     // Encrypted update record
//
//     // MSS deactivate encryption
//     CardRequestSpi cardEncryptReq4AndMssReq =
//         mockTransmitCardRequest(
//             CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_CMD,
//             CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_RSP,
//             CARD_MSS_CMD,
//             SW_9000);
//
//     /* Process closing */
//
//     // Plain read
//     CardRequestSpi cardReadRec4Req =
//         mockTransmitCardRequest(CARD_READ_REC_SFI1_REC4_CMD,
//         CARD_READ_REC_SFI1_REC4_RSP);
//
//     // Plain read + encryption activation
//     CardRequestSpi cardMssAuthAndReadRec5AndMssEncryptReq =
//         mockTransmitCardRequest(
//             CARD_MSS_AUTHENTICATION_CMD,
//             CARD_MSS_AUTHENTICATION_RSP,
//             CARD_READ_REC_SFI1_REC5_CMD,
//             CARD_READ_REC_SFI1_REC5_RSP,
//             CARD_MSS_ENCRYPTION_CMD,
//             SW_9000);
//
//     // Encrypted read record
//
//     CardRequestSpi cardEncryptReq5 =
//         mockTransmitCardRequest(
//             CARD_READ_REC_ENCRYPTED_SFI1_REC6_CMD,
//             CARD_READ_REC_ENCRYPTED_SFI1_REC6_RSP);
//
//     /* Mock commands */
//     when(cardReader.isContactless()).thenReturn(true);
//
//     when(symmetricCryptoCardTransactionManager.initTerminalSecureSessionContext())
//         .thenReturn(HexUtil.toByteArray(SAM_CHALLENGE_EXTENDED));
//     when(symmetricCryptoCardTransactionManager.generateTerminalSessionMac())
//         .thenReturn(HexUtil.toByteArray(SAM_SIGNATURE_EXTENDED));
//     when(symmetricCryptoCardTransactionManager.isCardSessionMacValid(
//             HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED)))
//         .thenReturn(true);
//
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC1_CMD)))
//         .thenReturn(HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC1_CMD));
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC1_RSP)))
//         .thenReturn(HexUtil.toByteArray(CARD_READ_REC_DECRYPTED_SFI1_REC1_RSP));
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC3_CMD)))
//         .thenReturn(HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC3_CMD));
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC3_RSP)))
//         .thenReturn(HexUtil.toByteArray(CARD_READ_REC_DECRYPTED_SFI1_REC3_RSP));
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(CARD_UPDATE_REC_SFI1_REC1_CMD)))
//         .thenReturn(HexUtil.toByteArray(CARD_UPDATE_REC_ENCRYPTED_SFI1_REC1_CMD));
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(SW_9000)))
//         .thenReturn(HexUtil.toByteArray(SW_9000));
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(CARD_UPDATE_REC_SFI1_REC2_CMD)))
//         .thenReturn(HexUtil.toByteArray(CARD_UPDATE_REC_ENCRYPTED_SFI1_REC2_CMD));
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC6_CMD)))
//         .thenReturn(HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC6_CMD));
//     when(symmetricCryptoCardTransactionManager.updateTerminalSessionMac(
//             HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC6_RSP)))
//         .thenReturn(HexUtil.toByteArray(CARD_READ_REC_DECRYPTED_SFI1_REC6_RSP));
//
//     when(symmetricCryptoCardTransactionManager.finalizeTerminalSessionMac())
//         .thenReturn(HexUtil.toByteArray(SAM_SIGNATURE_EXTENDED));
//     when(symmetricCryptoCardTransactionManager.isCardSessionMacValid(
//             HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED)))
//         .thenReturn(true);
//
//     /* Scenario */
//     cardTransactionManager
//         .prepareOpenSecureSession(WriteAccessLevel.DEBIT)
//         .prepareEarlyMutualAuthentication() // Authentication
//         .prepareActivateEncryption() // + encryption
//         .prepareReadRecords((byte) 1, 1, 1, 1)
//         .prepareEarlyMutualAuthentication() // Authentication
//         .prepareDeactivateEncryption() // - encryption
//         .prepareReadRecords((byte) 1, 2, 2, 1)
//         .prepareActivateEncryption() // + encryption
//         .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
//     cardTransactionManager
//         .prepareEarlyMutualAuthentication() // Authentication
//         .prepareEarlyMutualAuthentication() // Authentication (Twice consecutive call) // NOLINT
//         .prepareReadRecords((byte) 1, 3, 3, 1)
//         .prepareUpdateRecord((byte) 1, 1, new byte[] {(byte) 0xAA})
//         .prepareUpdateRecord((byte) 1, 2, new byte[] {(byte) 0xBB}) // 2nd session // NOLINT
//         .prepareDeactivateEncryption() // - encryption
//         .processCommands(CHANNEL_CONTROL_KEEP_OPEN);
//     cardTransactionManager
//         .prepareReadRecords((byte) 1, 4, 4, 1)
//         .prepareEarlyMutualAuthentication() // Authentication
//         .prepareReadRecords((byte) 1, 5, 5, 1)
//         .prepareActivateEncryption() // + encryption
//         .prepareReadRecords((byte) 1, 6, 6, 1)
//         .prepareCloseSecureSession()
//         .processCommands(CHANNEL_CONTROL_CLOSE_AFTER);
//
//     /* Check result */
//     InOrder inOrder = inOrder(cardReader,
//     symmetricCryptoCardTransactionManager);
//     inOrder.verify(symmetricCryptoCardTransactionManager).initTerminalSecureSessionContext();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardOssReq)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .initTerminalSessionMac(
//             HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT),
//             HexUtil.toByte(KIF),
//             HexUtil.toByte(KVC));
//     inOrder.verify(symmetricCryptoCardTransactionManager).generateTerminalSessionMac();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardMssAuthEncryptReq)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .isCardSessionMacValid(HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED));
//     inOrder.verify(symmetricCryptoCardTransactionManager).activateEncryption();
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC1_CMD));
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardEncryptReq1)),
//             eq(ChannelControl.KEEP_OPEN));
//
//     // Check with the decrypted response because the content of the APDU response if overwritten. // NOLINT
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_DECRYPTED_SFI1_REC1_RSP));
//
//     inOrder.verify(symmetricCryptoCardTransactionManager).generateTerminalSessionMac();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new
//             CardRequestMatcher(cardMssAuthReqAndReadRec2AndMssEncryptReq)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .isCardSessionMacValid(HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED));
//     inOrder.verify(symmetricCryptoCardTransactionManager).deactivateEncryption();
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_SFI1_REC2_CMD));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_SFI1_REC2_RSP));
//     inOrder.verify(symmetricCryptoCardTransactionManager).activateEncryption();
//     inOrder.verify(symmetricCryptoCardTransactionManager).synchronize();
//     inOrder.verify(symmetricCryptoCardTransactionManager).generateTerminalSessionMac();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardMssAuthEncryptReq)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .isCardSessionMacValid(HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC3_CMD));
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardEncryptReq2)),
//             eq(ChannelControl.KEEP_OPEN));
//
//     // Check with the decrypted response because the content of the APDU response if overwritten. // NOLINT
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_DECRYPTED_SFI1_REC3_RSP));
//
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_UPDATE_REC_SFI1_REC1_CMD));
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardEncryptReq3)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(SW_9000));
//     inOrder.verify(symmetricCryptoCardTransactionManager).finalizeTerminalSessionMac();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardCssReq)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .isCardSessionMacValid(HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED));
//     inOrder.verify(symmetricCryptoCardTransactionManager).initTerminalSecureSessionContext();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardOssAndMssEncryptReq)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .initTerminalSessionMac(
//             HexUtil.toByteArray(CARD_OPEN_SECURE_SESSION_EXTENDED_DATA_OUT),
//             HexUtil.toByte(KIF),
//             HexUtil.toByte(KVC));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_UPDATE_REC_SFI1_REC2_CMD));
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardEncryptReq4AndMssReq)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(SW_9000));
//     inOrder.verify(symmetricCryptoCardTransactionManager).deactivateEncryption();
//     inOrder.verify(symmetricCryptoCardTransactionManager).synchronize();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardReadRec4Req)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_SFI1_REC4_CMD));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_SFI1_REC4_RSP));
//     inOrder.verify(symmetricCryptoCardTransactionManager).generateTerminalSessionMac();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new
//             CardRequestMatcher(cardMssAuthAndReadRec5AndMssEncryptReq)),
//             eq(ChannelControl.KEEP_OPEN));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .isCardSessionMacValid(HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_SFI1_REC5_CMD));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_SFI1_REC5_RSP));
//     inOrder.verify(symmetricCryptoCardTransactionManager).activateEncryption();
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_ENCRYPTED_SFI1_REC6_CMD));
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardEncryptReq5)),
//             eq(ChannelControl.KEEP_OPEN));
//
//     // Check with the decrypted response because the content of the APDU response if overwritten. // NOLINT
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .updateTerminalSessionMac(HexUtil.toByteArray(CARD_READ_REC_DECRYPTED_SFI1_REC6_RSP));
//
//     inOrder.verify(symmetricCryptoCardTransactionManager).finalizeTerminalSessionMac();
//     inOrder
//         .verify(cardReader)
//         .transmitCardRequest(
//             argThat(new CardRequestMatcher(cardCssReq)),
//             eq(ChannelControl.CLOSE_AFTER));
//     inOrder
//         .verify(symmetricCryptoCardTransactionManager)
//         .isCardSessionMacValid(HexUtil.toByteArray(CARD_SIGNATURE_EXTENDED));
//     inOrder.verify(symmetricCryptoCardTransactionManager).synchronize();
//     verifyNoMoreInteractions(symmetricCryptoCardTransactionManager,
//     cardReader);
//   }
