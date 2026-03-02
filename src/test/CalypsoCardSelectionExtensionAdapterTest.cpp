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

#include "keyple/card/calypso/CalypsoCardSelectionExtensionAdapter.hpp"
#include "keyple/card/calypso/CalypsoExtensionService.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/IllegalStateException.hpp"
#include "keypop/calypso/card/GetDataTag.hpp"
#include "keypop/calypso/card/SelectFileControl.hpp"
#include "keypop/calypso/card/WriteAccessLevel.hpp"
#include "keypop/card/ParseException.hpp"
#include "keypop/card/spi/ApduRequestSpi.hpp"
#include "keypop/card/spi/CardSelectionRequestSpi.hpp"

#include "mock/CardSelectionResponseApiMock.hpp"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using keyple::card::calypso::CalypsoCardSelectionExtensionAdapter;
using keyple::card::calypso::CalypsoExtensionService;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::IllegalStateException;
using keypop::calypso::card::GetDataTag;
using keypop::calypso::card::SelectFileControl;
using keypop::calypso::card::WriteAccessLevel;
using keypop::card::ParseException;
using keypop::card::spi::ApduRequestSpi;
using keypop::card::spi::CardSelectionRequestSpi;

using testing::Return;
using testing::ReturnRef;
using testing::Throw;

class CalypsoCardSelectionExtensionAdapterTest : public ::testing::Test {
protected:
    void
    SetUp() override
    {
        cardSelectionExtension
            = static_unique_ptr_cast<CalypsoCardSelectionExtensionAdapter>(
                CalypsoExtensionService::getInstance()
                    ->getCalypsoCardApiFactory()
                    ->createCalypsoCardSelectionExtension());
    }

    void
    TearDown() override
    {
        cardSelectionExtension.reset();
    }

    std::unique_ptr<CalypsoCardSelectionExtensionAdapter>
        cardSelectionExtension;

private:
    template <typename To, typename From>
    static std::unique_ptr<To>
    static_unique_ptr_cast(std::unique_ptr<From>&& old)
    {
        return std::unique_ptr<To>(static_cast<To*>(old.release()));
    }
};

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareSelectFile_whenLidIs1234_shouldProduceSelectFileApduWithLid1234)
{
    cardSelectionExtension->prepareSelectFile(0x1234);

    std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest(
        cardSelectionExtension->getCardSelectionRequest());

    std::shared_ptr<ApduRequestSpi> commandApdu(
        cardSelectionRequest->getCardRequest()->getApduRequests()[0]);

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "00A4090002123400");
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareSelectFile_whenSelectFileControlIsNext_shouldProduceSelectFileApduWithSelectFileControlNext)  // NOLINT
{
    cardSelectionExtension->prepareSelectFile(SelectFileControl::NEXT_EF);

    std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest(
        cardSelectionExtension->getCardSelectionRequest());

    std::shared_ptr<ApduRequestSpi> commandApdu(
        cardSelectionRequest->getCardRequest()->getApduRequests()[0]);

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "00A4020202000000");
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadRecord_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadRecord(31, 1),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadRecord_whenRecordNumberIsLessThan0_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadRecord(0x07, -1),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadRecord_whenRecordNumberIsMoreThan250_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadRecord(0x07, 251),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadRecord_whenSfi07RecNumber1_shouldPrepareReadRecordApduWithSfi07RecNumber1)  // NOLINT
{
    cardSelectionExtension->prepareReadRecord(0x07, 1);

    std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest(
        cardSelectionExtension->getCardSelectionRequest());

    std::shared_ptr<ApduRequestSpi> commandApdu(
        cardSelectionRequest->getCardRequest()->getApduRequests()[0]);

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "00B2013C00");
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadBinary_whenSfiIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadBinary(-1, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadBinary_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadBinary(31, 1, 1),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadBinary_whenOffsetIsNegative_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadBinary(1, -1, 1),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadBinary_whenOffsetIsGreaterThan32767_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadBinary(1, 32768, 1),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadBinary_whenNbBytesToReadIsLessThan1_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadBinary(1, 1, 0),
        IllegalArgumentException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadBinary_whenSfiIsNot0AndOffsetIsGreaterThan255_shouldAddFirstAReadBinaryCommand)  // NOLINT
{
    cardSelectionExtension->prepareReadBinary(1, 256, 1);

    std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest(
        cardSelectionExtension->getCardSelectionRequest());

    std::shared_ptr<ApduRequestSpi> commandApdu(
        cardSelectionRequest->getCardRequest()->getApduRequests()[0]);

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "00B0810001");

    commandApdu = cardSelectionRequest->getCardRequest()->getApduRequests()[1];

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "00B0010001");
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadBinary_whenNbBytesToReadIsLessThanPayLoad_shouldPrepareOneCommand)  // NOLINT
{
    cardSelectionExtension->prepareReadBinary(1, 0, 1);

    std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest(
        cardSelectionExtension->getCardSelectionRequest());

    std::shared_ptr<ApduRequestSpi> commandApdu(
        cardSelectionRequest->getCardRequest()->getApduRequests()[0]);

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "00B0810001");
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadBinary_whenNbBytesToReadIsGreaterThanPayLoad_shouldPrepareMultipleCommands)  // NOLINT
{
    cardSelectionExtension->prepareReadBinary(1, 0, 251);

    std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest(
        cardSelectionExtension->getCardSelectionRequest());

    std::shared_ptr<ApduRequestSpi> commandApdu(
        cardSelectionRequest->getCardRequest()->getApduRequests()[0]);

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "00B08100FA");

    commandApdu = cardSelectionRequest->getCardRequest()->getApduRequests()[1];

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "00B081FA01");
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    prepareReadCounter_whenSfiIsGreaterThan30_shouldThrowIAE)
{
    EXPECT_THROW(
        cardSelectionExtension->prepareReadCounter(31, 1),
        IllegalArgumentException);
}

// C++: test doesn't apply
// TEST_F(
//     CalypsoCardSelectionExtensionAdapterTest,
//     preparePreOpenSecureSession_whenWriteAccessLevelIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardSelectionExtension->preparePreOpenSecureSession(nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    preparePreOpenSecureSession_whenIsAlreadyPrepared_shouldThrowISE)
{
    cardSelectionExtension->preparePreOpenSecureSession(WriteAccessLevel::LOAD);

    EXPECT_THROW(
        cardSelectionExtension->preparePreOpenSecureSession(
            WriteAccessLevel::LOAD),
        IllegalStateException);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    preparePreOpenSecureSession_whenWriteAccessLevelIsLoad_shouldAddCmd_Cla00_Ins8A_P102_P202_Lc01_Data00_Le00)  // NOLINT
{
    cardSelectionExtension->preparePreOpenSecureSession(WriteAccessLevel::LOAD);

    std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest(
        cardSelectionExtension->getCardSelectionRequest());

    std::shared_ptr<ApduRequestSpi> commandApdu(
        cardSelectionRequest->getCardRequest()->getApduRequests()[0]);

    ASSERT_EQ(HexUtil::toHex(commandApdu->getApdu()), "008A0202010000");
}

// C++: test doesn't apply
// TEST_F(
//     CalypsoCardSelectionExtensionAdapterTest,
//     prepareGetData_whenGetDataTagIsNull_shouldThrowIAE)
// {
//     EXPECT_THROW(
//         cardSelectionExtension->prepareGetData(nullptr),
//         IllegalArgumentException);
// }

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    getCardSelectionRequest_whenAcceptInvalidatedCardIsInvoked_shouldReturnResponseContainingACardSelectorWithSuccessfulStatusWord6283)  // NOLINT
{
    cardSelectionExtension->acceptInvalidatedCard();

    std::shared_ptr<CardSelectionRequestSpi> cardSelectionRequest(
        cardSelectionExtension->getCardSelectionRequest());

    const std::vector<int> expected = {0x9000, 0x6283};
    ASSERT_EQ(
        cardSelectionRequest->getSuccessfulSelectionStatusWords(), expected);
}

TEST_F(
    CalypsoCardSelectionExtensionAdapterTest,
    parse_whenCommandsResponsesMismatch_shouldThrowParseException)
{
    auto cardSelectionResponseApi(
        std::make_shared<CardSelectionResponseApiMock>());

    EXPECT_CALL(*cardSelectionResponseApi, getCardResponse())
        .WillRepeatedly(Return(nullptr));

    cardSelectionExtension->prepareGetData(GetDataTag::FCI_FOR_CURRENT_DF);

    EXPECT_THROW(
        cardSelectionExtension->parse(cardSelectionResponseApi),
        ParseException);
}
