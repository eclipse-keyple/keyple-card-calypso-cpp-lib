/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the MIT License which is available at                             *
 * https://opensource.org/licenses/MIT.                                       *
 *                                                                            *
 * SPDX-License-Identifier: MIT                                               *
 ******************************************************************************/

#pragma once

#include <map>
#include <memory>
#include <string>

#include "keypop/calypso/card/GetDataTag.hpp"
#include "keypop/calypso/card/PutDataTag.hpp"
#include "keypop/calypso/card/SelectFileControl.hpp"
#include "keypop/calypso/card/transaction/FreeTransactionManager.hpp"
#include "keypop/calypso/card/transaction/SearchCommandData.hpp"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using keypop::calypso::card::GetDataTag;
using keypop::calypso::card::PutDataTag;
using keypop::calypso::card::SelectFileControl;
using keypop::calypso::card::transaction::FreeTransactionManager;
using keypop::calypso::card::transaction::SearchCommandData;

class FreeTransactionManagerMock final : public FreeTransactionManager {
public:
    FreeTransactionManagerMock() = default;

    ~FreeTransactionManagerMock() = default;

    MOCK_METHOD(
        (FreeTransactionManager&),
        processCommands,
        (keypop::reader::ChannelControl),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareSelectFile,
        (std::uint16_t),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareSelectFile,
        (SelectFileControl),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&), prepareGetData, (GetDataTag), (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        preparePutData,
        (PutDataTag, const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareReadRecord,
        (std::uint8_t, int),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareReadRecords,
        (std::uint8_t, int, int, int),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareReadRecordsPartially,
        (std::uint8_t, int, int, int, int),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareReadBinary,
        (std::uint8_t, int, int),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareReadCounter,
        (std::uint8_t, int),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareSearchRecords,
        (std::shared_ptr<SearchCommandData>),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&), prepareCheckPinStatus, (), (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareAppendRecord,
        (std::uint8_t, const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareUpdateRecord,
        (std::uint8_t, int, const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareWriteRecord,
        (std::uint8_t, int, const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareUpdateBinary,
        (std::uint8_t, int, const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareWriteBinary,
        (std::uint8_t, int, const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareIncreaseCounter,
        (std::uint8_t, int, int),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareIncreaseCounters,
        (std::uint8_t, (const std::map<int, int>&)),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareDecreaseCounter,
        (std::uint8_t, int, int),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareDecreaseCounters,
        (std::uint8_t, (const std::map<int, int>&)),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareSetCounter,
        (std::uint8_t, int, int),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&), prepareSvReadAllLogs, (), (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareVerifyPin,
        (const std::vector<std::uint8_t>&),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareChangePin,
        (const std::vector<uint8_t>&),
        (override));

    MOCK_METHOD(
        (FreeTransactionManager&),
        prepareGenerateAsymmetricKeyPair,
        (),
        (override));

    MOCK_METHOD(
        (const std::vector<std::vector<std::uint8_t>>&),
        getTransactionAuditData,
        (),
        (const, override));
};
