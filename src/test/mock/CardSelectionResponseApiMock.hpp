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

#include <memory>
#include <string>

#include "keypop/card/ApduResponseApi.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/CardSelectionResponseApi.hpp"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using keypop::card::ApduResponseApi;
using keypop::card::CardResponseApi;
using keypop::card::CardSelectionResponseApi;

class CardSelectionResponseApiMock final : public CardSelectionResponseApi {
public:
    CardSelectionResponseApiMock() = default;

    ~CardSelectionResponseApiMock() = default;

    MOCK_METHOD((const std::string&), getPowerOnData, (), (const, override));

    MOCK_METHOD(
        (const std::shared_ptr<ApduResponseApi>),
        getSelectApplicationResponse,
        (),
        (const, override));

    MOCK_METHOD((bool), hasMatched, (), (const, override));

    MOCK_METHOD(
        (const std::shared_ptr<CardResponseApi>),
        getCardResponse,
        (),
        (const, override));
};
