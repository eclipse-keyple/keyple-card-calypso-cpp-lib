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

#include "keyple/card/calypso/CalypsoCardAdapter.hpp"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using keyple::card::calypso::CalypsoCardAdapter;

class CalypsoCardAdapterMock final : public CalypsoCardAdapter {
public:
    CalypsoCardAdapterMock() = default;

    ~CalypsoCardAdapterMock() = default;

    MOCK_METHOD((int), getPayloadCapacity, (), (const, override));
    MOCK_METHOD((const ProductType&), getProductType, (), (const, override));
};
