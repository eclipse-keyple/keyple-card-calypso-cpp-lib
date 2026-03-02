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

#include "keypop/calypso/card/transaction/SearchCommandData.hpp"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using keypop::calypso::card::transaction::SearchCommandData;

class SearchCommandDataMock final : public SearchCommandData {
public:
    SearchCommandDataMock() = default;

    ~SearchCommandDataMock() = default;
};
