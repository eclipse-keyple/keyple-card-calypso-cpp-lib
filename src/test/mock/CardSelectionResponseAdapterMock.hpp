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

#include "keyple/core/service/ApduResponseAdapter.hpp"
#include "keyple/core/util/HexUtil.hpp"
#include "keyple/core/util/cpp/System.hpp"
#include "keyple/core/util/cpp/exception/IllegalArgumentException.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/card/ApduResponseApi.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/CardSelectionResponseApi.hpp"

using keyple::core::service::ApduResponseAdapter;
using keyple::core::util::HexUtil;
using keyple::core::util::cpp::System;
using keyple::core::util::cpp::exception::IllegalArgumentException;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::card::ApduResponseApi;
using keypop::card::CardResponseApi;
using keypop::card::CardSelectionResponseApi;

class CardSelectionResponseAdapterMock final : public CardSelectionResponseApi {
public:
    explicit CardSelectionResponseAdapterMock(const std::string& powerOnData)
    : mPowerOnData(powerOnData)
    {
    }

    explicit CardSelectionResponseAdapterMock(
        std::shared_ptr<ApduResponseApi> selectApplicationResponse)
    : mSelectApplicationResponse(selectApplicationResponse)
    {
    }

    const std::string&
    getPowerOnData() const override
    {
        return mPowerOnData;
    }

    const std::shared_ptr<ApduResponseApi>
    getSelectApplicationResponse() const override
    {
        return mSelectApplicationResponse;
    }

    bool
    hasMatched() const override
    {
        throw UnsupportedOperationException("hasMatched");
    }

    const std::shared_ptr<CardResponseApi>
    getCardResponse() const override
    {
        throw UnsupportedOperationException("hasMatched");
    }

private:
    const std::string mPowerOnData = "";

    std::shared_ptr<ApduResponseApi> mSelectApplicationResponse;
};
