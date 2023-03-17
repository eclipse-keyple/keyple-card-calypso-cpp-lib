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

#pragma once

/* Calypsonet Terminal Card */
#include "CardSelectionResponseApi.h"

/* Keyple Core Util */
#include "UnsupportedOperationException.h"

using namespace calypsonet::terminal::card;
using namespace keyple::core::util::cpp::exception;

class CardSelectionResponseAdapter : public CardSelectionResponseApi {
public:
    CardSelectionResponseAdapter(const std::string& powerOnData) : mPowerOnData(powerOnData) {}

    CardSelectionResponseAdapter(const std::shared_ptr<ApduResponseApi> selectApplicationResponse)
    : mSelectApplicationResponse(selectApplicationResponse) {}

    const std::string& getPowerOnData() const override
    {
        return mPowerOnData;
    }

    const std::shared_ptr<ApduResponseApi> getSelectApplicationResponse() const override
    {
        return mSelectApplicationResponse;
    }

    bool hasMatched() const override
    {
        throw UnsupportedOperationException("hasMatched");
    }

    const std::shared_ptr<CardResponseApi> getCardResponse() const override
    {
        throw UnsupportedOperationException("hasMatched");
    }

private:

    const std::string mPowerOnData = "";

    std::shared_ptr<ApduResponseApi> mSelectApplicationResponse;
};
