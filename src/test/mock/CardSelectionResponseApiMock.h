/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
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
#include "CardSelectionResponseApi.h"

using namespace testing;

using namespace calypsonet::terminal::card;

class CardSelectionResponseApiMock final : public CardSelectionResponseApi {
public:
    MOCK_METHOD(const std::string&,  getPowerOnData, (), (const, override));
    MOCK_METHOD(const std::shared_ptr<ApduResponseApi>, getSelectApplicationResponse, (), (const, override));
    MOCK_METHOD(bool, hasMatched, (), (const, override));
    MOCK_METHOD(const std::shared_ptr<CardResponseApi>, getCardResponse, (), (const, override));
};
