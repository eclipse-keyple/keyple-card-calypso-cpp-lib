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
#include "CalypsoSam.h"

using namespace testing;

using namespace calypsonet::terminal::calypso::sam;

class CalypsoSamMock final : public CalypsoSam {
public:
    MOCK_METHOD(ProductType, getProductType, (), (const, override));
    MOCK_METHOD(const std::string, getProductInfo, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>&, getSerialNumber, (), (const, override));
    MOCK_METHOD(uint8_t, getPlatform, (), (const, override));
    MOCK_METHOD(uint8_t, getApplicationType, (), (const, override));
    MOCK_METHOD(uint8_t, getApplicationSubType, (), (const, override));
    MOCK_METHOD(uint8_t, getSoftwareIssuer, (), (const, override));
    MOCK_METHOD(uint8_t, getSoftwareVersion, (), (const, override));
    MOCK_METHOD(uint8_t, getSoftwareRevision, (), (const, override));
    MOCK_METHOD(const std::string&, getPowerOnData, (), (const, override));
    MOCK_METHOD(const std::vector<uint8_t>, getSelectApplicationResponse, (), (const, override));
};
