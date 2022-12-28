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
#include "SamRevocationServiceSpi.h"

using namespace testing;

using namespace calypsonet::terminal::calypso::spi;

class SamRevocationServiceSpiMock final : public SamRevocationServiceSpi {
public:
    MOCK_METHOD(bool, isSamRevoked, (const std::vector<uint8_t>&), (const, override));
    MOCK_METHOD(bool, isSamRevoked, (const std::vector<uint8_t>&, const int), (const, override));
};
