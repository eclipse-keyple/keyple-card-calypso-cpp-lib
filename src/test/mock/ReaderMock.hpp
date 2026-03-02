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

#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/ProxyReaderApi.hpp"
#include "keypop/card/spi/CardRequestSpi.hpp"
#include "keypop/reader/CardReader.hpp"
#include "keypop/reader/ChannelControl.hpp"

using keypop::card::CardResponseApi;
using keypop::card::ChannelControl;
using keypop::card::ProxyReaderApi;
using keypop::card::spi::CardRequestSpi;
using keypop::reader::CardReader;

class ReaderMock : public CardReader, public ProxyReaderApi {
public:
    MOCK_METHOD((const std::string&), getName, (), (const, override));

    MOCK_METHOD((bool), isContactless, (), (override));

    MOCK_METHOD((bool), isCardPresent, (), (override));

    MOCK_METHOD(
        (const std::shared_ptr<CardResponseApi>),
        transmitCardRequest,
        (const std::shared_ptr<CardRequestSpi>, const ChannelControl),
        (override));

    MOCK_METHOD(void, releaseChannel, (), (override));
};
