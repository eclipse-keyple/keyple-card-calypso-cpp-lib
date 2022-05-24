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

/* Calypsonet Terminal Card */
#include "ProxyReaderApi.h"

/* Calypsonet Terminal Reader */
#include "CardReader.h"

using namespace testing;

using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::reader;

class ReaderMock : public CardReader, public ProxyReaderApi {
public:
    MOCK_METHOD(const std::string&, getName, (), (const, override));
    MOCK_METHOD(bool, isContactless, (), (override));
    MOCK_METHOD(bool, isCardPresent, (), (override));
    MOCK_METHOD(const std::shared_ptr<CardResponseApi>,
                transmitCardRequest,
                (const std::shared_ptr<CardRequestSpi>, const ChannelControl),
                (override));
    MOCK_METHOD(void, releaseChannel, (), (override));
};
