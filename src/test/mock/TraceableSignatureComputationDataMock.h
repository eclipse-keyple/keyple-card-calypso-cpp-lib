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

/* Calypsonet Terminal Calypso  */
#include "TraceableSignatureComputationData.h"

using namespace testing;

using namespace calypsonet::terminal::calypso::transaction;

class TraceableSignatureComputationDataMock final : public TraceableSignatureComputationData {
public:
    MOCK_METHOD(TraceableSignatureComputationData&, withoutBusyMode, (), (override));
    MOCK_METHOD((const std::vector<uint8_t>&),  getSignedData, (), (const, override));
    MOCK_METHOD(TraceableSignatureComputationData&, withSamTraceabilityMode, (const int, const bool), (override));

    /* CommonSignatureComputationData<TraceableSignatureComputationData> */
    MOCK_METHOD(TraceableSignatureComputationData&, setData, (const std::vector<uint8_t>&, const uint8_t, const uint8_t), (override));
    MOCK_METHOD(TraceableSignatureComputationData&, setSignatureSize, (const int), (override));
    MOCK_METHOD(TraceableSignatureComputationData&, setKeyDiversifier, (const std::vector<uint8_t>&), (override));
    MOCK_METHOD(const std::vector<uint8_t>&, getSignature, (), (const, override));
};
