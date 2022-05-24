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
#include "CalypsoSamSelection.h"

using namespace testing;

using namespace calypsonet::terminal::calypso::sam;

class CalypsoSamSelectionMock : public CalypsoSamSelection {
public:
    MOCK_METHOD(CalypsoSamSelection&, filterByProductType, (const CalypsoSam::ProductType), (override));
    MOCK_METHOD(CalypsoSamSelection&, filterBySerialNumber, (const std::string&), (override));
    MOCK_METHOD(CalypsoSamSelection&, setUnlockData, (const std::string&), (override));
};
