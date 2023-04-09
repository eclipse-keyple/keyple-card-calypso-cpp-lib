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

/* Calypsonet Terminal Calypso */
#include "SearchCommandData.h"

using namespace calypsonet::terminal::calypso::transaction;

/**
 * (private)<br>
 * Implementation of SearchCommandData.
 */
class SearchCommandDataMock final : public SearchCommandData {
public:
    SearchCommandData& setSfi(const uint8_t sfi) override
    {
        (void)sfi;

        return *this;
    }

    SearchCommandData& startAtRecord(const uint8_t recordNumber) override
    {
        (void)recordNumber;

        return *this;
    }

    SearchCommandData& setOffset(int offset) override
    {
        (void)offset;

        return *this;
    }

    SearchCommandData& enableRepeatedOffset() override
    {
        return *this;
    }

    SearchCommandData& setSearchData(const std::vector<uint8_t>& data) override
    {
        (void)data;

        return *this;
    }

    SearchCommandData& setMask(const std::vector<uint8_t>& mask) override
    {
        (void)mask;

        return *this;
    }

    SearchCommandData& fetchFirstMatchingResult() override
    {
        return *this;
    }

    std::vector<uint8_t>& getMatchingRecordNumbers() override
    {
        return mDummy;
    }

private:
    std::vector<uint8_t> mDummy;
};

