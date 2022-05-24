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

#include "SearchCommandDataAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

SearchCommandDataAdapter::SearchCommandDataAdapter()
: mSfi(1), mRecordNumber(1) {}

SearchCommandData& SearchCommandDataAdapter::setSfi(const uint8_t sfi)
{
    mSfi = sfi;

    return *this;
}

SearchCommandData& SearchCommandDataAdapter::startAtRecord(const int recordNumber)
{
    mRecordNumber = recordNumber;

    return *this;
}

SearchCommandData& SearchCommandDataAdapter::setOffset(const int offset)
{
    mOffset = offset;

    return *this;
}

SearchCommandData& SearchCommandDataAdapter::enableRepeatedOffset()
{
    mEnableRepeatedOffset = true;

    return *this;
}

SearchCommandData& SearchCommandDataAdapter::setSearchData(const std::vector<uint8_t>& data)
{
    mSearchData = data;

    return *this;
}

SearchCommandData& SearchCommandDataAdapter::setMask(const std::vector<uint8_t>& mask)
{
    mMask = mask;

    return *this;
}

SearchCommandData& SearchCommandDataAdapter::fetchFirstMatchingResult()
{
    mFetchFirstMatchingResult = true;

    return *this;
}

std::vector<int>& SearchCommandDataAdapter::getMatchingRecordNumbers()
{
    return mMatchingRecordNumbers;
}

uint8_t SearchCommandDataAdapter::getSfi() const
{
    return mSfi;
}

int SearchCommandDataAdapter::getRecordNumber() const
{
    return mRecordNumber;
}

int SearchCommandDataAdapter::getOffset() const
{
    return mOffset;
}

bool SearchCommandDataAdapter::isEnableRepeatedOffset() const
{
    return mEnableRepeatedOffset;
}

const std::vector<uint8_t>& SearchCommandDataAdapter::getSearchData() const
{
    return mSearchData;
}

const std::vector<uint8_t>& SearchCommandDataAdapter::getMask() const
{
    return mMask;
}

bool SearchCommandDataAdapter::isFetchFirstMatchingResult() const
{
    return mFetchFirstMatchingResult;
}

}
}
}
