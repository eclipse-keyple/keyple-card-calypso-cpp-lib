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

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "SearchCommandData.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;

/**
 * (package-private)<br>
 * Implementation of SearchCommandData.
 *
 * @since 2.1.0
 */
class SearchCommandDataAdapter final : public SearchCommandData {
public:
    /**
     * (package-private)<br>
     * Constructor.
     *
     * @since 2.1.0
     */
    SearchCommandDataAdapter();

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    SearchCommandData& setSfi(const uint8_t sfi) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    SearchCommandData& startAtRecord(const int recordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    SearchCommandData& setOffset(const int offset) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    SearchCommandData& enableRepeatedOffset() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    SearchCommandData& setSearchData(const std::vector<uint8_t>& data) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    SearchCommandData& setMask(const std::vector<uint8_t>& mask) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    SearchCommandData& fetchFirstMatchingResult() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    std::vector<int>& getMatchingRecordNumbers() override;

    /**
     * (package-private)<br>
     *
     * @return The provided SFI or 0 if it is not set.
     * @since 2.1.0
     */
    uint8_t getSfi() const;

    /**
     * (package-private)<br>
     *
     * @return The provided record number or 1 if it is not set.
     * @since 2.1.0
     */
    int getRecordNumber() const;

    /**
     * (package-private)<br>
     *
     * @return The provided offset or 0 if it is not set.
     * @since 2.1.0
     */
    int getOffset() const;

    /**
     * (package-private)<br>
     *
     * @return True if repeated offset is enabled.
     * @since 2.1.0
     */
    bool isEnableRepeatedOffset() const;

    /**
     * (package-private)<br>
     *
     * @return A not empty array of search data. It is required to check input data first using
     *         checkInputData() method.
     * @since 2.1.0
     */
    const std::vector<uint8_t>& getSearchData() const;

    /**
     * (package-private)<br>
     *
     * @return Null if the mask is not set.
     * @since 2.1.0
     */
    const std::vector<uint8_t>& getMask() const;

    /**
     * (package-private)<br>
     *
     * @return True if first matching result needs to be fetched.
     * @since 2.1.0
     */
    bool isFetchFirstMatchingResult() const;

private:
    /**
     *
     */
    uint8_t mSfi;

    /**
     *
     */
    int mRecordNumber = 1;

    /**
     *
     */
    int mOffset;

    /**
     *
     */
    bool mEnableRepeatedOffset;

    /**
     *
     */
    std::vector<uint8_t> mSearchData;

    /**
     *
     */
    std::vector<uint8_t> mMask;

    /**
     *
     */
    bool mFetchFirstMatchingResult;

    /**
     *
     */
    std::vector<int> mMatchingRecordNumbers;
};

}
}
}
