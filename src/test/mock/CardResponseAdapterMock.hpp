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

#include <vector>

/**
 * This POJO contains an ordered list of the responses received following a card
 * request and indicators related to the status of the channel and the
 * completion of the card request.
 *
 * @since 2.0.0
 */
class CardResponseAdapterMock final : public CardResponseApi {
public:
    /**
     * Builds a card response from all ApduResponseApi received from the card
     * and booleans indicating if the logical channel is still open.
     *
     * @param apduResponses A not null list.
     * @param isLogicalChannelOpen true if the logical channel is open, false
     * if not.
     * @since 2.0.0
     */
    CardResponseAdapterMock(
        const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses,
        const bool isLogicalChannelOpen)
    : mApduResponses(apduResponses)
    , mIsLogicalChannelOpen(isLogicalChannelOpen)
    {
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<std::shared_ptr<ApduResponseApi>>&
    getApduResponses() const override
    {
        return mApduResponses;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool
    isLogicalChannelOpen() const override
    {
        return mIsLogicalChannelOpen;
    }

private:
    /**
     *
     */
    const std::vector<std::shared_ptr<ApduResponseApi>> mApduResponses;

    /**
     *
     */
    const bool mIsLogicalChannelOpen;
};
