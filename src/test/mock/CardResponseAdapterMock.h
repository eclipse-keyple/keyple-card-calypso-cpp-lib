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

/* Calypsonet Terminal Car */
#include "CardResponseApi.h"

using namespace calypsonet::terminal::card;

/**
 * (package-private)<br>
 * This POJO contains an ordered list of the responses received following a card request and
 * indicators related to the status of the channel and the completion of the card request.
 *
 * @see org.calypsonet.terminal.card.spi.CardRequestSpi
 * @since 2.0.0
 */
class CardResponseAdapterMock final : public CardResponseApi {
public:
    /**
     * (package-private)<br>
     * Builds a card response from all {@link ApduResponseApi} received from the card and booleans
     * indicating if the logical channel is still open.
     *
     * @param apduResponses A not null list.
     * @param isLogicalChannelOpen true if the logical channel is open, false if not.
     * @since 2.0.0
     */
    CardResponseAdapterMock(const std::vector<std::shared_ptr<ApduResponseApi>> apduResponses,
                            const bool isLogicalChannelOpen)
    : mApduResponses(apduResponses), mIsLogicalChannelOpen(isLogicalChannelOpen) {}

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<std::shared_ptr<ApduResponseApi>>& getApduResponses() const override
    {
        return mApduResponses;
    }

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool isLogicalChannelOpen() const override
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
