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
#include <vector>

#include "keyple/core/util/cpp/Arrays.hpp"
#include "keyple/core/util/cpp/exception/UnsupportedOperationException.hpp"
#include "keypop/card/ApduResponseApi.hpp"
#include "keypop/card/CardResponseApi.hpp"
#include "keypop/card/CardSelectionResponseApi.hpp"

using keyple::core::util::cpp::Arrays;
using keyple::core::util::cpp::exception::UnsupportedOperationException;
using keypop::card::ApduResponseApi;
using keypop::card::CardResponseApi;
using keypop::card::CardSelectionResponseApi;

class TestDtoAdapters {
public:
    /**
     * (private)<br>
     * Implementation of ApduResponseApi.
     */
    class ApduResponseAdapter final : public ApduResponseApi {
    public:
        /** Constructor */
        explicit ApduResponseAdapter(const std::vector<std::uint8_t>& apdu)
        : mApdu(apdu)
        , mStatusWord(
              ((apdu[apdu.size() - 2] & 0x000000FF) << 8)
              + (apdu[apdu.size() - 1] & 0x000000FF))
        {
        }

        /** {@inheritDoc} */
        const std::vector<std::uint8_t>&
        getApdu() const override
        {
            return mApdu;
        }

        /** {@inheritDoc} */
        std::vector<std::uint8_t>
        getDataOut() const override
        {
            return Arrays::copyOfRange(mApdu, 0, mApdu.size() - 2);
        }

        /** {@inheritDoc} */
        int
        getStatusWord() const override
        {
            return mStatusWord;
        }

        void
        setApdu(const std::vector<std::uint8_t>& apdu) override
        {
            mApdu = apdu;
        }

    private:
        std::vector<std::uint8_t> mApdu;
        const int mStatusWord;
    };

    /**
     * (package-private)<br>
     * This POJO contains an ordered list of the responses received following a
     * card request and indicators related to the status of the channel and the
     * completion of the card request.
     *
     * @see CardRequestSpi
     * @since 2.0.0
     */
    class CardResponseAdapter final : public CardResponseApi {
    public:
        /**
         * (package-private)<br>
         * Builds a card response from all ApduResponseApi received from the
         * card and booleans indicating if the logical channel is still open.
         *
         * @param apduResponses A not null list.
         * @param isLogicalChannelOpen true if the logical channel is open,
         * false if not.
         * @since 2.0.0
         */
        CardResponseAdapter(
            const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses,
            bool isLogicalChannelOpen)
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
        const std::vector<std::shared_ptr<ApduResponseApi>> mApduResponses;
        const bool mIsLogicalChannelOpen;
    };

    class CardSelectionResponseAdapter final : public CardSelectionResponseApi {
    public:
        explicit CardSelectionResponseAdapter(const std::string& powerOnData)
        : mPowerOnData(powerOnData)
        {
        }

        explicit CardSelectionResponseAdapter(
            std::shared_ptr<ApduResponseApi> selectApplicationResponse)
        : mSelectApplicationResponse(selectApplicationResponse)
        {
        }

        const std::string&
        getPowerOnData() const override
        {
            return mPowerOnData;
        }

        const std::shared_ptr<ApduResponseApi>
        getSelectApplicationResponse() const override
        {
            return mSelectApplicationResponse;
        }

        bool
        hasMatched() const override
        {
            throw UnsupportedOperationException("hasMatched");
        }

        const std::shared_ptr<CardResponseApi>
        getCardResponse() const override
        {
            throw UnsupportedOperationException("hasMatched");
        }

    private:
        const std::string mPowerOnData = "";
        std::shared_ptr<ApduResponseApi> mSelectApplicationResponse = nullptr;
    };

    TestDtoAdapters() = default;
};
