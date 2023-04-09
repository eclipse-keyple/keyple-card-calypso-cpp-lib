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

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"

/* Keyple Core Utils */
#include "Arrays.h"

using namespace calypsonet::terminal::card;
using namespace keyple::core::util::cpp;

/**
 * (private)<br>
 * Implementation of {@link ApduResponseApi}.
 */
class ApduResponseAdapterMock final : public ApduResponseApi {
public:
    /**
     * Constructor
     */
    ApduResponseAdapterMock(const std::vector<uint8_t>& apdu)
    : mApdu(apdu),
      mStatusWord(((apdu[apdu.size() - 2] & 0x000000FF) << 8) +
                  ((apdu[apdu.size() - 1] & 0x000000FF))) {}


    /**
     * {@inheritDoc}
     */
    const std::vector<uint8_t>& getApdu() const override
    {
        return mApdu;
    }

    /**
     * {@inheritDoc}
     */
    const std::vector<uint8_t> getDataOut() const override
    {
        return Arrays::copyOfRange(mApdu, 0, mApdu.size() - 2);
    }

    /**
     * {@inheritDoc}
     */
    int getStatusWord() const override
    {
        return mStatusWord;
    }

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const ApduResponseAdapterMock& ara)
    {
        os << "APDU_RESPONSE_ADAPTER: {"
           << "APDU: " << ara.mApdu << ", "
           << "STATUS_WORD: " << ara.mStatusWord << ", "
           << "}";

        return os;
    }

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os,
                                    const std::shared_ptr<ApduResponseAdapterMock> ara)
    {
        if (ara == nullptr) {
            os << "APDU_RESPONSE_ADAPTER: null";
        } else {
            os << *ara;
        }

        return os;
    }

private:
    /**
     *
     */
    const std::vector<uint8_t> mApdu;

    /**
     *
     */
    const int mStatusWord;
};

