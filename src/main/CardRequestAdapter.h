/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
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

#include <memory>
#include <ostream>

/* Calypsonet Terminal Car */
#include "CardRequestSpi.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card::spi;

/**
 * (package-private)<br>
 * This POJO contains an ordered list of ApduRequestSpi and the associated status code check
 * policy.
 *
 * @since 2.0.0
 */
class CardRequestAdapter final : public CardRequestSpi {
public:
    /**
     * Builds a card request with a list of ApduRequestSpi and the flag indicating the
     * expected response checking behavior.
     *
     * <p>When the status code verification is enabled, the transmission of the APDUs must be
     * interrupted as soon as the status code of a response is unexpected.
     *
     * @param apduRequests A not empty list.
     * @param isStatusCodesVerificationEnabled true or false.
     * @since 2.0.0
     */
    CardRequestAdapter(const std::vector<std::shared_ptr<ApduRequestSpi>>& apduRequests,
                       const bool isStatusCodesVerificationEnabled);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<std::shared_ptr<ApduRequestSpi>>& getApduRequests() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    bool stopOnUnsuccessfulStatusWord() const override;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const CardRequestAdapter& cra);

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const std::shared_ptr<CardRequestAdapter> cra);

private:
    /**
     *
     */
    std::vector<std::shared_ptr<ApduRequestSpi>> mApduRequests;

    /**
     *
     */
    const bool mIsStatusCodesVerificationEnabled;
};

}
}
}
