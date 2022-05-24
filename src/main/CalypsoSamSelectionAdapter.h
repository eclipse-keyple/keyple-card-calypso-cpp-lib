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
#include <string>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"
#include "CalypsoSamSelection.h"

/* Calypsonet Terminal Card */
#include "CardSelectionSpi.h"

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "CardSelectorAdapter.h"


namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;
using namespace calypsonet::terminal::card::spi;

/**
 * (package-private)<br>
 * Implementation of CalypsoSamSelection.
 *
 * <p>If not specified, the SAM product type used for unlocking is CalypsoSam::ProductType::SAM_C1.
 *
 * @since 2.0.0
 */
class CalypsoSamSelectionAdapter : public CalypsoSamSelection, public CardSelectionSpi {
public:
    /**
     * (package-private)<br>
     * Creates a {@link CalypsoSamSelection}.
     *
     * @since 2.0.0
     */
    CalypsoSamSelectionAdapter();

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<CardSelectionRequestSpi> getCardSelectionRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<SmartCardSpi> parse(
        const std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoSamSelection& filterByProductType(const CalypsoSam::ProductType productType) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoSamSelection& filterBySerialNumber(const std::string& serialNumberRegex) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoSamSelection& setUnlockData(const std::string& unlockData) override;

private:
    /**
     *
     */
    const std::shared_ptr<CardSelectorAdapter> mSamCardSelector;

    /**
     *
     */
    std::vector<std::shared_ptr<AbstractSamCommand>> mSamCommands;

    /**
     *
     */
    CalypsoSam::ProductType mProductType;

    /**
     *
     */
    std::string mSerialNumberRegex;

    /**
     *
     */
    std::string mUnlockData;

    /**
     * (private) Build a regular expression to be used as ATR filter in the SAM selection process.
     *
     * <p>Both argument are optional and can be null.
     *
     * @param productType The target SAM product type.
     * @param samSerialNumberRegex A regular expression matching the SAM serial number.
     * @return A not empty string containing a regular
     */
    const std::string buildAtrRegex(const CalypsoSam::ProductType productType,
                                    const std::string& samSerialNumberRegex);
};

}
}
}
