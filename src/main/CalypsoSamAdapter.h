/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
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

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"

/* Calypsonet Terminal Card */
#include "CardSelectionResponseApi.h"
#include "SmartCardSpi.h"

/* Keyple Card Calypso */
#include "KeypleCardCalypsoExport.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;
using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::card::spi;
using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Implementation of CalypsoSam.
 *
 * @since 2.0.0
 */
class KEYPLECARDCALYPSO_API CalypsoSamAdapter final : public CalypsoSam, public SmartCardSpi {
public:
    /**
     * Constructor.
     *
     * <p>Create the initial content from the data received in response to the card selection.
     *
     * @param cardSelectionResponse the response to the selection command.
     * @since 2.0.0
     */
    CalypsoSamAdapter(const std::shared_ptr<CardSelectionResponseApi> cardSelectionResponse);

    /**
     * (package-private)<br>
     * Gets the class byte to use for the provided product type.
     *
     * @return A byte.
     * @since 2.0.0
     */
    static uint8_t getClassByte(const CalypsoSam::ProductType type);

    /**
     * (package-private)<br>
     * Gets the class byte to use for the current product type.
     *
     * @return A byte.
     * @since 2.0.0
     */
    uint8_t getClassByte() const;

    /**
     * (package-private)<br>
     * Gets the maximum length allowed for digest commands.
     *
     * @return An positive int.
     * @since 2.0.0
     */
    int getMaxDigestDataLength() const;

    /**
     * {@inheritDoc}<br>
     * No select application for a SAM.
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getSelectApplicationResponse() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::string& getPowerOnData() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoSam::ProductType getProductType() const;

    /**
     * Gets textual information about the SAM.
     *
     * @return A not empty String.
     */
    const std::string getProductInfo() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getSerialNumber() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getPlatform() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getApplicationType() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getApplicationSubType() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getSoftwareIssuer() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getSoftwareVersion() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getSoftwareRevision() const;

    /**
     * (package-private)<br>
     * Adds or replace an event counter.
     *
     * @param eventCounterNumber The number of the counter.
     * @param eventCounterValue The counter value.
     * @since 2.2.3
     */
    void putEventCounter(const int eventCounterNumber, const int eventCounterValue);

    /**
     * (package-private)<br>
     * Adds or replace an event counter.
     *
     * @param eventCeilingNumber The number of the ceiling.
     * @param eventCeilingValue The ceiling value.
     * @since 2.2.3
     */
    void putEventCeiling(const int eventCeilingNumber, const int eventCeilingValue);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    std::shared_ptr<int> getEventCounter(const int eventCounterNumber) const; // override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    const std::map<int, int>& getEventCounters() const; // override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    std::shared_ptr<int> getEventCeiling(const int eventCeilingNumber) const; // override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    const std::map<int, int>& getEventCeilings() const; // override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CalypsoSamAdapter));

    /**
     *
     */
    std::string mPowerOnData;

    /**
     *
     */
    CalypsoSam::ProductType mSamProductType;

    /**
     *
     */
    std::vector<uint8_t> mSerialNumber;

    /**
     *
     */
    uint8_t mPlatform;

    /**
     *
     */
    uint8_t mApplicationType;

    /**
     *
     */
    uint8_t mApplicationSubType;

    /**
     *
     */
    uint8_t mSoftwareIssuer;

    /**
     *
     */
    uint8_t mSoftwareVersion;

    /**
     *
     */
    uint8_t mSoftwareRevision;

    /**
     *
     */
    std::map<int, int> mEventCounters;

    /**
     *
     */
    std::map<int, int> mEventCeilings;
};

}
}
}
