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
#include <string>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoCardSelection.h"

/* Calypsonet Terminal Card */
#include "CardSelectorSpi.h"
#include "CardSelectionSpi.h"

/* Keyple Card Calypso */
#include "AbstractCardCommand.h"
#include "CardSelectorAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;
using namespace calypsonet::terminal::card::spi;

/**
 * (package-private)<br>
 * Implementation of CalypsoCardSelection.
 *
 * @since 2.0.0
 */
class CalypsoCardSelectionAdapter final : public CalypsoCardSelection, public CardSelectionSpi {
public:
    /**
     * (package-private)<br>
     * Creates an instance of {@link CalypsoCardSelection}.
     *
     * @since 2.0.0
     * @throws IllegalArgumentException If cardSelector is null.
     */
    CalypsoCardSelectionAdapter();

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& filterByCardProtocol(const std::string& cardProtocol) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& filterByPowerOnData(const std::string& powerOnDataRegex) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& filterByDfName(const std::vector<uint8_t>& aid) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& filterByDfName(const std::string& aid) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& setFileOccurrence(const FileOccurrence fileOccurrence) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& setFileControlInformation(
        const FileControlInformation fileControlInformation) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CalypsoCardSelection& addSuccessfulStatusWord(const int statusWord) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& acceptInvalidatedCard() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CalypsoCardSelection& prepareReadRecordFile(const uint8_t sfi, const int recordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CalypsoCardSelection& prepareReadRecord(const uint8_t sfi, const int recordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& prepareGetData(const GetDataTag tag) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     * @deprecated
     */
    CalypsoCardSelection& prepareSelectFile(const std::vector<uint8_t>& lid) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& prepareSelectFile(const uint16_t lid) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelection& prepareSelectFile(const SelectFileControl selectControl) override;

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

private:
    /**
     *
     */
    static const int AID_MIN_LENGTH;
    static const int AID_MAX_LENGTH;
    static const int SW_CARD_INVALIDATED;

    /**
     *
     */
    std::vector<std::shared_ptr<AbstractCardCommand>> mCommands;

    /**
     *
     */
    std::shared_ptr<CardSelectorAdapter> mCardSelector;

};

}
}
}
