/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#pragma once

#include <memory>
#include <vector>

#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keypop/calypso/card/GetDataTag.hpp"
#include "keypop/calypso/card/SelectFileControl.hpp"
#include "keypop/calypso/card/WriteAccessLevel.hpp"
#include "keypop/calypso/card/card/CalypsoCardSelectionExtension.hpp"
#include "keypop/card/CardSelectionResponseApi.hpp"
#include "keypop/card/spi/CardSelectionExtensionSpi.hpp"
#include "keypop/card/spi/CardSelectionRequestSpi.hpp"
#include "keypop/card/spi/SmartCardSpi.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keypop::calypso::card::GetDataTag;
using keypop::calypso::card::SelectFileControl;
using keypop::calypso::card::WriteAccessLevel;
using keypop::calypso::card::card::CalypsoCardSelectionExtension;
using keypop::card::CardSelectionResponseApi;
using keypop::card::spi::CardSelectionExtensionSpi;
using keypop::card::spi::CardSelectionRequestSpi;
using keypop::card::spi::SmartCardSpi;

/**
 * Implementation of CalypsoCardSelectionExtension.
 *
 * @since 2.0.0
 */
class CalypsoCardSelectionExtensionAdapter
: public CalypsoCardSelectionExtension,
  public CardSelectionExtensionSpi {
public:
    /**
     * Creates an instance of CalypsoCardSelectionExtension.
     *
     * @since 2.0.0
     * @throw IllegalArgumentException If cardSelector is null.
     */
    CalypsoCardSelectionExtensionAdapter();

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelectionExtension& acceptInvalidatedCard() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CalypsoCardSelectionExtension&
    prepareReadRecord(std::uint8_t sfi, int recordNumber) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.3
     */
    CalypsoCardSelectionExtension&
    prepareReadBinary(std::uint8_t sfi, int offset, int nbBytesToRead) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.3
     */
    CalypsoCardSelectionExtension&
    prepareReadCounter(std::uint8_t sfi, int nbCountersToRead) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.3
     */
    CalypsoCardSelectionExtension&
    preparePreOpenSecureSession(WriteAccessLevel writeAccessLevel) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelectionExtension& prepareGetData(GetDataTag tag) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelectionExtension&
    prepareSelectFile(std::uint16_t lid) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    CalypsoCardSelectionExtension&
    prepareSelectFile(SelectFileControl selectControl) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::unique_ptr<CardSelectionRequestSpi> getCardSelectionRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::shared_ptr<SmartCardSpi> parse(
        const std::shared_ptr<CardSelectionResponseApi>& cardSelectionResponse)
        override;

private:
    /**
     *
     */
    static const int SW_CARD_INVALIDATED;

    /**
     *
     */
    std::vector<std::shared_ptr<Command>> mCommands;

    /**
     *
     */
    std::shared_ptr<DtoAdapters::TransactionContextDto> mTransactionContext;

    /**
     *
     */
    std::shared_ptr<DtoAdapters::CommandContextDto> mCommandContext;

    /**
     *
     */
    bool mIsPreOpenPrepared;

    /**
     *
     */
    bool mIsInvalidatedCardAccepted;

    /**
     * Parses the APDU responses and updates the Calypso card image.
     *
     * @param calypsoCard The Calypso card.
     * @param commands The list of commands that get the responses.
     * @param apduResponses The APDU responses returned by the card to all
     commands.
    */
    void parseApduResponses(
        const std::shared_ptr<CalypsoCardAdapter>& calypsoCard,
        const std::vector<std::shared_ptr<Command>>& commands,
        const std::vector<std::shared_ptr<ApduResponseApi>>& apduResponses);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
