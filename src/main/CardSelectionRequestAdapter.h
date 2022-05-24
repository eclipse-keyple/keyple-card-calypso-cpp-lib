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

#include <memory>
#include <ostream>

/* Calypsonet Terminal Card */
#include "CardRequestSpi.h"
#include "CardSelectionRequestSpi.h"
#include "CardSelectorSpi.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card::spi;

/**
 * (package-private)<br>
 * This POJO contains the data used to define a selection case.
 *
 * <p>A selection case is defined by a CardSelectorSpi that target a particular smart card
 * and an optional ardRequestSpi}containing additional APDU commands to be sent to the card
 * when the selection is successful.
 *
 * <p>One of the uses of this class is to open a logical communication channel with a card in order
 * to continue with other exchanges and carry out a complete transaction.
 *
 * @since 2.0.0
 */
class CardSelectionRequestAdapter final : public CardSelectionRequestSpi {
public:
    /**
     * Builds a card selection request to open a logical channel without sending additional APDUs.
     *
     * <p>The cardRequest field is set to null.
     *
     * @param cardSelector The card selector.
     * @since 2.0.0
     */
    CardSelectionRequestAdapter(const std::shared_ptr<CardSelectorSpi> cardSelector);

    /**
     * Builds a card selection request to open a logical channel with additional APDUs to be sent
     * after the selection step.
     *
     * @param cardSelector The card selector.
     * @param cardRequest The card request.
     * @since 2.0.0
     */
    CardSelectionRequestAdapter(const std::shared_ptr<CardSelectorSpi> cardSelector,
                                const std::shared_ptr<CardRequestSpi> cardRequest);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<CardSelectorSpi> getCardSelector() const override;

    /**
     * Gets the card request.
     *
     * @return a CardRequestSpi or null if it has not been defined
     * @since 2.0.0
     */
    const std::shared_ptr<CardRequestSpi> getCardRequest() const override;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const CardSelectionRequestAdapter& csra);

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os,
                                    const std::shared_ptr<CardSelectionRequestAdapter> csra);

private:
    /**
     *
     */
    const std::shared_ptr<CardSelectorSpi> mCardSelector;

    /**
     *
     */
    const std::shared_ptr<CardRequestSpi> mCardRequest;

};

}
}
}
