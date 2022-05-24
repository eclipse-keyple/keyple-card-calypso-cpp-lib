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

#include "CardSelectionRequestAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

CardSelectionRequestAdapter::CardSelectionRequestAdapter(
  const std::shared_ptr<CardSelectorSpi> cardSelector)
: CardSelectionRequestAdapter(cardSelector, nullptr) {}

CardSelectionRequestAdapter::CardSelectionRequestAdapter(
  const std::shared_ptr<CardSelectorSpi> cardSelector,
  const std::shared_ptr<CardRequestSpi> cardRequest)
: mCardSelector(cardSelector), mCardRequest(cardRequest) {}

const std::shared_ptr<CardSelectorSpi> CardSelectionRequestAdapter::getCardSelector() const
{
    return mCardSelector;
}

const std::shared_ptr<CardRequestSpi> CardSelectionRequestAdapter::getCardRequest() const
{
    return mCardRequest;
}

std::ostream& operator<<(std::ostream& os, const CardSelectionRequestAdapter& csra)
{
    os << "CARD_SELECTION_REQUEST_ADAPTER: {"
       << "CARD_SELECTOR: " << csra.mCardSelector << ", "
       << "CARD_REQUEST:" << csra.mCardRequest
       << "}";

    return os;
}

std::ostream& operator<<(std::ostream& os, const std::shared_ptr<CardSelectionRequestAdapter> csra)
{
    if (csra == nullptr) {
        os << "CARD_SELECTION_REQUEST_ADAPTER: null";
    } else {
        os << *csra;
    }

    return os;
}

}
}
}
