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

#include "CardRequestAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

CardRequestAdapter::CardRequestAdapter(
  const std::vector<std::shared_ptr<ApduRequestSpi>>& apduRequests,
  const bool isStatusCodesVerificationEnabled)
: mApduRequests(apduRequests),
  mIsStatusCodesVerificationEnabled(isStatusCodesVerificationEnabled) {}

const std::vector<std::shared_ptr<ApduRequestSpi>>& CardRequestAdapter::getApduRequests() const
{
    return mApduRequests;
}

bool CardRequestAdapter::stopOnUnsuccessfulStatusWord() const
{
    return mIsStatusCodesVerificationEnabled;
}

std::ostream& operator<<(std::ostream& os, const CardRequestAdapter& cra)
{
    os << "CARD_REQUEST_ADAPTER: {"
       << "APDU_REQUESTS: " << cra.mApduRequests << ", "
       << "IS_STATUS_CODES_VERIFICATION_ENABLED: " << cra.mIsStatusCodesVerificationEnabled
       << "}";

    return os;
}

std::ostream& operator<<(std::ostream& os, const std::shared_ptr<CardRequestAdapter> cra)
{
    if (cra ==  nullptr) {
        os << "CARD_REQUEST_ADAPTER: null";
    } else {
        os << *cra.get();
    }

    return os;
}


}
}
}
