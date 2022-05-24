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

#include "ApduRequestAdapter.h"

/* Keyple Core Utils */
#include "KeypleStd.h"

namespace keyple {
namespace card {
namespace calypso {

const int ApduRequestAdapter::DEFAULT_SUCCESSFUL_CODE = 0x9000;

ApduRequestAdapter::ApduRequestAdapter(const std::vector<uint8_t>& apdu)
: mApdu(apdu), mSuccessfulStatusWords({DEFAULT_SUCCESSFUL_CODE})
{}

ApduRequestAdapter& ApduRequestAdapter::addSuccessfulStatusWord(const int successfulStatusWord)
{
    mSuccessfulStatusWords.push_back(successfulStatusWord);

    return *this;
}

const std::vector<int>& ApduRequestAdapter::getSuccessfulStatusWords() const
{
    return mSuccessfulStatusWords;
}

ApduRequestAdapter& ApduRequestAdapter::setInfo(const std::string& info)
{
    mInfo = info;

    return *this;
}

const std::string& ApduRequestAdapter::getInfo() const
{
    return mInfo;
}

const std::vector<uint8_t>& ApduRequestAdapter::getApdu() const
{
    return mApdu;
}


std::ostream& operator<<(std::ostream& os, const std::shared_ptr<ApduRequestAdapter> ara)
{
    os << "APDU_REQUEST_ADAPTER: {";

    if (ara == nullptr) {
        os << "null";
    } else {
        os << "APDU = " << ara->mApdu << ", "
           << "SUCCESSFUL_STATUS_WORDS = " << ara->mSuccessfulStatusWords << ", "
           << "INFO = " << ara->mInfo;
    }

    os << "}";

    return os;
}

}
}
}
