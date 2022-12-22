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

#include "TraceableSignatureComputationDataAdapter.h"

/* Keyple Core Util */
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp::exception;

TraceableSignatureComputationData&
    TraceableSignatureComputationDataAdapter::withSamTraceabilityMode(
        const int offset, const bool usePartialSamSerialNumber)
{
    mIsSamTraceabilityMode = true;
    mTraceabilityOffset = offset;
    mIsPartialSamSerialNumber = usePartialSamSerialNumber;

    return *this;
}

TraceableSignatureComputationData& TraceableSignatureComputationDataAdapter::withoutBusyMode()
{
    mIsBusyMode = false;

    return *this;
}

const std::vector<uint8_t>& TraceableSignatureComputationDataAdapter::getSignedData() const
{
    if (!mSignedDataPresent) {
        throw IllegalStateException("The command has not yet been processed");
    }

    return mSignedData;
}

bool TraceableSignatureComputationDataAdapter::isSamTraceabilityMode() const
{
    return mIsSamTraceabilityMode;
}

int TraceableSignatureComputationDataAdapter::getTraceabilityOffset() const
{
    return mTraceabilityOffset;
}

bool TraceableSignatureComputationDataAdapter::isPartialSamSerialNumber() const
{
    return mIsPartialSamSerialNumber;
}

bool TraceableSignatureComputationDataAdapter::isBusyMode() const
{
    return mIsBusyMode;
}

void TraceableSignatureComputationDataAdapter::setSignedData(
    const std::vector<uint8_t>& signedData)
{
    mSignedData = signedData;
}

}
}
}
