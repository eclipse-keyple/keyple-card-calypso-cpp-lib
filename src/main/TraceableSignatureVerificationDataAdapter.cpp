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

#include "TraceableSignatureVerificationDataAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

TraceableSignatureVerificationData&
    TraceableSignatureVerificationDataAdapter::withSamTraceabilityMode(
        const int offset, const bool isPartialSamSerialNumber, const bool checkSamRevocationStatus)
{
    mIsSamTraceabilityMode = true;
    mTraceabilityOffset = offset;
    mIsPartialSamSerialNumber = isPartialSamSerialNumber;
    mIsSamRevocationStatusVerificationRequested = checkSamRevocationStatus;

    return *this;
}

TraceableSignatureVerificationData& TraceableSignatureVerificationDataAdapter::withoutBusyMode()
{
    mIsBusyMode = false;

    return *this;
}

bool TraceableSignatureVerificationDataAdapter::isSamTraceabilityMode() const
{
    return mIsSamTraceabilityMode;
}

int TraceableSignatureVerificationDataAdapter::getTraceabilityOffset() const
{
    return mTraceabilityOffset;
}

bool TraceableSignatureVerificationDataAdapter::isPartialSamSerialNumber() const
{
    return mIsPartialSamSerialNumber;
}

bool TraceableSignatureVerificationDataAdapter::isSamRevocationStatusVerificationRequested() const
{
    return mIsSamRevocationStatusVerificationRequested;
}

bool TraceableSignatureVerificationDataAdapter::isBusyMode() const
{
    return mIsBusyMode;
}

}
}
}
