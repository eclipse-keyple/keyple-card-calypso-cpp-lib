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

#include "SignatureVerificationDataAdapter.h"

/* Keyple Core Util */
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

SignatureVerificationData& SignatureVerificationDataAdapter::setData(
    const std::vector<uint8_t>& data, 
    const std::vector<uint8_t>& signature, 
    const uint8_t kif, 
    const uint8_t kvc)
{
    mData = data;
    mSignature = signature;
    mKif = kif;
    mKvc = kvc;
    
    return *this;
}

SignatureVerificationData& SignatureVerificationDataAdapter::setKeyDiversifier(
    const std::vector<uint8_t>& diversifier) 
{
    mKeyDiversifier = diversifier;
    
    return *this;
}

SignatureVerificationData& SignatureVerificationDataAdapter::withSamTraceabilityMode(
    const int offset, 
    const bool isPartialSamSerialNumber, 
    const bool checkSamRevocationStatus) 
{
    mIsSamTraceabilityMode = true;
    mTraceabilityOffset = offset;
    mIsPartialSamSerialNumber = isPartialSamSerialNumber;
    mIsSamRevocationStatusVerificationRequested = checkSamRevocationStatus;
    
    return *this;
}

SignatureVerificationData& SignatureVerificationDataAdapter::withoutBusyMode() 
{
    mIsBusyMode = false;
    
    return *this;
}

bool SignatureVerificationDataAdapter::isSignatureValid()
{
    if (mIsSignatureValid == nullptr) {
        throw IllegalStateException("The command has not yet been processed");
    }

    return *isSignatureValid;
}

const std::vector<uint8_t>& SignatureVerificationDataAdapter::getData() const 
{
    return mData;
}

const std::vector<uint8_t>& SignatureVerificationDataAdapter::getSignature() const
{
    return mSignature;
}

uint8_t SignatureVerificationDataAdapter::getKif() const 
{
    return mKif;
}

uint8_t SignatureVerificationDataAdapter::getKvc() const 
{
    return mKvc;
}

const std::vector<uint8_t>& SignatureVerificationDataAdapter::getKeyDiversifier() const 
{
    return mKeyDiversifier;
}

bool SignatureVerificationDataAdapter::isSamTraceabilityMode() const 
{
    return mIsSamTraceabilityMode;
}

int SignatureVerificationDataAdapter::getTraceabilityOffset() const
{
    return mTraceabilityOffset;
}

bool SignatureVerificationDataAdapter::isPartialSamSerialNumber() const 
{
    return mIsPartialSamSerialNumber;
}

bool SignatureVerificationDataAdapter::isSamRevocationStatusVerificationRequested() const 
{
    return mIsSamRevocationStatusVerificationRequested;
}

bool SignatureVerificationDataAdapter::isBusyMode() const 
{
    return mIsBusyMode;
}

void SignatureVerificationDataAdapter::setSignatureValid(const bool isSignatureValid) 
{
    mIsSignatureValid = std::make_shared<bool>(isSignatureValid);
}

}
}
}
