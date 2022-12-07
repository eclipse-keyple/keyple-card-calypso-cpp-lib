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

#include "SignatureComputationDataAdapter.h"

/* Keyple Core Util */
#include "IllegalStateException.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp::exception;

SignatureComputationData& SignatureComputationDataAdapter::setData(const std::vector<uint8_t>& data, 
                                                                   const uint8_t kif, 
                                                                   const uint8_t kvc)
{
    mData = data;
    mKif = kif;
    mKvc = kvc;
    
    return *this;
}

SignatureComputationData& SignatureComputationDataAdapter::setSignatureSize(const int size)
{
    mSignatureSize = size;
    
    return *this;
}

SignatureComputationData& SignatureComputationDataAdapter::setKeyDiversifier(
    const std::vector<uint8_t> diversifier) 
{
    mKeyDiversifier = diversifier;
    
    return *this;
}

SignatureComputationData& SignatureComputationDataAdapter::withSamTraceabilityMode(
    const int offset, const bool usePartialSamSerialNumber)
{
    mIsSamTraceabilityMode = true;
    mTraceabilityOffset = offset;
    mIsPartialSamSerialNumber = usePartialSamSerialNumber;
    
    return *this;
}

SignatureComputationData& SignatureComputationDataAdapter::withoutBusyMode() 
{
    mIsBusyMode = false;
    
    return *this;
}

const std::vector<uint8_t> SignatureComputationDataAdapter::getSignedData() const
{
    if (!mIsSignedDataSet) {
        throw IllegalStateException("The command has not yet been processed");
    }

    return mSignedData;
}

const std::vector<uint8_t>& SignatureComputationDataAdapter::getSignature() const
{
    if (!mIsSignatureSet) {
        throw IllegalStateException("The command has not yet been processed");
    }

    return mSignature;
}

const std::vector<uint8_t>& SignatureComputationDataAdapter::getData() const 
{
    return mData;
}

uint8_t SignatureComputationDataAdapter::getKif() const 
{
    return mKif;
}

uint8_t SignatureComputationDataAdapter::getKvc() const 
{
    return mKvc;
}

int SignatureComputationDataAdapter::getSignatureSize() const 
{
    return mSignatureSize;
}

const std::vector<uint8_t>& SignatureComputationDataAdapter::getKeyDiversifier() const
{
    return mKeyDiversifier;
}

bool SignatureComputationDataAdapter::isSamTraceabilityMode() const 
{
    return mIsSamTraceabilityMode;
}

int SignatureComputationDataAdapter::getTraceabilityOffset() const 
{
    return mTraceabilityOffset;
}

bool SignatureComputationDataAdapter::isPartialSamSerialNumber() const
{
    return mIsPartialSamSerialNumber;
}

bool SignatureComputationDataAdapter::isBusyMode() const
{
    return mIsBusyMode;
}

SignatureComputationDataAdapter& SignatureComputationDataAdapter::setSignedData(
    const std::vector<uint8_t>& signedData)
{
    mSignedData = signedData;
    mIsSignedDataSet = true,
    
    return *this;
}

SignatureComputationDataAdapter& SignatureComputationDataAdapter::setSignature(
    const std::vector<uint8_t>& signature) 
{
    mSignature = signature;
    mIsSignatureSet = true;
    
    return *this;
}

}
}
}
