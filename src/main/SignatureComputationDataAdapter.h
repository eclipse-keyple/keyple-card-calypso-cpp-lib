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

/* Calypsonet Terminal Calypso */
#include "SignatureComputationData.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;

/**
 * (package-private)<br>
 * Implementation of {@link SignatureComputationData}.
 *
 * @since 2.2.0
 */
class SignatureComputationDataAdapter final : public SignatureComputationData {
public:
    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureComputationData& setData(const std::vector<uint8_t>& data, 
                                      const uint8_t kif, 
                                      const uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureComputationData& setSignatureSize(const int size) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureComputationData& setKeyDiversifier(const std::vector<uint8_t> diversifier) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureComputationData& withSamTraceabilityMode(const int offset, 
                                                      const bool usePartialSamSerialNumber) 
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureComputationData& withoutBusyMode() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::vector<uint8_t>& getSignedData() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::vector<uint8_t>& getSignature() const override;

    /**
     * (package-private)<br>
     *
     * @return A not empty array of data. It is required to check input data first.
     * @since 2.2.0
     */
    const std::vector<uint8_t>& getData() const;

    /**
     * (package-private)<br>
     *
     * @return The KIF. It is required to check input data first.
     * @since 2.2.0
     */
    uint8_t getKif() const;

    /**
     * (package-private)<br>
     *
     * @return The KVC. It is required to check input data first.
     * @since 2.2.0
     */
    uint8_t getKvc() const;

    /**
     * (package-private)<br>
     *
     * @return The signature size.
     * @since 2.2.0
     */
    int getSignatureSize() const;

    /**
     * (package-private)<br>
     *
     * @return Null if the key diversifier is not set.
     * @since 2.2.0
     */
    const std::vector<uint8_t>& getKeyDiversifier() const;

    /**
     * (package-private)<br>
     *
     * @return True if the "SAM traceability" mode is enabled.
     * @since 2.2.0
     */
    bool isSamTraceabilityMode() const;

    /**
     * (package-private)<br>
     *
     * @return The offset associated to the "SAM traceability" mode. It is required to check if the
     *     "SAM traceability" mode is enabled first.
     * @since 2.2.0
     */
    int getTraceabilityOffset() const;

    /**
     * (package-private)<br>
     *
     * @return True if it is requested to use the partial SAM serial number with the "SAM
     *     traceability" mode. It is required to check if the "SAM traceability" mode is enabled
     *     first.
     * @since 2.2.0
     */
    bool isPartialSamSerialNumber() const;

    /**
     * (package-private)<br>
     *
     * @return True if the "Busy" mode is enabled.
     * @since 2.2.0
     */
    bool isBusyMode() const;

    /**
     * (package-private)<br>
     * Sets the data used for signature computation.
     *
     * @param signedData The signed data.
     * @return The current instance.
     * @since 2.2.0
     */
    SignatureComputationDataAdapter& setSignedData(const std::vector<uint8_t>& signedData);

    /**
     * (package-private)<br>
     * Sets the computed signature.
     *
     * @param signature The computed signature.
     * @return The current instance.
     * @since 2.2.0
     */
    SignatureComputationDataAdapter& setSignature(const std::vector<uint8_t>& signature);

private:
    /**
     * 
     */
    std::vector<uint8_t> mData;

    /**
     * 
     */
    uint8_t mKif = 0;

    /**
     * 
     */
    uint8_t mKvc = 0;

    /**
     * 
     */
    int mSignatureSize = 8;
    
    /**
     * 
     */
    std::vector<uint8_t> mKeyDiversifier;

    /**
     * 
     */
    bool mIsSamTraceabilityMode = false;

    /**
     * 
     */
    int mTraceabilityOffset = 0;
    
    /**
     * 
     */
    bool mIsPartialSamSerialNumber = false;

    /**
     * 
     */
    bool mIsBusyMode = true;
    
    /**
     * 
     */
    std::vector<uint8_t> mSignedData;

    /**
     * C++: Java equivalent to null assertion on mSignedData
     */
    bool mIsSignedDataSet = false;

    /**
     * 
     */
    std::vector<uint8_t> mSignature;

    /**
     * C++: Java equivalent to null assertion on mSignature
     */
    bool mIsSignatureSet = false;
};

}
}
}
