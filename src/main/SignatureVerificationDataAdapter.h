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
#include "SignatureVerificationData.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Implementation of {@link SignatureVerificationData}.
 *
 * @since 2.2.0
 */
class SignatureVerificationDataAdapter final : public SignatureVerificationData {
public:
    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureVerificationData& setData(const std::vector<uint8_t>& data, 
                                       const std::vector<uint8_t>& signature, 
                                       const uint8_t kif, 
                                       const uint8_t kvc) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureVerificationData& setKeyDiversifier(byte[] diversifier) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureVerificationData& withSamTraceabilityMode(const int offset, 
                                                       const bool isPartialSamSerialNumber, 
                                                       const bool checkSamRevocationStatus);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    SignatureVerificationData& withoutBusyMode() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    bool isSignatureValid() override;

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
     * @return A not empty array of the signature to check. It is required to check input data first.
     * @since 2.2.0
     */
    const std::vector<uint8_t>& getSignature() const;

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
     * @return True if the verification of the SAM revocation status is requested. It is required to
     *     check if the "SAM traceability" mode is enabled first.
     * @since 2.2.0
     */
    bool isSamRevocationStatusVerificationRequested() const;

    /**
     * (package-private)<br>
     *
     * @return True if the "Busy" mode is enabled.
     * @since 2.2.0
     */
    bool isBusyMode() const;

    /**
     * (package-private)<br>
     * Sets the signature verification status.
     *
     * @param isSignatureValid True if the signature is valid.
     * @since 2.2.0
     */
    void setSignatureValid(const bool isSignatureValid);

private:
    /**
     * 
     */
    std::vector<uint8_t> mData;

    /**
     * 
     */
    std::vector<uint8_t> mSignature;

    /**
     * 
     */
    uint8_t kif = 0;

    /**
     * 
     */
    uint8_t kvc = 0;

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
    bool mIsSamRevocationStatusVerificationRequested = false;

    /**
     * 
     */
    bool mIsBusyMode = true;

    /**
     * 
     */
    std::shared_ptr<bool> mIsSignatureValid = nullptr;
};

}
}
}
