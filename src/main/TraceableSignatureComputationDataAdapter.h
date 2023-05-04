/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        *
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
#include "TraceableSignatureComputationData.h"

/* Keyple Card Calypso */
#include "CommonSignatureComputationDataAdapter.h"
#include "KeypleCardCalypsoExport.h"


namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;

/**
 * (package-private)<br>
 * Implementation of {@link TraceableSignatureComputationData}.
 *
 * @since 2.2.0
 */
class KEYPLECARDCALYPSO_API TraceableSignatureComputationDataAdapter final
: public CommonSignatureComputationDataAdapter<TraceableSignatureComputationData>,
  public TraceableSignatureComputationData {
public:
    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    TraceableSignatureComputationData& withSamTraceabilityMode(const int offset,
                                                               const bool usePartialSamSerialNumber)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    TraceableSignatureComputationData& withoutBusyMode() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::vector<uint8_t>& getSignedData() const override;

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
     * @return True if it is requested to use the partial SAM serial number with the "SAM
     *         traceability" mode. It is required to check if the "SAM traceability" mode is enabled
     *         first.
     * @since 2.2.0
     */
    bool isPartialSamSerialNumber() const;

    /**
     * (package-private)<br>
     *
     * @return The offset associated to the "SAM traceability" mode. It is required to check if the
     *         "SAM traceability" mode is enabled first.
     * @since 2.2.0
     */
    int getTraceabilityOffset() const;

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
     * @since 2.2.0
     */
    void setSignedData(const std::vector<uint8_t>& signedData);

private:
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
     * C++: required to avoid pointer on mSignedData
     */
    bool mSignedDataPresent = false;
};

}
}
}
