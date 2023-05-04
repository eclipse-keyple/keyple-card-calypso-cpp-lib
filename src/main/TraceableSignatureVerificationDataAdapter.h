/**************************************************************************************************
 * Copyright (c) 2023 Calypso Networks Association https://calypsonet.org/                        =======
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
#include "TraceableSignatureVerificationData.h"

/* Keyple Card Calypso */
#include "CommonSignatureVerificationDataAdapter.h"
#include "KeypleCardCalypsoExport.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::transaction;

/**
 * (package-private)<br>
 * Implementation of {@link TraceableSignatureVerificationData}.
 *
 * @since 2.2.0
 */
class KEYPLECARDCALYPSO_API TraceableSignatureVerificationDataAdapter final
: public CommonSignatureVerificationDataAdapter<TraceableSignatureVerificationData>,
  public TraceableSignatureVerificationData {
public:
    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    TraceableSignatureVerificationData& withSamTraceabilityMode(const int offset,
                                                                const bool isPartialSamSerialNumber,
                                                                const bool checkSamRevocationStatus)
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    TraceableSignatureVerificationData& withoutBusyMode() override;

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
     *         "SAM traceability" mode is enabled first.
     * @since 2.2.0
     */
    int getTraceabilityOffset() const;

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
     * @return True if the verification of the SAM revocation status is requested. It is required to
     *         check if the "SAM traceability" mode is enabled first.
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
    bool mIsSamRevocationStatusVerificationRequested = false;

    /**
     *
     */
    bool mIsBusyMode = true;
};

}
}
}
