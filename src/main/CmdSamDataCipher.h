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

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractSamCommand.h"
#include "BasicSignatureComputationDataAdapter.h"
#include "BasicSignatureVerificationDataAdapter.h"
#include "CalypsoSamAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the "Data Cipher" SAM command.
 *
 * @since 2.2.0
 */
class CmdSamDataCipher final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Builds a new instance based on the provided data.
     *
     * @param calypsoSam The Calypso SAM.
     * @param signatureComputationData The signature computation data (optional).
     * @param signatureVerificationData The signature computation data (optional).
     * @since 2.2.0
     */
    CmdSamDataCipher(
        const std::shared_ptr<CalypsoSamAdapter> calypsoSam,
        const std::shared_ptr<BasicSignatureComputationDataAdapter> signatureComputationData,
        const std::shared_ptr<BasicSignatureVerificationDataAdapter> signatureVerificationData);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

private:
    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    const std::shared_ptr<BasicSignatureComputationDataAdapter> mSignatureComputationData;

    /**
     *
     */
    const std::shared_ptr<BasicSignatureVerificationDataAdapter> mSignatureVerificationData;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
