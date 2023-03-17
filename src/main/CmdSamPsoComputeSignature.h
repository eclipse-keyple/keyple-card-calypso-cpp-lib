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

#include <map>

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "TraceableSignatureComputationDataAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Builds the "PSO Compute Signature" SAM command.
 *
 * @since 2.2.0
 */
class CmdSamPsoComputeSignature final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Builds a new instance based on the provided signature computation data.
     *
     * @param calypsoSam The Calypso SAM.
     * @param data The signature computation data.
     * @since 2.2.0
     */
    CmdSamPsoComputeSignature(const std::shared_ptr<CalypsoSamAdapter> calypsoSam,
                              const std::shared_ptr<TraceableSignatureComputationDataAdapter> data);

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
    const std::shared_ptr<TraceableSignatureComputationDataAdapter> mData;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
