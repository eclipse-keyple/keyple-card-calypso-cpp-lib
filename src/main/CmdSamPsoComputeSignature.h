/**************************************************************************************************
 * Copyright (c) 2021 Calypso Networks Association https://calypsonet.org/                        *
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

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "TraceableSignatureComputationDataAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;

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
     * @param productType The SAM product type.
     * @param data The signature computation data.
     * @since 2.2.0
     */
    CmdSamPsoComputeSignature(const CalypsoSam::ProductType productType,
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
    AbstractSamCommand& setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
        override;


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
