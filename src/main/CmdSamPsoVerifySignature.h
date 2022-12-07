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

#include "AbstractSamCommand.h"
#include "SignatureVerificationDataAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Builds the "PSO Verify Signature" SAM command.
 *
 * @since 2.2.0
 */
class CmdSamPsoVerifySignature final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Builds a new instance based on the provided signature verification data.
     *
     * @param productType The SAM product type.
     * @param data The signature verification data.
     * @since 2.2.0
     */
    CmdSamPsoVerifySignature(const CalypsoSam::ProductType productType, 
                             const std::shred_ptr<SignatureVerificationDataAdapter> data);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.0
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() override;

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
    const std::shared_ptr<SignatureVerificationDataAdapter> mData;
};

}
}
}
