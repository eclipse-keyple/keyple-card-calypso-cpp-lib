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

#include <cstdint>
#include <map>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "CalypsoSam.h"

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::sam;

/**
 * (package-private)<br>
 * Builds the Give Random APDU command.
 *
 * @since 2.0.1
 */
class CmdSamCardGenerateKey final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdSamCardGenerateKey and generate the ciphered data for a key ciphered by
     * another.
     *
     * <p>If bot KIF and KVC of the ciphering are equal to 0, the source key is ciphered with the null
     * key.
     *
     * @param productType the SAM product type.
     * @param cipheringKif The KIF of the ciphering key.
     * @param cipheringKvc The KVC of the ciphering key.
     * @param sourceKif The KIF of the source key.
     * @param sourceKvc The KVC of the source key.
     * @since 2.0.1
     */
    CmdSamCardGenerateKey(const CalypsoSam::ProductType productType,
                          const uint8_t cipheringKif,
                          const uint8_t cipheringKvc,
                          const uint8_t sourceKif,
                          const uint8_t sourceKvc);

    /**
     * (package-private)<br>
     * Gets the 32 bytes of ciphered data.
     *
     * @return the ciphered data byte array or null if the operation failed
     * @since 2.0.1
     */
    const std::vector<uint8_t> getCipheredData() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
    /**
     * The command
     */
    static const CalypsoSamCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
