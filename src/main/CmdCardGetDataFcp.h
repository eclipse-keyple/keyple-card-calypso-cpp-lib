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
#include <memory>
#include <vector>

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardClass.h"
#include "CalypsoCardCommand.h"

namespace keyple {
namespace card {
namespace calypso {

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the Get data APDU commands for the FCP tag.
 *
 * <p>In contact mode, this command can not be sent in a secure session because it would generate a
 * 6Cxx status and thus make calculation of the digest impossible.
 *
 * <p>The value of the Proprietary Information tag is extracted from the Select File response and
 * made available using the corresponding getter.
 *
 * @since 2.0.1
 */
class CmdCardGetDataFcp final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardGetDataFci.
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @since 2.0.1
     */
    CmdCardGetDataFcp(const CalypsoCardClass calypsoCardClass);

    /**
     * {@inheritDoc}
     *
     * @return False
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * (package-private)<br>
     *
     * @return The content of the proprietary information tag present in the response to the Get
     *         Data (FCP) command
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getProprietaryInformation();

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
    /**
     *
     */
    static const CalypsoCardCommand mCommand;

    /**
     *
     */
    static const int TAG_PROPRIETARY_INFORMATION;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    std::vector<uint8_t> mProprietaryInformation;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
