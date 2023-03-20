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

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardAdapter.h"
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
     * @param calypsoCard The Calypso card.
     * @since 2.2.3
     */
    CmdCardGetDataFcp(const std::shared_ptr<CalypsoCardAdapter> calypsoCard);

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
     * @since 2.2.3
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @return False
     */
    bool isSessionBufferUsed() const override;

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
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();

    /**
    * (private)<br>
    * Builds the command.
    *
    * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
    */
    void buildCommand(const CalypsoCardClass calypsoCardClass);
};

}
}
}
