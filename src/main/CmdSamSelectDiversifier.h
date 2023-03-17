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
#include <vector>

/* Keyple Card Calypso */
#include "AbstractSamCommand.h"
#include "CalypsoSamAdapter.h"

namespace keyple {
namespace card {
namespace calypso {

/**
 * (package-private)<br>
 * Builds the SAM Select Diversifier APDU command.
 *
 * @since 2.0.1
 */
class CmdSamSelectDiversifier final : public AbstractSamCommand {
public:
    /**
     * (package-private)<br>
     * Creates a new instance.
     *
     * @param calypsoSam The Calypso SAM.
     * @param diversifier The key diversifier.
     * @throws IllegalArgumentException If the diversifier is null or has a wrong length
     * @since 2.0.1
     */
    CmdSamSelectDiversifier(const std::shared_ptr<CalypsoSamAdapter> calypsoSam,
                            std::vector<uint8_t>& diversifier);

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
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
