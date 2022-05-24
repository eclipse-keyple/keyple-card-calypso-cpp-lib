
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

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardClass.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the "Increase/Decrease Multiple" APDU command.
 *
 * @since 2.1.0
 */
class CmdCardIncreaseOrDecreaseMultiple final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Constructor.
     *
     * @param isDecreaseCommand True if it is a "Decrease Multiple" command, false if it is an
     *        "Increase Multiple" command.
     * @param calypsoCardClass The CLA field value.
     * @param sfi The SFI.
     * @param counterNumberToIncDecValueMap The map containing the counter numbers to be incremented
     *        and their associated increment values.
     * @since 2.1.0
     */
    CmdCardIncreaseOrDecreaseMultiple(
        const bool isDecreaseCommand,
        const CalypsoCardClass calypsoCardClass,
        const uint8_t sfi,
        const std::map<const int, const int> counterNumberToIncDecValueMap);

    /**
     * {@inheritDoc}
     *
     * <p>This command modified the contents of the card and therefore uses the session buffer.
     *
     * @return false
     * @since 2.1.0
     */
    bool isSessionBufferUsed() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    CmdCardIncreaseOrDecreaseMultiple& setApduResponse(
        const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * (package-private)<br>
     *
     * @return The SFI.
     * @since 2.1.0
     */
    int getSfi() const;

    /**
     * (package-private)<br>
     *
     * @return The counters/values map.
     * @since 2.1.0
     */
    const std::map<const int, const int>& getCounterNumberToIncDecValueMap() const;
    /**
     * (package-private)<br>
     *
     * @return A not empty sorted map of counter values as 3-byte array by counter number, or an
     *         empty map if no data is available.
     * @since 2.1.0
     */
    const std::map<const int, const std::vector<uint8_t>>& getNewCounterValues() const;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CmdCardIncreaseOrDecreaseMultiple));

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    const uint8_t mSfi;

    /**
     *
     */
    const std::map<const int, const int> mCounterNumberToIncDecValueMap;

    /**
     *
     */
    std::map<const int, const std::vector<uint8_t>> mNewCounterValues;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
