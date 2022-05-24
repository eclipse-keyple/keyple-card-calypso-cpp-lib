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
#include "SearchCommandDataAdapter.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the "Search Record Multiple" APDU command.
 *
 * @since 2.1.0
 */
class CmdCardSearchRecordMultiple final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Constructor.
     *
     * @param calypsoCardClass The CLA field value.
     * @param data The search command input/output data.
     * @since 2.1.0
     */
    CmdCardSearchRecordMultiple(const CalypsoCardClass calypsoCardClass,
                                const std::shared_ptr<SearchCommandDataAdapter> data);

    /**
     * {@inheritDoc}
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
    CmdCardSearchRecordMultiple& setApduResponse(
        const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * (package-private)<br>
     *
     * @return The search command input/output data.
     * @since 2.1.0
     */
    const std::shared_ptr<SearchCommandDataAdapter> getSearchCommandData() const;

    /**
     * (package-private)<br>
     *
     * @return An empty array if fetching of first matching record is not requested or if no record
     *     has matched.
     * @since 2.1.0
     */
    const std::vector<uint8_t> getFirstMatchingRecordContent() const;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CmdCardSearchRecordMultiple));

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     *
     */
    const std::shared_ptr<SearchCommandDataAdapter> mData;

    /**
     *
     */
    std::vector<uint8_t> mFirstMatchingRecordContent;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
