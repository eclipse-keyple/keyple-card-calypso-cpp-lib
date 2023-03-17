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

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardAdapter.h"
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
 * Builds the "Write Record" APDU command.
 *
 * @since 2.0.1
 */
class CmdCardWriteRecord final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardWriteRecord.
     *
     * @param calypsoCard The Calypso card.
     * @param sfi the sfi to select.
     * @param recordNumber the record number to write.
     * @param newRecordData the new record data to write.
     * @throw IllegalArgumentException If record number is &lt; 1
     * @throw IllegalArgumentException If the request is inconsistent
     * @since 2.0.1
     */
    CmdCardWriteRecord(const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                       const uint8_t sfi,
                       const uint8_t recordNumber,
                       const std::vector<uint8_t>& newRecordData);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @return True
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CmdCardWriteRecord));

    /**
     * The command
     */
    static const CalypsoCardCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     * Construction arguments
     */
    const uint8_t mSfi;

    /**
     *
     */
    const uint8_t mRecordNumber;

    /**
     *
     */
    const std::vector<uint8_t> mData;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
