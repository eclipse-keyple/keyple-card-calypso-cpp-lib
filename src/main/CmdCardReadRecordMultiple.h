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
 * Builds the "Read Record Multiple" APDU command.
 *
 * @since 2.1.0
 */
class CmdCardReadRecordMultiple final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Constructor.
     *
     * @param calypsoCardClass The CLA field value.
     * @param sfi The SFI.
     * @param recordNumber The number of the first record to read.
     * @param offset The offset from which to read in each record.
     * @param length The number of bytes to read in each record.
     * @since 2.1.0
     */
    CmdCardReadRecordMultiple(const CalypsoCardClass calypsoCardClass,
                              const uint8_t sfi,
                              const uint8_t recordNumber,
                              const uint8_t offset,
                              const uint8_t length);

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
    CmdCardReadRecordMultiple& setApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse)
        override;

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
     * @return The offset.
     * @since 2.1.0
     */
    uint8_t getOffset() const;

    /**
     * (package-private)<br>
     *
     * @return A not empty sorted map of read bytes by record number, or an empty map if no data is
     *     available.
     * @since 2.1.0
     */
    const std::map<const int, const std::vector<uint8_t>>& getResults() const;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CmdCardReadRecordMultiple));

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
    const uint8_t mRecordNumber;

    /**
     *
     */
    const uint8_t mOffset;

    /**
     *
     */
    const uint8_t mLength;

    /**
     *
     */
    std::map<const int, const std::vector<uint8_t>> mResults;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
