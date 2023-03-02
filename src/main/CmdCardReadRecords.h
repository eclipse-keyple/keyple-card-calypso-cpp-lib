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
#include "CalypsoCardClass.h"
#include "CalypsoCardCommand.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the Read Records APDU command.
 *
 * @since 2.0.1
 */
class CmdCardReadRecords final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Indicates if one or multiple records
     *
     * @since 2.0.1
     */
    enum class ReadMode {
        /**
         * Read one record
         */
        ONE_RECORD,

        /**
         * Read multiple records
         */
        MULTIPLE_RECORD
    };

    /**
     * (package-private)<br>
     * Instantiates a new read records cmd build.
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @param sfi the sfi top select.
     * @param firstRecordNumber the record number to read (or first record to read in case of
     *        several records)
     * @param readMode read mode, requests the reading of one or all the records.
     * @param expectedLength the expected length of the record(s).
     * @throws IllegalArgumentException If record number &lt; 1
     * @throws IllegalArgumentException If the request is inconsistent
     * @since 2.0.1
     */
    CmdCardReadRecords(const CalypsoCardClass calypsoCardClass,
                       const uint8_t sfi,
                       const uint8_t firstRecordNumber,
                       const ReadMode readMode,
                       const uint8_t expectedLength);

    /**
     * {@inheritDoc}
     *
     * @return false
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * (package-private)<br>
     *
     * @return the SFI of the accessed file
     * @since 2.0.1
     */
    uint8_t getSfi() const;

    /**
     * (package-private)<br>
     *
     * @return the number of the first record to read
     * @since 2.0.1
     */
    uint8_t getFirstRecordNumber() const;

    /**
     * (package-private)<br>
     *
     * @return the readJustOneRecord flag
     * @since 2.0.1
     */
    ReadMode getReadMode() const;

    /**
     * (package-private)<br>
     *
     * @return A not empty map of records content by record numbers, or an empty map if no data is
     *         available.
     * @since 2.0.1
     */
    const std::map<const uint8_t, const std::vector<uint8_t>>& getRecords() const;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const ReadMode rm);

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CmdCardReadRecords));

    /**
     *
     */
    static const CalypsoCardCommand mCommand;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;

    /**
     * Construction arguments used for parsing
     */
    const uint8_t mSfi;

    /**
     *
     */
    const uint8_t mFirstRecordNumber;

    /**
     *
     */
    const ReadMode mReadMode;

    /**
     *
     */
    std::map<const uint8_t, const std::vector<uint8_t>> mRecords;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();

};

}
}
}
