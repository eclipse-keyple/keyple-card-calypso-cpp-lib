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
     * @param calypsoCard The Calypso card.
     * @param sfi the sfi top select.
     * @param firstRecordNumber the record number to read (or first record to read in case of
     *        several records)
     * @param readMode read mode, requests the reading of one or all the records.
     * @param expectedLength the expected length of the record(s).
     * @since 2.2.3
     */
    CmdCardReadRecords(const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                       const int sfi,
                       const int firstRecordNumber,
                       const ReadMode readMode,
                       const int expectedLength);

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
     * @since 2.0.1
     */
    CmdCardReadRecords(const CalypsoCardClass calypsoCardClass,
                       const uint8_t sfi,
                       const uint8_t firstRecordNumber,
                       const ReadMode readMode,
                       const int expectedLength);

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
     * @return the size of the record to read
     * @since 2.2.5.4
     */
    int getRecordSize() const;

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
    int mSfi = 0;

    /**
     *
     */
    int mRecordSize = 0;

    /**
     *
     */
    int mFirstRecordNumber = 0;


    /**
     *
     */
    ReadMode mReadMode = ReadMode::ONE_RECORD;

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
     * @param sfi the sfi top select.
     * @param firstRecordNumber the record number to read (or first record to read in case of several.
     *     records)
     * @param readMode read mode, requests the reading of one or all the records.
     * @param expectedLength the expected length of the record(s).
     */
    void buildCommand(const CalypsoCardClass calypsoCardClass,
                      const int sfi,
                      const int firstRecordNumber,
                      const ReadMode readMode,
                      const int expectedLength);

};

}
}
}
