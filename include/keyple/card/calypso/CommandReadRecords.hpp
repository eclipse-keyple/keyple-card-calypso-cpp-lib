/******************************************************************************
 * Copyright (c) 2025 Calypso Networks Association https://calypsonet.org/    *
 *                                                                            *
 * See the NOTICE file(s) distributed with this work for additional           *
 * information regarding copyright ownership.                                 *
 *                                                                            *
 * This program and the accompanying materials are made available under the   *
 * terms of the Eclipse Public License 2.0 which is available at              *
 * http://www.eclipse.org/legal/epl-2.0                                       *
 *                                                                            *
 * SPDX-License-Identifier: EPL-2.0                                           *
 ******************************************************************************/

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

#include "keyple/card/calypso/Command.hpp"
#include "keyple/card/calypso/DtoAdapters.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/calypso/card/card/ElementaryFile.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::calypso::card::card::ElementaryFile;

/**
 * Builds the Read Records APDU command.
 *
 * @since 2.0.1
 */
class CommandReadRecords final : public Command {
public:
    /**
     * Indicates if one or multiple records
     *
     * @since 2.0.1
     */
    enum class ReadMode {
        /** read one record */
        ONE_RECORD,

        /** read multiple records */
        MULTIPLE_RECORD
    };

    /**
     * Instantiates a new read records cmd build.
     *
     * @param transactionContext The global transaction context common to all
     * commands.
     * @param commandContext The local command context specific to each command.
     * @param sfi the sfi top select.
     * @param firstRecordNumber the record number to read (or first record to
     * read in case of several. records)
     * @param readMode read mode, requests the reading of one or all the
     * records.
     * @param expectedLength the expected length of the record(s) or -1 if not
     * specified.
     * @param recordSize the size of one record.
     * @since 2.3.2
     */
    CommandReadRecords(
        const std::shared_ptr<DtoAdapters::TransactionContextDto>&
            transactionContext,
        const std::shared_ptr<DtoAdapters::CommandContextDto>& commandContext,
        int sfi,
        int firstRecordNumber,
        ReadMode readMode,
        std::unique_ptr<int> expectedLength,
        int recordSize);

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void finalizeRequest() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool isCryptoServiceRequiredToFinalizeRequest() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    bool synchronizeCryptoServiceBeforeCardProcessing() override;

    /**
     * {@inheritDoc}
     *
     * @since 2.3.2
     */
    void parseResponse(std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.1
     */
    const std::map<int, const std::shared_ptr<Command::StatusProperties>>&
    getStatusTable() const override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(CommandReadRecords));

    /**
     *
     */
    static const std::map<int, const std::shared_ptr<Command::StatusProperties>>
        STATUS_TABLE;

    /**
     *
     */
    const int mSfi;

    /**
     *
     */
    const int mFirstRecordNumber;

    /**
     *
     */
    const int mRecordSize;

    /**
     *
     */
    const ReadMode mReadMode;

    /**
     *
     */
    const bool mIsPreOpenMode;

    /**
     *
     */
    std::vector<uint8_t> mAnticipatedDataOut;

    /**
     * Builds the anticipated APDU response with the SW.
     *
     * @return Null if the record or some records have not been read beforehand.
     */
    std::vector<std::uint8_t> buildAnticipatedResponse();

    /**
     * Builds the anticipated APDU response with the SW for single record mode.
     *
     * @param ef The EF.
     * @return Null if the record has not been read beforehand.
     */
    std::vector<std::uint8_t> buildAnticipatedResponseForOneRecordMode(
        const std::shared_ptr<ElementaryFile>& ef);

    /**
     * Builds the anticipated APDU response with the SW for multiple records
     * mode.
     *
     * @param ef The EF.
     * @return Null if some records have not been read beforehand.
     */
    std::vector<std::uint8_t> buildAnticipatedResponseForMultipleRecordsMode(
        const std::shared_ptr<ElementaryFile>& ef);
};

} /* namespace calypso */
} /* namespace card */
} /* namespace keyple */
