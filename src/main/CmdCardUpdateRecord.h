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
 * Builds the Update Record APDU command.
 *
 * @since 2.0.1
 */
class CmdCardUpdateRecord final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Instantiates a new CmdCardUpdateRecord.
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @param sfi the sfi to select.
     * @param recordNumber the record number to update.
     * @param newRecordData the new record data to write.
     * @throw IllegalArgumentException If record number is &lt; 1
     * @throw IllegalArgumentException If the request is inconsistent
     * @since 2.0.1
     */
    CmdCardUpdateRecord(const CalypsoCardClass calypsoCardClass,
                        const uint8_t sfi,
                        const int recordNumber,
                        const std::vector<uint8_t>& newRecordData);

    /**
     * {@inheritDoc}
     *
     * <p>This command modified the contents of the card and therefore uses the session buffer.
     *
     * @return True
     * @since 2.0.1
     */
    bool isSessionBufferUsed() const override;

    /**
     * (package-private)<br>
     *
     * @return The SFI of the accessed file
     * @since 2.0.1
     */
    int getSfi() const;

    /**
     * (package-private)<br>
     *
     * @return The number of the accessed record
     * @since 2.0.1
     */
    int getRecordNumber() const;

    /**
     * (package-private)<br>
     *
     * @return The data sent to the card
     * @since 2.0.1
     */
    const std::vector<uint8_t>& getData() const;

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
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CmdCardUpdateRecord));

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> STATUS_TABLE;


    /**
     * The command
     */
    static const CalypsoCardCommand mCommand;

    /**
     * Construction arguments
     */
    const int mSfi;

    /**
     *
     */
    const int mRecordNumber;

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
