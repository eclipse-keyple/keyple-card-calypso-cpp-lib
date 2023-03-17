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

/* Calypsonet Terminal Calypso */
#include "CalypsoCard.h"

/* Calypsonet Terminal Card */
#include "ApduResponseApi.h"

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardAdapter.h"
#include "CalypsoCardClass.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::card;
using namespace calypsonet::terminal::calypso::card;
using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the "Read Binary" APDU command.
 *
 * @since 2.1.0
 */
class CmdCardReadBinary final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Constructor.
     *
     * @param calypsoCard The Calypso card.
     * @param sfi The sfi to select.
     * @param offset The offset.
     * @param length The number of bytes to read.
     * @since 2.1.0
     */
    CmdCardReadBinary(const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                      const uint8_t sfi,
                      const uint8_t offset,
                      const uint8_t length);

    /**
     * {@inheritDoc}
     *
     * @return false
     * @since 2.1.0
     * @since 2.2.3
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

    /**
     * {@inheritDoc}
     *
     * @return false
     * @since 2.1.0
     */
    bool isSessionBufferUsed() const override;

    /**
     * (package-private)<br>
     *
     * @return The offset.
     * @since 2.1.0
     */
    uint8_t getOffset() const;

    /**
     * {@inheritDoc}
     *
     * @since 2.1.0
     */
    const std::map<const int, const std::shared_ptr<StatusProperties>>& getStatusTable() const
        override;

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(CmdCardReadBinary));

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
    const uint8_t mOffset;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
