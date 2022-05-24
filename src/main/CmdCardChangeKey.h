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

/* Calypsonet Terminal Calypso */
#include "CalypsoCard.h"
#include "SvDebitLogRecord.h"
#include "SvLoadLogRecord.h"
#include "SvOperation.h"

/* Keyple Card Calypso */
#include "AbstractApduCommand.h"
#include "AbstractCardCommand.h"
#include "CalypsoCardClass.h"

/* Keyple Core Util */
#include "LoggerFactory.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;
using namespace calypsonet::terminal::calypso::transaction;
using namespace keyple::core::util::cpp;

using StatusProperties = AbstractApduCommand::StatusProperties;

/**
 * (package-private)<br>
 * Builds the Change key APDU command.
 *
 * @since 2.1.0
 */
class CmdCardChangeKey final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Change Key Calypso command
     *
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @param keyIndex index of the key of the current DF to change.
     * @param cryptogram key encrypted with Issuer key (key #1).
     * @since 2.1.0
     */
    CmdCardChangeKey(const CalypsoCardClass calypsoCardClass,
                     const uint8_t keyIndex,
                     const std::vector<uint8_t>& cryptogram);

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

private:
    /**
     *
     */
    static const CalypsoCardCommand mCommand;

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
