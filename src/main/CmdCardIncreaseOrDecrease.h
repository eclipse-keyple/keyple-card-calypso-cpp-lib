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
 * Builds the "Increase/Decrease" APDU command.
 *
 * @since 2.1.0
 */
class CmdCardIncreaseOrDecrease final : public AbstractCardCommand {
public:
    /**
     * (package-private)<br>
     * Constructor.
     *
     * @param isDecreaseCommand True if it is a "Decrease" command, false if it is an * "Increase"
     *        command.
     * @param calypsoCardClass indicates which CLA byte should be used for the Apdu.
     * @param sfi SFI of the file to select or 00h for current EF.
     * @param counterNumber &gt;= 01h: Counters file, number of the counter. 00h: Simulated Counter.
     *        file.
     * @param incDecValue Value to subtract or add to the counter (defined as a positive int &lt;=
     *        16777215 [FFFFFFh])
     * @throw IllegalArgumentException If the decrement value is out of range
     * @throw IllegalArgumentException If the command is inconsistent
     */
    CmdCardIncreaseOrDecrease(const bool isDecreaseCommand,
                              const CalypsoCardClass calypsoCardClass,
                              const uint8_t sfi,
                              const int counterValue,
                              const int incDecValue);

    /**
     * {@inheritDoc}
     *
     * @return true
     * @since 2.1.0
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
     * @return The counter number
     * @since 2.0.1
     */
    int getCounterNumber() const;

    /**
     * (package-private)<br>
     *
     * @return The decrement/increment value
     * @since 2.0.1
     */
    int getIncDecValue() const;

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
    const std::unique_ptr<Logger> mLogger =
        LoggerFactory::getLogger(typeid(CmdCardIncreaseOrDecrease));

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
    const int mCounterNumber;

    /**
     *
     */
    const int mIncDecValue;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
