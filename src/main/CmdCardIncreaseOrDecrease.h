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
     * @param calypsoCard The Calypso card.
     * @param sfi SFI of the file to select or 00h for current EF.
     * @param counterNumber &gt;= 01h: Counters file, number of the counter. 00h: Simulated Counter.
     *        file.
     * @param incDecValue Value to subtract or add to the counter (defined as a positive int &lt;=
     *        16777215 [FFFFFFh])
     */
    CmdCardIncreaseOrDecrease(const bool isDecreaseCommand,
                              const std::shared_ptr<CalypsoCardAdapter> calypsoCard,
                              const uint8_t sfi,
                              const uint8_t counterValue,
                              const int incDecValue);

    /**
     * {@inheritDoc}
     *
     * @since 2.2.3
     */
    void parseApduResponse(const std::shared_ptr<ApduResponseApi> apduResponse) override;

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
    uint8_t getSfi() const;

    /**
     * (package-private)<br>
     *
     * @return The counter number
     * @since 2.0.1
     */
    uint8_t getCounterNumber() const;

    /**
     * (package-private)<br>
     *
     * @return The decrement/increment value
     * @since 2.0.1
     */
    int getIncDecValue() const;

    /**
     * (package-private)<br>
     * Sets the computed data.
     *
     * @param data A 3-byte array containing the computed data.
     * @since 2.2.4
     */
    void setComputedData(const std::vector<uint8_t>& data);

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
    static const int SW_POSTPONED_DATA;

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
    const uint8_t mCounterNumber;

    /**
     *
     */
    const int mIncDecValue;

    /**
     *
     */
    std::vector<uint8_t> mComputedData;

    /**
     *
     */
    static const std::map<const int, const std::shared_ptr<StatusProperties>> initStatusTable();
};

}
}
}
