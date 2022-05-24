/**************************************************************************************************
 * Copyright (c) 2022 Calypso Networks Association https://calypsonet.org/                        *
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
#include <memory>
#include <ostream>
#include <vector>

/* Calypsonet Terminal Calypso */
#include "SvLoadLogRecord.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;

/**
 * (package-private)<br>
 * Implementation of SvLoadLogRecord.
 *
 * @since 2.0.0
 */
class SvLoadLogRecordAdapter : public SvLoadLogRecord {
public:
    /**
     * Constructor
     *
     * @param cardResponse the Sv Get or Read Record (SV Debit log file) response data.
     * @param offset the load log offset in the response (may change from a card to another).
     * @since 2.0.0
     */
    SvLoadLogRecordAdapter(const std::vector<uint8_t>& cardResponse, const int offset);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t>& getRawData() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getAmount() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getBalance() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getLoadTime() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getLoadDate() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getFreeData() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    uint8_t getKvc() const override;
    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getSamId() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getSvTNum() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    int getSamTNum() const override;

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const SvLoadLogRecordAdapter& ra);

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os,
                                    const std::shared_ptr<SvLoadLogRecordAdapter> ra);

    /**
     * Gets the object content as a Json string.
     *
     * @return A not empty string.
     * @since 2.0.0
     */
    const std::string toJSONString() const;

private:
    /**
     *
     */
    const int mOffset;

    /**
     *
     */
    const std::vector<uint8_t> mCardResponse;
};

}
}
}
