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
#include <ostream>
#include <vector>

#include "keyple/card/calypso/KeypleCardCalypsoExport.hpp"
#include "keyple/core/util/cpp/Logger.hpp"
#include "keyple/core/util/cpp/LoggerFactory.hpp"
#include "keypop/calypso/card/card/FileData.hpp"

namespace keyple {
namespace card {
namespace calypso {

using keyple::core::util::cpp::Logger;
using keyple::core::util::cpp::LoggerFactory;
using keypop::calypso::card::card::FileData;

/**
 * Implementation of FileData.
 *
 * @since 2.0.0
 */
class KEYPLECARDCALYPSO_API FileDataAdapter final : public FileData {
public:
    /**
     * Constructor
     *
     * @since 2.0.0
     */
    FileDataAdapter();

    /**
     * Constructor used to create a clone of the provided file data.
     *
     * @param source the header to be cloned.
     * @since 2.0.0
     */
    FileDataAdapter(const std::shared_ptr<FileData>& source);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::map<const std::uint8_t, std::vector<std::uint8_t>>&
    getAllRecordsContent() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::vector<std::uint8_t> getContent() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::vector<std::uint8_t> getContent(std::uint8_t numRecord) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::vector<std::uint8_t> getContent(
        std::uint8_t numRecord,
        std::uint8_t dataOffset,
        std::uint8_t dataLength) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::shared_ptr<int>
    getContentAsCounterValue(const int numCounter) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    std::map<const int, const int> getAllCountersValue() const override;

    /**
     * Sets or replaces the entire content of the specified record #numRecord by
     * the provided content.
     *
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @since 2.0.0
     */
    void setContent(
        std::uint8_t numRecord, const std::vector<std::uint8_t>& content);

    /**
     * Sets a counter value in record #1.
     *
     * @param numCounter the counter number (should be {@code >=} 1).
     * @param content the counter value (should be not null and 3 bytes length).
     * @since 2.0.0
     */
    void setCounter(
        std::uint8_t numCounter, const std::vector<std::uint8_t>& content);

    /**
     * Sets or replaces the content at the specified offset of record #numRecord
     * by a copy of the provided content.<br>
     * If actual record content is not set or has a size {@code <} offset, then
     * missing data will be padded with 0.
     *
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @param offset the offset (should be {@code >=} 0).
     * @since 2.0.0
     */
    void setContent(
        std::uint8_t numRecord,
        const std::vector<std::uint8_t>& content,
        int offset);

    /**
     * Fills the content at the specified offset of the specified record using a
     * binary OR operation with the provided content.<br>
     * If actual record content is not set or has a size {@code <} offset +
     * content size, then missing data will be completed by the provided
     * content.
     *
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @param offset the offset (should be {@code >=} 0).
     * @since 2.0.0
     */
    void fillContent(
        std::uint8_t numRecord,
        const std::vector<std::uint8_t>& content,
        int offset);

    /**
     * Adds cyclic content at record #1 by rolling previously all actual records
     * contents (record #1 -> record #2, record #2 -> record #3,...).<br>
     * This is useful for cyclic files.<br>
     * Note that records are infinitely shifted.
     *
     * @param content the content (should be not empty).
     * @since 2.0.0
     */
    void addCyclicContent(const std::vector<std::uint8_t>& content);

    /**
     *
     */
    friend std::ostream&
    operator<<(std::ostream& os, const FileDataAdapter& fda);

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger
        = LoggerFactory::getLogger(typeid(FileDataAdapter));

    /**
     *
     */
    std::map<const std::uint8_t, std::vector<std::uint8_t>> mRecords;
};

}
}
}
