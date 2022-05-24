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
#include <map>
#include <memory>
#include <ostream>
#include <vector>

/* Keyple Core Util */
#include "LoggerFactory.h"

/* Calypsonet Terminal alypso */
#include "FileData.h"

namespace keyple {
namespace card {
namespace calypso {

using namespace calypsonet::terminal::calypso::card;
using namespace keyple::core::util::cpp;

/**
 * (package-private)<br>
 * Implementation of FileData.
 *
 * @since 2.0.0
 */
class FileDataAdapter final : public FileData {
public:
    /**
     * (package-private)<br>
     * Constructor
     *
     * @since 2.0.0
     */
    FileDataAdapter();

    /**
     * (package-private)<br>
     * Constructor used to create a clone of the provided file file data.
     *
     * @param source the header to be cloned.
     * @since 2.0.0
     */
    FileDataAdapter(const std::shared_ptr<FileData> source);

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::map<int, std::vector<uint8_t>>& getAllRecordsContent() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getContent() const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getContent(const int numRecord) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::vector<uint8_t> getContent(const int numRecord,
                                          const int dataOffset,
                                          const int dataLength) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::shared_ptr<int> getContentAsCounterValue(const int numCounter) const override;

    /**
     * {@inheritDoc}
     *
     * @since 2.0.0
     */
    const std::map<const int, const int> getAllCountersValue() const override;

    /**
     * (package-private)<br>
     * Sets or replaces the entire content of the specified record #numRecord by the provided content.
     *
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @since 2.0.0
     */
    void setContent(const int numRecord, const std::vector<uint8_t>& content);

    /**
     * (package-private)<br>
     * Sets a counter value in record #1.
     *
     * @param numCounter the counter number (should be {@code >=} 1).
     * @param content the counter value (should be not null and 3 bytes length).
     * @since 2.0.0
     */
    void setCounter(const int numCounter, const std::vector<uint8_t>& content);

    /**
     * (package-private)<br>
     * Sets or replaces the content at the specified offset of record #numRecord by a copy of the
     * provided content.<br>
     * If actual record content is not set or has a size {@code <} offset, then missing data will be
     * padded with 0.
     *
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @param offset the offset (should be {@code >=} 0).
     * @since 2.0.0
     */
    void setContent(const int numRecord, const std::vector<uint8_t> content, const int offset);

    /**
     * (package-private)<br>
     * Fills the content at the specified offset of the specified record using a binary OR operation
     * with the provided content.<br>
     * If actual record content is not set or has a size {@code <} offset + content size, then missing
     * data will be completed by the provided content.
     *
     * @param numRecord the record number (should be {@code >=} 1).
     * @param content the content (should be not empty).
     * @param offset the offset (should be {@code >=} 0).
     * @since 2.0.0
     */
    void fillContent(const int numRecord, const std::vector<uint8_t> content, const int offset);

    /**
     * (package-private)<br>
     * Adds cyclic content at record #1 by rolling previously all actual records contents (record #1
     * -> record #2, record #2 -> record #3,...).<br>
     * This is useful for cyclic files.<br>
     * Note that records are infinitely shifted.
     *
     * @param content the content (should be not empty).
     * @since 2.0.0
     */
    void addCyclicContent(const std::vector<uint8_t>& content);

    /**
     *
     */
    friend std::ostream& operator<<(std::ostream& os, const FileDataAdapter& fda);

private:
    /**
     *
     */
    const std::unique_ptr<Logger> mLogger = LoggerFactory::getLogger(typeid(FileDataAdapter));

    /**
     *
     */
    std::map<int, std::vector<uint8_t>> mRecords;

};

}
}
}
